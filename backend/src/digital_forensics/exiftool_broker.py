import argparse
import asyncio
import array
import hashlib
import json
import os
import re
import signal
import socket
import stat
import struct
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID, uuid4

try:
    import fcntl
except ImportError:
    fcntl = None

MAX_REQUEST_BYTES = 16_384
MAX_OUTPUT_BYTES = 1_000_000
MAX_STDERR_BYTES = 65_536
MAX_INPUT_BYTES = 10 * 1024 * 1024 * 1024
MAX_TIMEOUT_SECONDS = 60
MAX_RESPONSE_BYTES = 6 * MAX_OUTPUT_BYTES + 4096
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_RE = re.compile(
    r"(?:[A-Za-z0-9.-]+(?::[0-9]{1,5})?/)?[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}\Z"
)
_SUPPORTED_ACTIONS = {"version", "metadata"}


@dataclass(frozen=True)
class BrokerConfig:
    socket_path: Path
    socket_gid: int
    worker_uid: int
    staging_root: Path
    sandbox_image: str
    podman_path: Path
    home: Path
    runtime_dir: Path
    timeout_seconds: int = MAX_TIMEOUT_SECONDS
    max_input_bytes: int = MAX_INPUT_BYTES
    memory_limit: str = "256m"
    cpu_limit: str = "1"
    pids_limit: int = 64

    def validate(self) -> None:
        for label, path in (
            ("socket", self.socket_path),
            ("staging root", self.staging_root),
            ("Podman executable", self.podman_path),
            ("home", self.home),
            ("runtime directory", self.runtime_dir),
        ):
            if not path.is_absolute():
                raise ValueError(f"{label} path must be absolute")
            if label == "staging root" and "," in str(path):
                raise ValueError(f"{label} path contains unsupported characters")
        if not _IMAGE_RE.fullmatch(self.sandbox_image):
            raise ValueError("Sandbox image must be pinned by sha256 digest")
        if self.socket_gid <= 0 or self.worker_uid <= 0:
            raise ValueError("Broker socket group and worker UID must be unprivileged")
        if not 1 <= self.timeout_seconds <= MAX_TIMEOUT_SECONDS:
            raise ValueError("Sandbox timeout is out of range")
        if not 1 <= self.max_input_bytes <= MAX_INPUT_BYTES:
            raise ValueError("Sandbox input limit is out of range")
        if self.memory_limit != "256m" or self.cpu_limit != "1" or self.pids_limit != 64:
            raise ValueError("Sandbox resource limits must use the approved fixed values")


def build_podman_command(
    config: BrokerConfig,
    *,
    action: str,
    container_name: str,
    staged_input: Path | None = None,
) -> list[str]:
    config.validate()
    if action not in _SUPPORTED_ACTIONS:
        raise ValueError("Unsupported sandbox action")
    if not re.fullmatch(r"df-exiftool-[0-9a-f]{32}", container_name):
        raise ValueError("Invalid sandbox container name")
    if (action == "metadata") != (staged_input is not None):
        raise ValueError("Sandbox input does not match the requested action")

    command = [
        str(config.podman_path),
        "--remote=false",
        "run",
        "--pull=never",
        "--runtime=runsc",
        "--rm",
        "--unsetenv-all",
        "--env=HOME=/tmp",
        f"--name={container_name}",
        "--network=none",
        "--read-only",
        "--ipc=private",
        "--pid=private",
        "--userns=private",
        "--user=65532:65532",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--memory={config.memory_limit}",
        f"--cpus={config.cpu_limit}",
        f"--pids-limit={config.pids_limit}",
        "--ulimit=nofile=64:64",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m",
    ]
    if staged_input is not None:
        if not staged_input.is_absolute():
            raise ValueError("Staged input path must be absolute")
        if "," in str(staged_input):
            raise ValueError("Staged input path contains unsupported characters")
        command.append(
            f"--mount=type=bind,src={staged_input},dst=/input/evidence,ro"
        )
    command.extend(
        [
            f"--entrypoint=/usr/bin/exiftool",
            config.sandbox_image,
            "-ver" if action == "version" else "-json",
        ]
    )
    if action == "metadata":
        command.extend(["-G1", "-a", "-s", "/input/evidence"])
    return command


def _validate_request(request: object, descriptor_count: int) -> dict[str, str]:
    if not isinstance(request, dict):
        raise ValueError("broker_request_invalid")
    action = request.get("action")
    if not isinstance(action, str) or action not in _SUPPORTED_ACTIONS:
        raise ValueError("broker_request_invalid")
    expected_keys = {"action"} if action == "version" else {
        "action",
        "evidence_id",
        "sha256",
    }
    if set(request) != expected_keys:
        raise ValueError("broker_request_invalid")
    if descriptor_count != (1 if action == "metadata" else 0):
        raise ValueError("broker_input_descriptor_invalid")
    if action == "metadata":
        try:
            UUID(request["evidence_id"])
        except (ValueError, TypeError, AttributeError) as error:
            raise ValueError("broker_request_invalid") from error
        if not isinstance(request["sha256"], str) or not _SHA256_RE.fullmatch(
            request["sha256"]
        ):
            raise ValueError("broker_request_invalid")
    return request


def _file_signature(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


@contextmanager
def stage_verified_input(
    source_fd: int,
    *,
    staging_root: Path,
    evidence_id: str,
    expected_sha256: str,
    max_input_bytes: int = MAX_INPUT_BYTES,
    timeout_seconds: int = MAX_TIMEOUT_SECONDS,
) -> Iterator[Path]:
    try:
        UUID(evidence_id)
    except (ValueError, TypeError, AttributeError) as error:
        raise ValueError("broker_request_invalid") from error
    if not _SHA256_RE.fullmatch(expected_sha256):
        raise ValueError("broker_request_invalid")
    before = os.fstat(source_fd)
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("broker_input_not_regular")
    if fcntl is None:
        raise RuntimeError("The ExifTool broker requires Linux")
    if fcntl.fcntl(source_fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
        raise ValueError("broker_input_must_be_read_only")
    if before.st_size > max_input_bytes:
        raise ValueError("broker_input_too_large")
    root_info = staging_root.lstat()
    if not stat.S_ISDIR(root_info.st_mode):
        raise ValueError("broker_staging_root_permissions_invalid")
    if root_info.st_uid != os.geteuid() or stat.S_IMODE(root_info.st_mode) & 0o077:
        raise ValueError("broker_staging_root_permissions_invalid")

    os.lseek(source_fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix="exiftool-", dir=staging_root) as directory:
        os.chmod(directory, 0o700)
        destination = Path(directory) / "evidence"
        bytes_copied = 0
        deadline = time.monotonic() + timeout_seconds
        with destination.open("xb") as target:
            os.fchmod(target.fileno(), 0o400)
            while chunk := os.read(source_fd, 1024 * 1024):
                if time.monotonic() > deadline:
                    raise TimeoutError("sandbox_timeout")
                bytes_copied += len(chunk)
                if bytes_copied > max_input_bytes or bytes_copied > before.st_size:
                    raise ValueError("broker_input_changed_during_copy")
                digest.update(chunk)
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        after = os.fstat(source_fd)
        if (
            _file_signature(before) != _file_signature(after)
            or bytes_copied != before.st_size
        ):
            raise ValueError("broker_input_changed_during_copy")
        if digest.hexdigest() != expected_sha256:
            raise ValueError("broker_input_digest_mismatch")
        os.chmod(destination, 0o444)
        yield_path = destination
        yield yield_path


def _process_environment(config: BrokerConfig) -> dict[str, str]:
    return {
        "HOME": str(config.home),
        "PATH": "/usr/bin:/bin",
        "TMPDIR": str(config.staging_root),
        "XDG_RUNTIME_DIR": str(config.runtime_dir),
    }


async def _read_limited_stream(
    stream: asyncio.StreamReader,
    *,
    limit: int,
) -> bytes:
    output = bytearray()
    while chunk := await stream.read(65_537):
        if len(output) + len(chunk) > limit:
            raise ValueError("sandbox_output_too_large")
        output.extend(chunk)
    return bytes(output)


async def _terminate_process(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as error:
        raise RuntimeError("sandbox_cleanup_failed") from error
    try:
        await asyncio.wait_for(process.wait(), timeout=5)
    except TimeoutError as error:
        raise RuntimeError("sandbox_cleanup_failed") from error


async def _run_limited_process(
    command: list[str],
    *,
    environment: dict[str, str],
    timeout_seconds: int,
    capture_output: bool,
) -> tuple[int, bytes, bytes]:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_seconds
    process = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE if capture_output else asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE if capture_output else asyncio.subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
        env=environment,
    )
    readers: list[asyncio.Task[bytes]] = []
    try:
        if capture_output:
            if process.stdout is None or process.stderr is None:
                raise RuntimeError("broker_process_pipes_unavailable")
            readers = [
                asyncio.create_task(
                    _read_limited_stream(process.stdout, limit=MAX_OUTPUT_BYTES)
                ),
                asyncio.create_task(
                    _read_limited_stream(process.stderr, limit=MAX_STDERR_BYTES)
                ),
            ]
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise TimeoutError("sandbox_timeout")
            try:
                stdout, stderr = await asyncio.wait_for(
                    asyncio.gather(*readers),
                    timeout=remaining,
                )
            except TimeoutError as error:
                raise TimeoutError("sandbox_timeout") from error
        else:
            stdout, stderr = b"", b""

        remaining = deadline - loop.time()
        if remaining <= 0:
            raise TimeoutError("sandbox_timeout")
        try:
            returncode = await asyncio.wait_for(process.wait(), timeout=remaining)
        except TimeoutError as error:
            raise TimeoutError("sandbox_timeout") from error
        return returncode, stdout, stderr
    except BaseException:
        for reader in readers:
            reader.cancel()
        try:
            await _terminate_process(process)
        finally:
            await asyncio.gather(*readers, return_exceptions=True)
        raise


class ExifToolBroker:
    def __init__(self, config: BrokerConfig) -> None:
        if not sys.platform.startswith("linux"):
            raise RuntimeError("The ExifTool broker requires Linux")
        if os.geteuid() == 0 or config.worker_uid == os.geteuid():
            raise RuntimeError("Broker and worker must use separate unprivileged accounts")
        config.validate()
        for directory in (config.staging_root, config.home, config.runtime_dir):
            info = directory.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077
            ):
                raise ValueError("Broker directories must be private and owned by the broker")
        podman_info = config.podman_path.lstat()
        if (
            config.podman_path.name != "podman"
            or not stat.S_ISREG(podman_info.st_mode)
            or podman_info.st_uid != 0
            or stat.S_IMODE(podman_info.st_mode) & 0o022
            or not os.access(config.podman_path, os.X_OK)
        ):
            raise ValueError("Configured Podman executable is invalid")
        self.config = config
        self._socket: socket.socket | None = None
        self._socket_identity: tuple[int, int] | None = None

    def _prepare_socket(self) -> socket.socket:
        path = self.config.socket_path
        parent_info = path.parent.stat()
        if parent_info.st_uid != os.geteuid() or stat.S_IMODE(parent_info.st_mode) & 0o077:
            raise RuntimeError("broker_socket_directory_permissions_invalid")
        if path.exists() or path.is_symlink():
            old_info = path.lstat()
            if not stat.S_ISSOCK(old_info.st_mode) or old_info.st_uid != os.geteuid():
                raise RuntimeError("broker_socket_path_already_exists")
            path.unlink()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            previous_umask = os.umask(0o117)
            try:
                listener.bind(str(path))
            finally:
                os.umask(previous_umask)
            os.chown(path, os.geteuid(), self.config.socket_gid)
            listener.listen(8)
            self._socket_identity = (path.stat().st_dev, path.stat().st_ino)
            self._socket = listener
            return listener
        except Exception:
            listener.close()
            path.unlink(missing_ok=True)
            raise

    def serve_forever(self) -> None:
        listener = self._prepare_socket()
        try:
            while True:
                connection, _ = listener.accept()
                with connection:
                    try:
                        self._handle_connection(connection)
                    except OSError:
                        continue
        finally:
            self.close()

    def close(self) -> None:
        if self._socket is not None:
            self._socket.close()
            self._socket = None
        identity = self._socket_identity
        path = self.config.socket_path
        if identity is not None:
            try:
                info = path.lstat()
                if (info.st_dev, info.st_ino) == identity:
                    path.unlink()
            except FileNotFoundError:
                pass

    def _handle_connection(self, connection: socket.socket) -> None:
        request_started = time.monotonic()
        connection.settimeout(5)
        try:
            self._require_worker_peer(connection)
            request, descriptors = _receive_request(connection)
            _validate_request(request, len(descriptors))
            connection.settimeout(self.config.timeout_seconds + 15)
            if request["action"] == "version":
                result = self._run_container(action="version")
            else:
                with stage_verified_input(
                    descriptors[0],
                    staging_root=self.config.staging_root,
                    evidence_id=request["evidence_id"],
                    expected_sha256=request["sha256"],
                    max_input_bytes=self.config.max_input_bytes,
                    timeout_seconds=self.config.timeout_seconds,
                ) as staged_input:
                    remaining = self.config.timeout_seconds - (
                        time.monotonic() - request_started
                    )
                    if remaining <= 0:
                        raise TimeoutError("sandbox_timeout")
                    result = self._run_container(
                        action="metadata",
                        staged_input=staged_input,
                        timeout_seconds=max(1, int(remaining)),
                    )
            _send_response(connection, result)
        except (OSError, ValueError, RuntimeError) as error:
            message = str(error)
            if message not in {
                "broker_request_invalid",
                "broker_input_descriptor_invalid",
                "broker_input_not_regular",
                "broker_input_too_large",
                "broker_input_changed_during_copy",
                "broker_input_digest_mismatch",
                "sandbox_output_too_large",
                "sandbox_timeout",
                "sandbox_execution_failed",
                "sandbox_cleanup_failed",
            }:
                message = "sandbox_execution_failed"
            try:
                _send_response(connection, {"error": message})
            except OSError:
                pass
        finally:
            for descriptor in locals().get("descriptors", []):
                os.close(descriptor)

    def _require_worker_peer(self, connection: socket.socket) -> None:
        if not hasattr(socket, "SO_PEERCRED"):
            raise RuntimeError("broker_peer_credentials_unavailable")
        credentials = connection.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            struct.calcsize("3i"),
        )
        _, peer_uid, _ = struct.unpack("3i", credentials)
        if peer_uid != self.config.worker_uid:
            raise PermissionError("broker_peer_uid_rejected")

    def _run_container(
        self,
        *,
        action: str,
        staged_input: Path | None = None,
        timeout_seconds: int | None = None,
    ) -> dict[str, object]:
        container_name = f"df-exiftool-{uuid4().hex}"
        command = build_podman_command(
            self.config,
            action=action,
            container_name=container_name,
            staged_input=staged_input,
        )
        output = b""
        stderr = b""
        returncode = -1
        execution_error: Exception | None = None
        try:
            returncode, output, stderr = asyncio.run(
                _run_limited_process(
                    command,
                    environment=_process_environment(self.config),
                    timeout_seconds=timeout_seconds or self.config.timeout_seconds,
                    capture_output=True,
                )
            )
            if returncode != 0:
                execution_error = RuntimeError("sandbox_execution_failed")
            elif stderr:
                execution_error = RuntimeError("sandbox_stderr_not_empty")
        except (
            OSError,
            RuntimeError,
            TimeoutError,
            ValueError,
        ) as error:
            execution_error = error
        finally:
            try:
                cleanup_command = [
                    str(self.config.podman_path),
                    "--remote=false",
                    "rm",
                    "--force",
                    "--ignore",
                    container_name,
                ]
                cleanup_returncode, _, _ = asyncio.run(
                    _run_limited_process(
                        cleanup_command,
                        environment=_process_environment(self.config),
                        timeout_seconds=10,
                        capture_output=False,
                    )
                )
            except (
                OSError,
                RuntimeError,
                TimeoutError,
                ValueError,
            ) as error:
                raise RuntimeError("sandbox_cleanup_failed") from error
            if cleanup_returncode != 0:
                raise RuntimeError("sandbox_cleanup_failed")
        if execution_error is not None:
            error = str(execution_error)
            if error not in {"sandbox_output_too_large", "sandbox_timeout"}:
                error = "sandbox_execution_failed"
            raise RuntimeError(error)
        return {"returncode": returncode, "stdout": output.decode("utf-8", errors="replace")}


def _receive_request(connection: socket.socket) -> tuple[object, list[int]]:
    deadline = time.monotonic() + 5
    connection.settimeout(5)
    data, ancillary, flags, _ = connection.recvmsg(
        4,
        socket.CMSG_SPACE(array.array("i").itemsize),
    )
    descriptors: list[int] = []
    try:
        for level, kind, payload in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                raise ValueError("broker_input_descriptor_invalid")
            received = array.array("i")
            received.frombytes(payload[: len(payload) - (len(payload) % received.itemsize)])
            descriptors.extend(received.tolist())
        if len(data) != 4 or flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC):
            raise ValueError("broker_request_invalid")
        length = struct.unpack("!I", data)[0]
        if not 1 <= length <= MAX_REQUEST_BYTES:
            raise ValueError("broker_request_invalid")
        payload = bytearray()
        while len(payload) < length:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("broker_request_timeout")
            connection.settimeout(remaining)
            chunk = connection.recv(length - len(payload))
            if not chunk:
                raise ValueError("broker_request_invalid")
            payload.extend(chunk)
        try:
            request = json.loads(payload)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise ValueError("broker_request_invalid") from error
        return request, descriptors
    except Exception:
        for descriptor in descriptors:
            os.close(descriptor)
        raise


def _send_response(connection: socket.socket, response: dict[str, object]) -> None:
    payload = json.dumps(response, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(payload) > MAX_RESPONSE_BYTES:
        payload = b'{"error":"sandbox_output_too_large"}'
    connection.sendall(struct.pack("!I", len(payload)) + payload)


class ExifToolBrokerClient:
    def __init__(
        self,
        socket_path: Path,
        *,
        timeout_seconds: int = MAX_TIMEOUT_SECONDS,
    ) -> None:
        if not socket_path.is_absolute() or not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
            raise ValueError("Sandbox broker client configuration is invalid")
        self.socket_path = socket_path
        self.timeout_seconds = timeout_seconds

    def run_version(self) -> dict[str, object]:
        return self._request({"action": "version"})

    def run_metadata(
        self,
        source_fd: int,
        *,
        evidence_id: UUID,
        expected_sha256: str,
    ) -> dict[str, object]:
        return self._request(
            {
                "action": "metadata",
                "evidence_id": str(evidence_id),
                "sha256": expected_sha256,
            },
            source_fd=source_fd,
        )

    def _request(
        self,
        request: dict[str, str],
        *,
        source_fd: int | None = None,
    ) -> dict[str, object]:
        payload = json.dumps(request, separators=(",", ":")).encode("utf-8")
        if len(payload) > MAX_REQUEST_BYTES:
            raise RuntimeError("sandbox_broker_request_too_large")
        path_info = self.socket_path.lstat()
        if not stat.S_ISSOCK(path_info.st_mode):
            raise RuntimeError("sandbox_broker_unavailable")
        prefix = struct.pack("!I", len(payload))
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(self.timeout_seconds + 15)
            connection.connect(str(self.socket_path))
            if source_fd is None:
                connection.sendall(prefix + payload)
            else:
                descriptors = array.array("i", [source_fd])
                sent = connection.sendmsg(
                    [prefix],
                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptors)],
                )
                if sent != len(prefix):
                    raise RuntimeError("sandbox_broker_request_failed")
                connection.sendall(payload)
            length = struct.unpack("!I", _recv_exact(connection, 4))[0]
            if not 1 <= length <= MAX_RESPONSE_BYTES:
                raise RuntimeError("sandbox_broker_response_invalid")
            try:
                response = json.loads(_recv_exact(connection, length))
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                raise RuntimeError("sandbox_broker_response_invalid") from error
        if not isinstance(response, dict):
            raise RuntimeError("sandbox_broker_response_invalid")
        if "error" in response:
            raise RuntimeError(str(response["error"]))
        if set(response) != {"returncode", "stdout"} or type(
            response["returncode"]
        ) is not int or not isinstance(response["stdout"], str):
            raise RuntimeError("sandbox_broker_response_invalid")
        return response


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = connection.recv(size - len(result))
        if not chunk:
            raise RuntimeError("sandbox_broker_response_invalid")
        result.extend(chunk)
    return bytes(result)


def _parse_args() -> BrokerConfig:
    parser = argparse.ArgumentParser(description="Run the isolated ExifTool OCI broker.")
    parser.add_argument("--socket-path", required=True, type=Path)
    parser.add_argument("--socket-gid", required=True, type=int)
    parser.add_argument("--worker-uid", required=True, type=int)
    parser.add_argument("--staging-root", required=True, type=Path)
    parser.add_argument("--sandbox-image", required=True)
    parser.add_argument("--podman-path", required=True, type=Path)
    parser.add_argument("--home", required=True, type=Path)
    parser.add_argument("--runtime-dir", required=True, type=Path)
    arguments = parser.parse_args()
    return BrokerConfig(
        socket_path=arguments.socket_path,
        socket_gid=arguments.socket_gid,
        worker_uid=arguments.worker_uid,
        staging_root=arguments.staging_root,
        sandbox_image=arguments.sandbox_image,
        podman_path=arguments.podman_path,
        home=arguments.home,
        runtime_dir=arguments.runtime_dir,
    )


def main() -> None:
    config = _parse_args()
    config.validate()

    def stop_broker(signum: int, _frame: object) -> None:
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, stop_broker)
    if hasattr(signal, "SIGINT"):
        signal.signal(signal.SIGINT, stop_broker)
    ExifToolBroker(config).serve_forever()


if __name__ == "__main__":
    main()
