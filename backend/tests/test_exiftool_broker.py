import asyncio
import hashlib
import os
import sys
from pathlib import Path
from uuid import uuid4

import pytest

import digital_forensics.exiftool_broker as broker_module
from digital_forensics.exiftool import ExifToolError, collect_metadata_sandboxed
from digital_forensics.exiftool_broker import (
    BrokerConfig,
    _validate_request,
    build_podman_command,
    stage_verified_input,
)


def _broker_config(
    tmp_path: Path,
    *,
    sandbox_image: str = "registry.example.test/forensics/exiftool@sha256:" + "a" * 64,
    socket_gid: int = 1001,
    worker_uid: int = 1002,
) -> BrokerConfig:
    return BrokerConfig(
        socket_path=tmp_path / "broker.sock",
        socket_gid=socket_gid,
        worker_uid=worker_uid,
        staging_root=tmp_path,
        sandbox_image=sandbox_image,
        podman_path=tmp_path / "podman",
        home=tmp_path,
        runtime_dir=tmp_path,
    )


def _mock_subprocess(
    monkeypatch: pytest.MonkeyPatch,
    outputs: list[tuple[bytes | None, bytes | None]],
) -> tuple[list[tuple[list[str], dict[str, object]]], list[int]]:
    invocations: list[tuple[list[str], dict[str, object]]] = []
    killed_process_groups: list[int] = []

    class FakeStream:
        def __init__(self, content: bytes | None) -> None:
            self.content = content
            self.has_read = False

        async def read(self, _limit: int) -> bytes:
            if self.content is None:
                await asyncio.sleep(60)
            if self.has_read:
                return b""
            self.has_read = True
            return self.content or b""

    class FakeProcess:
        def __init__(self, output: bytes | None, error: bytes | None) -> None:
            self.pid = 123
            self.returncode: int | None = None
            self.stdout = FakeStream(output)
            self.stderr = FakeStream(error)

        async def wait(self) -> int:
            self.returncode = 0
            return self.returncode

    async def fake_create_subprocess_exec(
        executable: str,
        *args: str,
        **kwargs: object,
    ) -> FakeProcess:
        command = [executable, *args]
        invocations.append((command, kwargs))
        if command[2:3] == ["rm"]:
            return FakeProcess(b"", b"")
        output, error = outputs.pop(0)
        return FakeProcess(output, error)

    monkeypatch.setattr(
        broker_module.asyncio,
        "create_subprocess_exec",
        fake_create_subprocess_exec,
    )
    monkeypatch.setattr(
        broker_module.os,
        "killpg",
        lambda pid, _signal: killed_process_groups.append(pid),
        raising=False,
    )
    monkeypatch.setattr(broker_module.signal, "SIGKILL", 9, raising=False)
    return invocations, killed_process_groups


def test_broker_configuration_requires_pinned_image(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="pinned by sha256"):
        _broker_config(tmp_path, sandbox_image="exiftool:latest").validate()
    with pytest.raises(ValueError, match="must be unprivileged"):
        _broker_config(tmp_path, worker_uid=0).validate()


@pytest.mark.skipif(sys.platform != "linux", reason="The host broker is Linux-only")
def test_broker_socket_is_created_with_group_access_and_restores_umask(
    tmp_path: Path,
) -> None:
    broker = broker_module.ExifToolBroker.__new__(broker_module.ExifToolBroker)
    broker.config = _broker_config(tmp_path, socket_gid=os.getegid())
    broker._socket = None
    broker._socket_identity = None
    original_umask = os.umask(0o077)
    listener = None
    try:
        listener = broker._prepare_socket()
        assert broker.config.socket_path.stat().st_mode & 0o777 == 0o660
        assert os.umask(0o077) == 0o077
    finally:
        os.umask(original_umask)
        if listener is not None:
            broker.close()


def test_broker_command_uses_fixed_isolated_container_policy(tmp_path: Path) -> None:
    config = _broker_config(tmp_path)
    config.validate()

    command = build_podman_command(
        config,
        action="metadata",
        container_name="df-exiftool-" + "b" * 32,
        staged_input=tmp_path / "staging" / "evidence",
    )

    assert command[1] == "--remote=false"
    assert "--runtime=runsc" in command
    assert "--network=none" in command
    assert "--read-only" in command
    assert "--ipc=private" in command
    assert "--pid=private" in command
    assert "--userns=private" in command
    assert "--unsetenv-all" in command
    assert "--env=HOME=/tmp" in command
    assert "--user=65532:65532" in command
    assert "--cap-drop=ALL" in command
    assert "--security-opt=no-new-privileges" in command
    assert "--memory=256m" in command
    assert "--cpus=1" in command
    assert "--pids-limit=64" in command
    assert any("dst=/input/evidence,ro" in item for item in command)
    assert command[-5:] == ["-json", "-G1", "-a", "-s", "/input/evidence"]
    assert not any("docker.sock" in item or "host" in item.casefold() for item in command)


def test_broker_run_passes_fixed_command_and_strips_container_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _broker_config(tmp_path)
    broker = broker_module.ExifToolBroker.__new__(broker_module.ExifToolBroker)
    broker.config = config
    invocations, _ = _mock_subprocess(monkeypatch, [(b"12.80\n", b"")])

    assert broker._run_container(action="version") == {
        "returncode": 0,
        "stdout": "12.80\n",
    }
    command, options = invocations[0]
    assert "--network=none" in command
    assert options["start_new_session"] is True
    assert options["close_fds"] is True
    assert set(options["env"]) == {"HOME", "PATH", "TMPDIR", "XDG_RUNTIME_DIR"}
    assert invocations[1][0][2] == "rm"


def test_broker_fails_closed_when_output_exceeds_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broker = broker_module.ExifToolBroker.__new__(broker_module.ExifToolBroker)
    broker.config = _broker_config(tmp_path)
    _mock_subprocess(
        monkeypatch,
        [(b"x" * (broker_module.MAX_OUTPUT_BYTES + 1), b"")],
    )

    with pytest.raises(RuntimeError, match="sandbox_output_too_large"):
        broker._run_container(action="version")


def test_broker_fails_closed_on_runtime_warnings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broker = broker_module.ExifToolBroker.__new__(broker_module.ExifToolBroker)
    broker.config = _broker_config(tmp_path)
    _mock_subprocess(monkeypatch, [(b"12.80\n", b"resource limits unavailable")])

    with pytest.raises(RuntimeError, match="sandbox_execution_failed"):
        broker._run_container(action="version")


def test_broker_kills_process_group_on_output_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, killed_process_groups = _mock_subprocess(monkeypatch, [(None, b"")])

    with pytest.raises(TimeoutError, match="sandbox_timeout"):
        asyncio.run(
            broker_module._run_limited_process(
                ["podman", "run"],
                environment={},
                timeout_seconds=0.01,
                capture_output=True,
            )
        )
    assert killed_process_groups == [123]


def test_broker_protocol_rejects_arbitrary_commands_and_extra_fields() -> None:
    with pytest.raises(ValueError, match="broker_request_invalid"):
        _validate_request({"action": "command", "argv": ["sh"]}, 0)
    with pytest.raises(ValueError, match="broker_request_invalid"):
        _validate_request({"action": "version", "argv": ["exiftool", "-ver"]}, 0)
    with pytest.raises(ValueError, match="broker_request_invalid"):
        _validate_request({"action": []}, 0)


@pytest.mark.skipif(sys.platform != "linux", reason="The host broker is Linux-only")
def test_broker_stages_only_digest_verified_read_only_input(tmp_path: Path) -> None:
    evidence_id = uuid4()
    content = b"synthetic evidence"
    source = tmp_path / "source"
    source.write_bytes(content)
    descriptor = os.open(source, os.O_RDONLY)
    try:
        with stage_verified_input(
            descriptor,
            staging_root=tmp_path,
            evidence_id=str(evidence_id),
            expected_sha256=hashlib.sha256(content).hexdigest(),
        ) as staged:
            assert staged.read_bytes() == content
            assert staged.stat().st_mode & 0o777 == 0o444
            assert staged.parent.stat().st_mode & 0o777 == 0o700
        with pytest.raises(FileNotFoundError):
            staged.stat()
    finally:
        os.close(descriptor)


@pytest.mark.skipif(sys.platform != "linux", reason="The host broker is Linux-only")
def test_broker_rejects_digest_mismatch_and_input_over_limit(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.write_bytes(b"synthetic evidence")
    descriptor = os.open(source, os.O_RDONLY)
    try:
        with pytest.raises(ValueError, match="digest_mismatch"):
            with stage_verified_input(
                descriptor,
                staging_root=tmp_path,
                evidence_id=str(uuid4()),
                expected_sha256="0" * 64,
            ):
                pytest.fail("Mismatched input must not be staged")
        with pytest.raises(ValueError, match="too_large"):
            with stage_verified_input(
                descriptor,
                staging_root=tmp_path,
                evidence_id=str(uuid4()),
                expected_sha256=hashlib.sha256(b"synthetic evidence").hexdigest(),
                max_input_bytes=1,
            ):
                pytest.fail("Oversized input must not be staged")
    finally:
        os.close(descriptor)


def test_sandboxed_collector_hands_off_verified_descriptor_and_bounds_output(
    tmp_path: Path,
) -> None:
    evidence_id = uuid4()
    content = b"synthetic evidence"
    working_copy = tmp_path / "evidence.working-copy"
    working_copy.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()

    class FakeBroker:
        def run_version(self) -> dict[str, object]:
            return {"returncode": 0, "stdout": "12.80\n"}

        def run_metadata(
            self,
            source_fd: int,
            *,
            evidence_id: object,
            expected_sha256: str,
        ) -> dict[str, object]:
            assert os.read(source_fd, len(content)) == content
            assert evidence_id == self_evidence_id
            assert expected_sha256 == digest
            return {
                "returncode": 0,
                "stdout": '[{"EXIF:Make":"Synthetic","SourceFile":"/input/evidence"}]',
            }

    self_evidence_id = evidence_id
    result = collect_metadata_sandboxed(
        working_copy,
        evidence_id=evidence_id,
        expected_sha256=digest,
        runner=FakeBroker(),
    )
    assert result["metadata"] == {"EXIF:Make": "Synthetic"}

    class OversizedBroker(FakeBroker):
        def run_metadata(
            self,
            source_fd: int,
            *,
            evidence_id: object,
            expected_sha256: str,
        ) -> dict[str, object]:
            return {"returncode": 0, "stdout": " " * 1_000_001}

    with pytest.raises(ExifToolError, match="exiftool_output_too_large"):
        collect_metadata_sandboxed(
            working_copy,
            evidence_id=evidence_id,
            expected_sha256=digest,
            runner=OversizedBroker(),
        )
