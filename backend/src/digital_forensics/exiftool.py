import json
import os
import shutil
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Protocol
from uuid import UUID

from digital_forensics.hashing import hash_file_read_only

EXIFTOOL_LICENSE = "Perl Artistic License or GPL"
EXIFTOOL_LICENSE_URL = "https://github.com/exiftool/exiftool/blob/master/README"
EXIFTOOL_SOURCE_URL = "https://exiftool.org/"
MAX_EXIFTOOL_OUTPUT_BYTES = 1_000_000
EXIFTOOL_TIMEOUT_SECONDS = 60


class ExifToolProcess(Protocol):
    returncode: int
    stdout: str


ExifToolRunner = Callable[..., ExifToolProcess]


class ExifToolSandboxRunner(Protocol):
    def run_version(self) -> dict[str, object]: ...

    def run_metadata(
        self,
        source_fd: int,
        *,
        evidence_id: UUID,
        expected_sha256: str,
    ) -> dict[str, object]: ...


class ExifToolError(RuntimeError):
    pass


def build_metadata_command(executable: str, working_copy: Path) -> list[str]:
    return [
        executable,
        "-json",
        "-G1",
        "-a",
        "-s",
        str(working_copy.resolve(strict=True)),
    ]


def collect_metadata(
    working_copy: Path,
    *,
    executable: str = "exiftool",
    runner: ExifToolRunner | None = None,
) -> dict[str, object]:
    if runner is None:
        raise ExifToolError("sandbox_required")

    source_info = working_copy.lstat()
    if not working_copy.is_file() or working_copy.is_symlink():
        raise ExifToolError("working_copy_not_regular")
    initial_hash = _working_copy_hash(working_copy, source_info)

    resolved_executable = shutil.which(executable)
    if resolved_executable is None:
        raise ExifToolError("exiftool_unavailable")

    version_process = runner(
        [resolved_executable, "-ver"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=EXIFTOOL_TIMEOUT_SECONDS,
        check=False,
    )
    if version_process.returncode != 0:
        raise ExifToolError("exiftool_version_failed")
    tool_version = version_process.stdout.strip()
    if not tool_version:
        raise ExifToolError("exiftool_version_missing")

    result = runner(
        build_metadata_command(resolved_executable, working_copy),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=EXIFTOOL_TIMEOUT_SECONDS,
        check=False,
    )
    if result.returncode != 0:
        raise ExifToolError("exiftool_execution_failed")
    return _build_metadata_result(working_copy, source_info, initial_hash, tool_version, result.stdout)


def collect_metadata_sandboxed(
    working_copy: Path,
    *,
    evidence_id: UUID,
    expected_sha256: str,
    runner: ExifToolSandboxRunner,
) -> dict[str, object]:
    source_info = working_copy.lstat()
    if not working_copy.is_file() or working_copy.is_symlink():
        raise ExifToolError("working_copy_not_regular")
    initial_hash = _working_copy_hash(working_copy, source_info)
    if initial_hash != expected_sha256:
        raise ExifToolError("working_copy_digest_mismatch")

    version_process = runner.run_version()
    if version_process.get("returncode") != 0:
        raise ExifToolError("exiftool_version_failed")
    tool_version = version_process.get("stdout")
    if not isinstance(tool_version, str) or not tool_version.strip():
        raise ExifToolError("exiftool_version_missing")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_fd = os.open(working_copy, flags)
    except OSError as error:
        raise ExifToolError("working_copy_not_regular") from error
    try:
        opened_info = os.fstat(source_fd)
        if (
            not stat.S_ISREG(opened_info.st_mode)
            or opened_info.st_dev != source_info.st_dev
            or opened_info.st_ino != source_info.st_ino
            or opened_info.st_size != source_info.st_size
            or opened_info.st_mtime_ns != source_info.st_mtime_ns
        ):
            raise ExifToolError("working_copy_changed_during_analysis")
        result = runner.run_metadata(
            source_fd,
            evidence_id=evidence_id,
            expected_sha256=expected_sha256,
        )
    finally:
        os.close(source_fd)
    if result.get("returncode") != 0:
        raise ExifToolError("exiftool_execution_failed")
    output = result.get("stdout")
    if not isinstance(output, str):
        raise ExifToolError("exiftool_output_invalid")
    return _build_metadata_result(working_copy, source_info, initial_hash, tool_version.strip(), output)


def _build_metadata_result(
    working_copy: Path,
    source_info: os.stat_result,
    initial_hash: str,
    tool_version: str,
    output: str,
) -> dict[str, object]:
    if len(output.encode("utf-8")) > MAX_EXIFTOOL_OUTPUT_BYTES:
        raise ExifToolError("exiftool_output_too_large")

    try:
        documents = json.loads(output, parse_constant=_reject_json_constant)
    except (json.JSONDecodeError, ValueError) as error:
        raise ExifToolError("exiftool_output_invalid") from error
    if (
        not isinstance(documents, list)
        or len(documents) != 1
        or not isinstance(documents[0], dict)
    ):
        raise ExifToolError("exiftool_output_invalid")

    metadata = {
        key: value
        for key, value in documents[0].items()
        if key.rsplit(":", maxsplit=1)[-1].casefold()
        not in {"sourcefile", "directory"}
    }
    final_hash = _working_copy_hash(working_copy, source_info)
    if final_hash != initial_hash:
        raise ExifToolError("working_copy_changed_during_analysis")
    return {
        "tool": {
            "name": "ExifTool",
            "version": tool_version,
            "license": EXIFTOOL_LICENSE,
            "license_url": EXIFTOOL_LICENSE_URL,
            "source_url": EXIFTOOL_SOURCE_URL,
        },
        "metadata": metadata,
        "working_copy_sha256": initial_hash,
    }


def _working_copy_hash(path: Path, source_info: os.stat_result) -> str:
    copied = hash_file_read_only(path)
    after = path.lstat()
    if (
        source_info.st_dev != after.st_dev
        or source_info.st_ino != after.st_ino
        or source_info.st_size != after.st_size
        or source_info.st_mtime_ns != after.st_mtime_ns
    ):
        raise ExifToolError("working_copy_changed_during_analysis")
    return copied.sha256


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON constant: {value}")
