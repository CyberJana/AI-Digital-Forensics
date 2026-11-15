import json
import os
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

from digital_forensics.hashing import hash_file_read_only

EXIFTOOL_LICENSE = "Perl Artistic License or GPL"
EXIFTOOL_LICENSE_URL = "https://github.com/exiftool/exiftool/blob/master/README"
EXIFTOOL_SOURCE_URL = "https://exiftool.org/"
MAX_EXIFTOOL_OUTPUT_BYTES = 1_000_000
EXIFTOOL_TIMEOUT_SECONDS = 60
ExifToolRunner = Callable[..., subprocess.CompletedProcess[str]]


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
    if len(result.stdout.encode("utf-8")) > MAX_EXIFTOOL_OUTPUT_BYTES:
        raise ExifToolError("exiftool_output_too_large")

    try:
        documents = json.loads(result.stdout, parse_constant=_reject_json_constant)
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
