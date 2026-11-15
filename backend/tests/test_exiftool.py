import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from digital_forensics.exiftool import (
    EXIFTOOL_LICENSE,
    EXIFTOOL_LICENSE_URL,
    ExifToolError,
    build_metadata_command,
    collect_metadata,
)
from digital_forensics.working_copy import resolve_verified_working_copy


def test_build_metadata_command_uses_json_and_absolute_working_copy(
    tmp_path: Path,
) -> None:
    working_copy = tmp_path / "evidence.working-copy"
    working_copy.write_bytes(b"synthetic evidence")

    command = build_metadata_command("exiftool", working_copy)

    assert command == [
        "exiftool",
        "-json",
        "-G1",
        "-a",
        "-s",
        str(working_copy.resolve()),
    ]


def test_collect_metadata_redacts_paths_and_records_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    working_copy = tmp_path / "evidence.working-copy"
    content = b"synthetic evidence"
    working_copy.write_bytes(content)
    calls: list[list[str]] = []
    outputs = [
        SimpleNamespace(returncode=0, stdout="12.80\n", stderr=""),
        SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "SourceFile": str(working_copy),
                        "File:Directory": str(tmp_path),
                        "File:FileName": working_copy.name,
                        "EXIF:Make": "Synthetic Camera",
                    }
                ]
            ),
            stderr="",
        ),
    ]

    monkeypatch.setattr("digital_forensics.exiftool.shutil.which", lambda _: "exiftool")

    def fake_run(command: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append(command)
        return outputs.pop(0)

    result = collect_metadata(working_copy, runner=fake_run)

    assert result == {
        "tool": {
            "name": "ExifTool",
            "version": "12.80",
            "license": EXIFTOOL_LICENSE,
            "license_url": EXIFTOOL_LICENSE_URL,
            "source_url": "https://exiftool.org/",
        },
        "metadata": {
            "File:FileName": working_copy.name,
            "EXIF:Make": "Synthetic Camera",
        },
        "working_copy_sha256": hashlib.sha256(content).hexdigest(),
    }
    assert len(calls) == 2
    assert calls[0] == ["exiftool", "-ver"]
    assert calls[1][1:5] == ["-json", "-G1", "-a", "-s"]
    assert str(working_copy) not in json.dumps(result)
    assert str(tmp_path) not in json.dumps(result)


def test_collect_metadata_rejects_missing_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    working_copy = tmp_path / "evidence.working-copy"
    working_copy.write_bytes(b"synthetic evidence")
    monkeypatch.setattr("digital_forensics.exiftool.shutil.which", lambda _: None)

    with pytest.raises(ExifToolError, match="exiftool_unavailable"):
        collect_metadata(working_copy, runner=lambda *_args, **_kwargs: pytest.fail())


def test_collect_metadata_rejects_invalid_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    working_copy = tmp_path / "evidence.working-copy"
    working_copy.write_bytes(b"synthetic evidence")
    outputs = [
        SimpleNamespace(returncode=0, stdout="12.80\n", stderr=""),
        SimpleNamespace(returncode=0, stdout="not json", stderr=""),
    ]
    monkeypatch.setattr("digital_forensics.exiftool.shutil.which", lambda _: "exiftool")
    runner = lambda *_args, **_kwargs: outputs.pop(0)

    with pytest.raises(ExifToolError, match="exiftool_output_invalid"):
        collect_metadata(working_copy, runner=runner)


def test_collect_metadata_rejects_nonstandard_json_constants(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    working_copy = tmp_path / "evidence.working-copy"
    working_copy.write_bytes(b"synthetic evidence")
    outputs = [
        SimpleNamespace(returncode=0, stdout="12.80\n", stderr=""),
        SimpleNamespace(returncode=0, stdout='[{"EXIF:Value": NaN}]', stderr=""),
    ]
    monkeypatch.setattr("digital_forensics.exiftool.shutil.which", lambda _: "exiftool")
    runner = lambda *_args, **_kwargs: outputs.pop(0)

    with pytest.raises(ExifToolError, match="exiftool_output_invalid"):
        collect_metadata(working_copy, runner=runner)


def test_collect_metadata_requires_sandbox_runner(tmp_path: Path) -> None:
    working_copy = tmp_path / "evidence.working-copy"
    working_copy.write_bytes(b"synthetic evidence")

    with pytest.raises(ExifToolError, match="sandbox_required"):
        collect_metadata(working_copy)


def test_resolve_verified_working_copy_checks_registered_digest(tmp_path: Path) -> None:
    evidence_id = uuid4()
    content = b"synthetic evidence"
    working_copy = tmp_path / f"{evidence_id}.working-copy"
    working_copy.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()

    assert resolve_verified_working_copy(tmp_path, evidence_id, digest) == working_copy
    with pytest.raises(ValueError, match="does not match"):
        resolve_verified_working_copy(tmp_path, evidence_id, "0" * 64)
