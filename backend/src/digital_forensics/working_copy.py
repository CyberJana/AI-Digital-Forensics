import argparse
import hashlib
import json
import os
import stat
from dataclasses import asdict, dataclass
from pathlib import Path

from digital_forensics.hashing import CHUNK_SIZE, hash_file_read_only


@dataclass(frozen=True)
class VerifiedWorkingCopy:
    path: str
    sha256: str
    size_bytes: int


def create_verified_working_copy(source: Path, destination: Path) -> VerifiedWorkingCopy:
    source_info = source.lstat()
    if not stat.S_ISREG(source_info.st_mode):
        raise ValueError("The source must be a regular, non-symlink file")
    if not destination.parent.is_dir():
        raise FileNotFoundError("The working-copy destination directory must exist")
    if destination.exists():
        raise FileExistsError("The working-copy destination already exists")
    if source.resolve() == destination.resolve():
        raise ValueError("The source and working-copy paths must differ")

    source_digest = hashlib.sha256()
    bytes_written = 0
    created_destination = False
    complete = False
    try:
        with source.open("rb") as source_file:
            before = os.fstat(source_file.fileno())
            if not stat.S_ISREG(before.st_mode) or _signature(source_info) != _signature(before):
                raise RuntimeError("The source file changed before copying")
            with destination.open("xb") as destination_file:
                created_destination = True
                while chunk := source_file.read(CHUNK_SIZE):
                    source_digest.update(chunk)
                    destination_file.write(chunk)
                    bytes_written += len(chunk)
                destination_file.flush()
                os.fsync(destination_file.fileno())
            after = os.fstat(source_file.fileno())

        if _signature(before) != _signature(after) or bytes_written != before.st_size:
            raise RuntimeError("The source file changed while being copied")
        source_sha256 = source_digest.hexdigest()
        copied = hash_file_read_only(destination)
        if copied.size_bytes != bytes_written or copied.sha256 != source_sha256:
            raise RuntimeError("The working copy does not match the source")
        destination.chmod(stat.S_IREAD)
        complete = True
        return VerifiedWorkingCopy(
            path=str(destination),
            sha256=copied.sha256,
            size_bytes=copied.size_bytes,
        )
    finally:
        if created_destination and not complete:
            destination.unlink(missing_ok=True)


def _signature(file_stat: os.stat_result) -> tuple[int, int, int, int]:
    return file_stat.st_dev, file_stat.st_ino, file_stat.st_size, file_stat.st_mtime_ns


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create a verified, read-only local working copy of a regular file."
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    print(json.dumps(asdict(create_verified_working_copy(args.source, args.destination))))


if __name__ == "__main__":
    main()
