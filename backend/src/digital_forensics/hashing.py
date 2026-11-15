import argparse
import hashlib
import json
import os
import stat
from dataclasses import asdict, dataclass
from pathlib import Path

CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True)
class FileHash:
    algorithm: str
    sha256: str
    size_bytes: int


def hash_file_read_only(path: Path) -> FileHash:
    digest = hashlib.sha256()
    bytes_read = 0
    with path.open("rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("Only regular files can be hashed")

        while chunk := source.read(CHUNK_SIZE):
            digest.update(chunk)
            bytes_read += len(chunk)

        after = os.fstat(source.fileno())

    before_signature = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    after_signature = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if before_signature != after_signature or bytes_read != before.st_size:
        raise RuntimeError("The file changed while it was being hashed")

    return FileHash(algorithm="sha256", sha256=digest.hexdigest(), size_bytes=bytes_read)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Read a file without modifying it and print its SHA-256 digest."
    )
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    print(json.dumps(asdict(hash_file_read_only(args.path)), sort_keys=True))


if __name__ == "__main__":
    main()
