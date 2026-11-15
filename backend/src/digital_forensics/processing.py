from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import UUID

from digital_forensics.custody import verify_custody_chain
from digital_forensics.exiftool import collect_metadata
from digital_forensics.models import CustodyEvent


@dataclass(frozen=True)
class ProcessingContext:
    job_id: UUID
    case_id: UUID
    evidence_id: UUID
    parameters: dict[str, object]
    custody_events: tuple[CustodyEvent, ...]
    working_copy_path: Path | None = None
    expected_sha256: str | None = None
    exiftool_executable: str = "exiftool"


class ProcessingAdapter(Protocol):
    name: str
    version: str
    enabled: bool

    def run(self, context: ProcessingContext) -> dict[str, object]: ...


class CustodyChainVerificationAdapter:
    name = "custody-chain-verification"
    version = "1.0"
    enabled = True

    def run(self, context: ProcessingContext) -> dict[str, object]:
        events = list(context.custody_events)
        return {
            "valid": verify_custody_chain(events),
            "event_count": len(events),
            "head_hash": events[-1].event_hash if events else None,
        }


class ExifToolMetadataAdapter:
    name = "exiftool-metadata"
    version = "1.0"
    enabled = False

    def run(self, context: ProcessingContext) -> dict[str, object]:
        if not self.enabled:
            raise RuntimeError("sandbox_required")
        if context.working_copy_path is None:
            raise RuntimeError("working_copy_unavailable")
        result = collect_metadata(
            context.working_copy_path,
            executable=context.exiftool_executable,
        )
        if (
            context.expected_sha256 is not None
            and result["working_copy_sha256"] != context.expected_sha256
        ):
            raise RuntimeError("working_copy_digest_mismatch")
        return result


ADAPTERS: dict[str, ProcessingAdapter] = {
    CustodyChainVerificationAdapter.name: CustodyChainVerificationAdapter(),
    ExifToolMetadataAdapter.name: ExifToolMetadataAdapter(),
}


def get_adapter(name: str) -> ProcessingAdapter | None:
    return ADAPTERS.get(name)
