from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from digital_forensics.custody import verify_custody_chain
from digital_forensics.models import CustodyEvent


@dataclass(frozen=True)
class ProcessingContext:
    job_id: UUID
    case_id: UUID
    evidence_id: UUID
    parameters: dict[str, object]
    custody_events: tuple[CustodyEvent, ...]


class ProcessingAdapter(Protocol):
    name: str
    version: str

    def run(self, context: ProcessingContext) -> dict[str, object]: ...


class CustodyChainVerificationAdapter:
    name = "custody-chain-verification"
    version = "1.0"

    def run(self, context: ProcessingContext) -> dict[str, object]:
        events = list(context.custody_events)
        return {
            "valid": verify_custody_chain(events),
            "event_count": len(events),
            "head_hash": events[-1].event_hash if events else None,
        }


ADAPTERS: dict[str, ProcessingAdapter] = {
    CustodyChainVerificationAdapter.name: CustodyChainVerificationAdapter(),
}


def get_adapter(name: str) -> ProcessingAdapter | None:
    return ADAPTERS.get(name)
