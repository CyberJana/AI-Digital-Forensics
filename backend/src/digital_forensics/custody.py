import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from digital_forensics.models import CustodyEvent, EvidenceItem, utc_now


def append_custody_event(
    db: Session,
    *,
    evidence_id: UUID,
    actor_id: UUID,
    event_type: str,
    details: dict[str, Any],
    notes: str | None = None,
) -> CustodyEvent:
    evidence = db.scalar(
        select(EvidenceItem)
        .where(EvidenceItem.id == evidence_id)
        .with_for_update()
    )
    if evidence is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")

    previous_event = db.scalar(
        select(CustodyEvent)
        .where(CustodyEvent.evidence_id == evidence_id)
        .order_by(CustodyEvent.sequence.desc())
        .limit(1)
    )
    previous_hash = previous_event.event_hash if previous_event is not None else None
    event = CustodyEvent(
        id=uuid4(),
        evidence_id=evidence_id,
        sequence=previous_event.sequence + 1 if previous_event is not None else 1,
        actor_id=actor_id,
        event_type=event_type,
        notes=notes,
        details=details,
        previous_hash=previous_hash,
        event_hash="",
        recorded_at=utc_now(),
    )
    event.event_hash = calculate_event_hash(event)
    db.add(event)
    db.flush()
    return event


def verify_custody_chain(events: list[CustodyEvent]) -> bool:
    if not events:
        return False
    previous_hash = None
    for expected_sequence, event in enumerate(events, start=1):
        if event.sequence != expected_sequence or event.previous_hash != previous_hash:
            return False
        if event.event_hash != calculate_event_hash(event):
            return False
        previous_hash = event.event_hash
    return True


def calculate_event_hash(event: CustodyEvent) -> str:
    payload = {
        "actor_id": str(event.actor_id),
        "details": event.details,
        "event_id": str(event.id),
        "event_type": event.event_type,
        "evidence_id": str(event.evidence_id),
        "notes": event.notes,
        "previous_hash": event.previous_hash,
        "recorded_at": _utc_isoformat(event.recorded_at),
        "sequence": event.sequence,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _utc_isoformat(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()
