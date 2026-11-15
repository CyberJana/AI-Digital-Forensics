from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from digital_forensics.case_access import get_case_access
from digital_forensics.custody import verify_custody_chain
from digital_forensics.database import get_db_session
from digital_forensics.identity import AuthenticatedUser, get_authenticated_user
from digital_forensics.models import AcquisitionRecord, CustodyEvent, EvidenceItem

router = APIRouter(tags=["timeline"])
DatabaseSession = Annotated[Session, Depends(get_db_session)]
CurrentUser = Annotated[AuthenticatedUser, Depends(get_authenticated_user)]


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


@router.get("/cases/{case_id}/timeline")
def get_case_timeline(
    case_id: UUID,
    db: DatabaseSession,
    current: CurrentUser,
) -> dict[str, object]:
    get_case_access(db, current.user.id, case_id)
    return build_case_timeline(db, case_id)


def build_case_timeline(db: Session, case_id: UUID) -> dict[str, object]:
    evidence_items = db.scalars(
        select(EvidenceItem)
        .where(EvidenceItem.case_id == case_id)
        .order_by(EvidenceItem.id)
    ).all()
    acquisition_rows = db.execute(
        select(AcquisitionRecord, EvidenceItem)
        .join(EvidenceItem, EvidenceItem.id == AcquisitionRecord.evidence_id)
        .where(EvidenceItem.case_id == case_id)
    ).all()
    custody_rows = db.execute(
        select(CustodyEvent, EvidenceItem)
        .join(EvidenceItem, EvidenceItem.id == CustodyEvent.evidence_id)
        .where(EvidenceItem.case_id == case_id)
        .order_by(EvidenceItem.id, CustodyEvent.sequence)
    ).all()

    events: list[dict[str, object]] = []
    for acquisition, evidence in acquisition_rows:
        events.append(
            {
                "source_type": "acquisition",
                "source_record_id": acquisition.id,
                "event_type": "acquisition",
                "occurred_at": _as_utc(acquisition.acquired_at),
                "recorded_at": _as_utc(acquisition.recorded_at),
                "evidence_id": evidence.id,
                "evidence_number": evidence.evidence_number,
                "actor_id": acquisition.acquired_by,
                "details": {
                    "acquisition_method": acquisition.acquisition_method,
                    "source_description": acquisition.source_description,
                },
                "notes": None,
            }
        )

    custody_by_evidence: dict[UUID, list[CustodyEvent]] = {}
    for event, evidence in custody_rows:
        custody_by_evidence.setdefault(evidence.id, []).append(event)
        events.append(
            {
                "source_type": "custody",
                "source_record_id": event.id,
                "event_type": event.event_type,
                "occurred_at": _as_utc(event.recorded_at),
                "recorded_at": _as_utc(event.recorded_at),
                "evidence_id": evidence.id,
                "evidence_number": evidence.evidence_number,
                "actor_id": event.actor_id,
                "details": event.details,
                "notes": event.notes,
            }
        )

    events.sort(
        key=lambda item: (
            item["occurred_at"],
            item["source_type"],
            str(item["source_record_id"]),
        )
    )
    custody_verification = [
        {
            "evidence_id": evidence.id,
            "valid": bool(custody_by_evidence.get(evidence.id))
            and verify_custody_chain(custody_by_evidence[evidence.id]),
            "event_count": len(custody_by_evidence.get(evidence.id, [])),
            "head_hash": (
                custody_by_evidence[evidence.id][-1].event_hash
                if custody_by_evidence.get(evidence.id)
                else None
            ),
        }
        for evidence in evidence_items
    ]
    return {
        "case_id": case_id,
        "events": events,
        "custody_verification": custody_verification,
    }
