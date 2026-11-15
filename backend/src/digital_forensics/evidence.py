from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import AwareDatetime, BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from digital_forensics.case_access import CaseAccess, get_case_access, require_case_roles
from digital_forensics.custody import append_custody_event, verify_custody_chain
from digital_forensics.database import get_db_session
from digital_forensics.identity import AuthenticatedUser, get_authenticated_user, require_csrf
from digital_forensics.models import (
    AcquisitionRecord,
    CaseRole,
    CaseStatus,
    CustodyEvent,
    EvidenceItem,
    HashVerification,
    utc_now,
)

router = APIRouter(tags=["evidence"])
DatabaseSession = Annotated[Session, Depends(get_db_session)]
CurrentUser = Annotated[AuthenticatedUser, Depends(get_authenticated_user)]
CsrfProtected = Annotated[None, Depends(require_csrf)]


class RegisterEvidenceRequest(BaseModel):
    evidence_number: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    size_bytes: int = Field(ge=0)
    media_type: str | None = Field(default=None, max_length=255)
    original_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    acquisition_method: str = Field(min_length=1, max_length=100)
    source_description: str = Field(min_length=1, max_length=1000)
    acquired_at: AwareDatetime


class HashVerificationRequest(BaseModel):
    submitted_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class CustodyEventRequest(BaseModel):
    event_type: Literal["received", "transferred", "stored", "released", "examined"]
    notes: str | None = Field(default=None, max_length=2000)


def _require_evidence(
    db: Session, current: AuthenticatedUser, evidence_id: UUID
) -> tuple[EvidenceItem, CaseAccess]:
    evidence = db.get(EvidenceItem, evidence_id)
    if evidence is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")
    access = get_case_access(db, current.user.id, evidence.case_id)
    return evidence, access


def _require_evidence_writer(access: CaseAccess) -> None:
    if access.case.status != CaseStatus.OPEN:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Closed cases are read-only")
    require_case_roles(access, {CaseRole.OWNER, CaseRole.EXAMINER})


def _evidence_response(evidence: EvidenceItem) -> dict[str, object]:
    return {
        "id": evidence.id,
        "case_id": evidence.case_id,
        "evidence_number": evidence.evidence_number,
        "name": evidence.name,
        "description": evidence.description,
        "size_bytes": evidence.size_bytes,
        "media_type": evidence.media_type,
        "original_sha256": evidence.original_sha256,
        "registered_by": evidence.registered_by,
        "created_at": evidence.created_at,
        "binary_available": False,
    }


def _custody_event_response(event: CustodyEvent) -> dict[str, object]:
    return {
        "id": event.id,
        "sequence": event.sequence,
        "actor_id": event.actor_id,
        "event_type": event.event_type,
        "notes": event.notes,
        "details": event.details,
        "previous_hash": event.previous_hash,
        "event_hash": event.event_hash,
        "recorded_at": event.recorded_at,
    }


def _acquisition_response(acquisition: AcquisitionRecord) -> dict[str, object]:
    return {
        "id": acquisition.id,
        "evidence_id": acquisition.evidence_id,
        "acquired_by": acquisition.acquired_by,
        "acquisition_method": acquisition.acquisition_method,
        "source_description": acquisition.source_description,
        "acquired_at": acquisition.acquired_at,
        "recorded_at": acquisition.recorded_at,
    }


def _hash_verification_response(verification: HashVerification) -> dict[str, object]:
    return {
        "id": verification.id,
        "evidence_id": verification.evidence_id,
        "checked_by": verification.checked_by,
        "submitted_sha256": verification.submitted_sha256,
        "matched": verification.matched,
        "checked_at": verification.checked_at,
    }


@router.post(
    "/cases/{case_id}/evidence",
    status_code=status.HTTP_201_CREATED,
)
def register_evidence(
    case_id: UUID,
    payload: RegisterEvidenceRequest,
    db: DatabaseSession,
    current: CurrentUser,
    _: CsrfProtected,
) -> dict[str, object]:
    access = get_case_access(db, current.user.id, case_id)
    _require_evidence_writer(access)

    existing = db.scalar(
        select(EvidenceItem).where(
            EvidenceItem.case_id == case_id,
            EvidenceItem.evidence_number == payload.evidence_number,
        )
    )
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Evidence number already exists in this case",
        )

    evidence = EvidenceItem(
        case_id=case_id,
        evidence_number=payload.evidence_number,
        name=payload.name,
        description=payload.description,
        size_bytes=payload.size_bytes,
        media_type=payload.media_type,
        original_sha256=payload.original_sha256,
        registered_by=current.user.id,
    )
    db.add(evidence)
    db.flush()
    acquisition = AcquisitionRecord(
        evidence_id=evidence.id,
        acquired_by=current.user.id,
        acquisition_method=payload.acquisition_method,
        source_description=payload.source_description,
        acquired_at=payload.acquired_at,
    )
    db.add(acquisition)
    db.flush()
    append_custody_event(
        db,
        evidence_id=evidence.id,
        actor_id=current.user.id,
        event_type="registered",
        details={
            "acquisition_id": str(acquisition.id),
            "acquisition_sha256": payload.original_sha256,
            "size_bytes": payload.size_bytes,
        },
    )
    db.commit()
    db.refresh(evidence)
    return _evidence_response(evidence)


@router.get("/cases/{case_id}/evidence")
def list_evidence(
    case_id: UUID,
    db: DatabaseSession,
    current: CurrentUser,
) -> list[dict[str, object]]:
    get_case_access(db, current.user.id, case_id)
    evidence_items = db.scalars(
        select(EvidenceItem)
        .where(EvidenceItem.case_id == case_id)
        .order_by(EvidenceItem.created_at, EvidenceItem.id)
    ).all()
    return [_evidence_response(evidence) for evidence in evidence_items]


@router.get("/evidence/{evidence_id}")
def get_evidence(
    evidence_id: UUID,
    db: DatabaseSession,
    current: CurrentUser,
) -> dict[str, object]:
    evidence, _ = _require_evidence(db, current, evidence_id)
    return _evidence_response(evidence)


@router.get("/evidence/{evidence_id}/acquisitions")
def list_acquisitions(
    evidence_id: UUID,
    db: DatabaseSession,
    current: CurrentUser,
) -> list[dict[str, object]]:
    _require_evidence(db, current, evidence_id)
    acquisitions = db.scalars(
        select(AcquisitionRecord)
        .where(AcquisitionRecord.evidence_id == evidence_id)
        .order_by(AcquisitionRecord.acquired_at, AcquisitionRecord.id)
    ).all()
    return [_acquisition_response(acquisition) for acquisition in acquisitions]


@router.post(
    "/evidence/{evidence_id}/hash-verifications",
    status_code=status.HTTP_201_CREATED,
)
def verify_evidence_hash(
    evidence_id: UUID,
    payload: HashVerificationRequest,
    db: DatabaseSession,
    current: CurrentUser,
    _: CsrfProtected,
) -> dict[str, object]:
    evidence, access = _require_evidence(db, current, evidence_id)
    _require_evidence_writer(access)
    matched = payload.submitted_sha256 == evidence.original_sha256
    verification = HashVerification(
        evidence_id=evidence.id,
        checked_by=current.user.id,
        submitted_sha256=payload.submitted_sha256,
        matched=matched,
    )
    db.add(verification)
    db.flush()
    append_custody_event(
        db,
        evidence_id=evidence.id,
        actor_id=current.user.id,
        event_type="hash_match" if matched else "hash_mismatch",
        details={
            "submitted_sha256": payload.submitted_sha256,
            "original_sha256": evidence.original_sha256,
            "verification_id": str(verification.id),
            "matched": matched,
        },
    )
    db.commit()
    return {
        "verification_id": verification.id,
        "evidence_id": evidence.id,
        "matched": matched,
        "recorded_sha256": evidence.original_sha256,
        "submitted_sha256": verification.submitted_sha256,
    }


@router.get("/evidence/{evidence_id}/hash-verifications")
def list_hash_verifications(
    evidence_id: UUID,
    db: DatabaseSession,
    current: CurrentUser,
) -> list[dict[str, object]]:
    _require_evidence(db, current, evidence_id)
    verifications = db.scalars(
        select(HashVerification)
        .where(HashVerification.evidence_id == evidence_id)
        .order_by(HashVerification.checked_at, HashVerification.id)
    ).all()
    return [_hash_verification_response(verification) for verification in verifications]


@router.post(
    "/evidence/{evidence_id}/custody-events",
    status_code=status.HTTP_201_CREATED,
)
def record_custody_event(
    evidence_id: UUID,
    payload: CustodyEventRequest,
    db: DatabaseSession,
    current: CurrentUser,
    _: CsrfProtected,
) -> dict[str, object]:
    evidence, access = _require_evidence(db, current, evidence_id)
    _require_evidence_writer(access)
    event = append_custody_event(
        db,
        evidence_id=evidence.id,
        actor_id=current.user.id,
        event_type=payload.event_type,
        details={},
        notes=payload.notes,
    )
    db.commit()
    return _custody_event_response(event)


@router.get("/evidence/{evidence_id}/custody-events")
def list_custody_events(
    evidence_id: UUID,
    db: DatabaseSession,
    current: CurrentUser,
) -> list[dict[str, object]]:
    _require_evidence(db, current, evidence_id)
    events = db.scalars(
        select(CustodyEvent)
        .where(CustodyEvent.evidence_id == evidence_id)
        .order_by(CustodyEvent.sequence)
    ).all()
    return [_custody_event_response(event) for event in events]


@router.get("/evidence/{evidence_id}/custody-events/verification")
def verify_custody_events(
    evidence_id: UUID,
    db: DatabaseSession,
    current: CurrentUser,
) -> dict[str, object]:
    _require_evidence(db, current, evidence_id)
    events = list(
        db.scalars(
            select(CustodyEvent)
            .where(CustodyEvent.evidence_id == evidence_id)
            .order_by(CustodyEvent.sequence)
        ).all()
    )
    return {
        "evidence_id": evidence_id,
        "valid": bool(events) and verify_custody_chain(events),
        "event_count": len(events),
        "head_hash": events[-1].event_hash if events else None,
    }
