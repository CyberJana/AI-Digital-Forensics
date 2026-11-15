import logging
from urllib.parse import quote
from typing import Annotated, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import AwareDatetime, BaseModel, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile
from starlette.responses import StreamingResponse

from digital_forensics.audit import record_case_audit
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
from digital_forensics.storage import (
    EvidenceIntegrityError,
    EvidenceObjectStore,
    EvidenceTooLarge,
    StorageBusy,
    StorageUnavailable,
)

router = APIRouter(tags=["evidence"])
logger = logging.getLogger(__name__)
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


class UploadEvidenceForm(BaseModel):
    evidence_number: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
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
        "binary_available": (
            evidence.storage_object_key is not None
            and evidence.encrypted_data_key is not None
            and evidence.encryption_nonce is not None
            and evidence.encryption_tag is not None
        ),
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


def _cleanup_uploaded_object(
    storage: EvidenceObjectStore,
    object_key: str,
    version_id: str | None,
) -> bool:
    try:
        storage.delete(object_key, version_id)
    except StorageUnavailable:
        logger.exception("Could not remove unreferenced evidence object")
        return False
    return True


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
    record_case_audit(
        db,
        case_id=case_id,
        actor_id=current.user.id,
        action="evidence.registered",
        target_type="evidence",
        target_id=evidence.id,
    )
    db.commit()
    db.refresh(evidence)
    return _evidence_response(evidence)


@router.post(
    "/cases/{case_id}/evidence/upload",
    status_code=status.HTTP_201_CREATED,
)
async def upload_evidence(
    case_id: UUID,
    request: Request,
    db: DatabaseSession,
    current: CurrentUser,
    _: CsrfProtected,
) -> dict[str, object]:
    access = get_case_access(db, current.user.id, case_id)
    _require_evidence_writer(access)
    storage: EvidenceObjectStore | None = request.app.state.evidence_storage
    if storage is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Encrypted evidence storage is not configured",
        )
    form = await request.form(max_files=1, max_fields=6)
    allowed_fields = {
        "evidence_number",
        "name",
        "description",
        "acquisition_method",
        "source_description",
        "acquired_at",
        "file",
    }
    if set(form.keys()) - allowed_fields or any(
        len(form.getlist(field)) != 1
        for field in (
            "evidence_number",
            "name",
            "acquisition_method",
            "source_description",
            "acquired_at",
            "file",
        )
    ) or len(form.getlist("description")) > 1:
        await form.close()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Evidence upload form contains missing, duplicate, or unexpected fields",
        )
    try:
        payload = UploadEvidenceForm.model_validate(
            {
                field: form.get(field)
                for field in (
                    "evidence_number",
                    "name",
                    "description",
                    "acquisition_method",
                    "source_description",
                    "acquired_at",
                )
            }
        )
    except ValidationError as error:
        await form.close()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=[
                {"loc": item["loc"], "msg": item["msg"], "type": item["type"]}
                for item in error.errors()
            ],
        ) from error
    file = form.get("file")
    if not isinstance(file, UploadFile):
        await form.close()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Evidence upload requires one file",
        )
    if db.scalar(
        select(EvidenceItem).where(
            EvidenceItem.case_id == case_id,
            EvidenceItem.evidence_number == payload.evidence_number,
        )
    ):
        await form.close()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Evidence number already exists in this case",
        )
    db.rollback()

    evidence_id = uuid4()
    try:
        stored = await run_in_threadpool(
            storage.store,
            file.file,
            case_id=case_id,
            evidence_id=evidence_id,
        )
    except StorageBusy as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Another evidence upload is in progress",
            headers={"Retry-After": "30"},
        ) from error
    except StorageUnavailable as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Encrypted evidence storage is unavailable",
        ) from error
    except EvidenceIntegrityError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(error),
        ) from error
    except EvidenceTooLarge as error:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=str(error),
        ) from error
    finally:
        await form.close()
    media_type = file.content_type
    if media_type is not None and len(media_type) > 255:
        media_type = None
    evidence = EvidenceItem(
        id=evidence_id,
        case_id=case_id,
        evidence_number=payload.evidence_number,
        name=payload.name,
        description=payload.description,
        size_bytes=stored.size_bytes,
        media_type=media_type,
        original_sha256=stored.sha256,
        storage_object_key=stored.object_key,
        storage_version_id=stored.version_id,
        encrypted_data_key=stored.encrypted_data_key,
        encryption_nonce=stored.nonce,
        encryption_tag=stored.tag,
        registered_by=current.user.id,
    )
    try:
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
                "acquisition_sha256": stored.sha256,
                "size_bytes": stored.size_bytes,
                "encrypted_storage": "vault-transit-envelope",
            },
        )
        record_case_audit(
            db,
            case_id=case_id,
            actor_id=current.user.id,
            action="evidence.uploaded",
            target_type="evidence",
            target_id=evidence.id,
            metadata={"size_bytes": stored.size_bytes},
        )
    except HTTPException as error:
        db.rollback()
        if not await run_in_threadpool(
            _cleanup_uploaded_object, storage, stored.object_key, stored.version_id
        ):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=(
                    "Evidence registration was rejected; stored object cleanup "
                    "requires operator attention"
                ),
            ) from error
        raise
    except SQLAlchemyError as error:
        db.rollback()
        cleaned_up = await run_in_threadpool(
            _cleanup_uploaded_object,
            storage,
            stored.object_key,
            stored.version_id,
        )
        detail = (
            "Evidence metadata could not be saved"
            if cleaned_up
            else (
                "Evidence metadata could not be saved; stored object cleanup requires "
                "operator attention"
            )
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail,
        ) from error
    try:
        db.commit()
    except SQLAlchemyError as error:
        db.rollback()
        logger.error(
            "Evidence metadata commit outcome is uncertain; object retained for reconciliation (%s)",
            type(error).__name__,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Evidence registration outcome is uncertain; check the case evidence "
                "list before retrying"
            ),
        ) from error
    return _evidence_response(evidence)


@router.get("/evidence/{evidence_id}/binary")
def download_evidence(
    evidence_id: UUID,
    request: Request,
    db: DatabaseSession,
    current: CurrentUser,
) -> StreamingResponse:
    evidence, access = _require_evidence(db, current, evidence_id)
    object_key = evidence.storage_object_key
    encrypted_data_key = evidence.encrypted_data_key
    nonce = evidence.encryption_nonce
    tag = evidence.encryption_tag
    if (
        object_key is None
        or encrypted_data_key is None
        or nonce is None
        or tag is None
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence binary is not stored",
        )
    storage: EvidenceObjectStore | None = request.app.state.evidence_storage
    if storage is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Encrypted evidence storage is not configured",
        )
    record_case_audit(
        db,
        case_id=access.case.id,
        actor_id=current.user.id,
        action="evidence.binary_download_requested",
        target_type="evidence",
        target_id=evidence.id,
    )
    db.commit()
    try:
        verified = storage.verify(
            object_key=object_key,
            version_id=evidence.storage_version_id,
            encrypted_data_key=encrypted_data_key,
            nonce=nonce,
            tag=tag,
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            expected_sha256=evidence.original_sha256,
            expected_size=evidence.size_bytes,
        )
    except EvidenceIntegrityError as error:
        logger.error("Stored evidence failed integrity verification (%s)", evidence.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Stored evidence failed integrity verification",
        ) from error
    except StorageUnavailable as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Encrypted evidence storage is unavailable",
        ) from error

    filename = quote(evidence.name, safe="")
    return StreamingResponse(
        storage.stream(
            object_key=object_key,
            verified=verified,
            encrypted_data_key=encrypted_data_key,
            nonce=nonce,
            tag=tag,
            case_id=evidence.case_id,
            evidence_id=evidence.id,
        ),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{filename}",
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


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
    record_case_audit(
        db,
        case_id=evidence.case_id,
        actor_id=current.user.id,
        action="evidence.hash_verified",
        target_type="evidence",
        target_id=evidence.id,
        metadata={"matched": matched},
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
    record_case_audit(
        db,
        case_id=evidence.case_id,
        actor_id=current.user.id,
        action="evidence.custody_recorded",
        target_type="custody_event",
        target_id=event.id,
        metadata={"event_type": payload.event_type},
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
