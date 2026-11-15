from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from digital_forensics.audit import record_case_audit
from digital_forensics.case_access import get_case_access, require_case_roles
from digital_forensics.database import get_db_session
from digital_forensics.identity import AuthenticatedUser, get_authenticated_user, require_csrf
from digital_forensics.models import (
    CaseRole,
    CaseStatus,
    EvidenceItem,
    ProcessingJob,
    ProcessingJobStatus,
)
from digital_forensics.processing import get_adapter

router = APIRouter(tags=["processing"])
DatabaseSession = Annotated[Session, Depends(get_db_session)]
CurrentUser = Annotated[AuthenticatedUser, Depends(get_authenticated_user)]
CsrfProtected = Annotated[None, Depends(require_csrf)]


class CreateProcessingJobRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: UUID
    adapter_name: str = Field(min_length=1, max_length=100)
    parameters: dict[str, object] = Field(default_factory=dict)


def _job_response(job: ProcessingJob) -> dict[str, object]:
    return {
        "id": job.id,
        "case_id": job.case_id,
        "evidence_id": job.evidence_id,
        "requested_by": job.requested_by,
        "adapter_name": job.adapter_name,
        "adapter_version": job.adapter_version,
        "status": job.status.value,
        "parameters": job.parameters,
        "result": job.result,
        "error_code": job.error_code,
        "attempt_count": job.attempt_count,
        "max_attempts": job.max_attempts,
        "created_at": job.created_at,
        "updated_at": job.updated_at,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
    }


def _require_job_access(db: Session, current: AuthenticatedUser, job_id: UUID) -> ProcessingJob:
    job = db.get(ProcessingJob, job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Processing job not found")
    get_case_access(db, current.user.id, job.case_id)
    return job


@router.post(
    "/cases/{case_id}/processing-jobs",
    status_code=status.HTTP_202_ACCEPTED,
)
def create_processing_job(
    case_id: UUID,
    payload: CreateProcessingJobRequest,
    db: DatabaseSession,
    current: CurrentUser,
    _: CsrfProtected,
) -> dict[str, object]:
    access = get_case_access(db, current.user.id, case_id)
    require_case_roles(access, {CaseRole.OWNER, CaseRole.EXAMINER})
    if access.case.status != CaseStatus.OPEN:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Closed cases cannot be processed")

    evidence = db.get(EvidenceItem, payload.evidence_id)
    if evidence is None or evidence.case_id != case_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")

    adapter = get_adapter(payload.adapter_name)
    if adapter is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Unknown adapter",
        )
    if not adapter.enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Adapter execution is disabled until sandboxing is approved",
        )
    if adapter.name == "custody-chain-verification" and payload.parameters:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="This adapter does not accept parameters",
        )

    job = ProcessingJob(
        case_id=case_id,
        evidence_id=evidence.id,
        requested_by=current.user.id,
        adapter_name=adapter.name,
        adapter_version=adapter.version,
        status=ProcessingJobStatus.QUEUED,
        parameters=payload.parameters,
    )
    db.add(job)
    db.flush()
    record_case_audit(
        db,
        case_id=case_id,
        actor_id=current.user.id,
        action="processing_job.created",
        target_type="processing_job",
        target_id=job.id,
        metadata={"adapter_name": job.adapter_name, "status": job.status.value},
    )
    db.commit()
    db.refresh(job)
    return _job_response(job)


@router.get("/cases/{case_id}/processing-jobs")
def list_processing_jobs(
    case_id: UUID,
    db: DatabaseSession,
    current: CurrentUser,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict[str, object]]:
    get_case_access(db, current.user.id, case_id)
    jobs = db.scalars(
        select(ProcessingJob)
        .where(ProcessingJob.case_id == case_id)
        .order_by(ProcessingJob.created_at.desc(), ProcessingJob.id)
        .limit(limit)
    ).all()
    return [_job_response(job) for job in jobs]


@router.get("/processing-jobs/{job_id}")
def get_processing_job(
    job_id: UUID,
    db: DatabaseSession,
    current: CurrentUser,
) -> dict[str, object]:
    job = _require_job_access(db, current, job_id)
    return _job_response(job)


@router.post("/processing-jobs/{job_id}/cancel")
def cancel_processing_job(
    job_id: UUID,
    db: DatabaseSession,
    current: CurrentUser,
    _: CsrfProtected,
) -> dict[str, object]:
    job = db.get(ProcessingJob, job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Processing job not found")
    access = get_case_access(db, current.user.id, job.case_id)
    require_case_roles(access, {CaseRole.OWNER, CaseRole.EXAMINER})
    now = datetime.now(UTC)
    cancelled = db.execute(
        update(ProcessingJob)
        .where(
            ProcessingJob.id == job_id,
            ProcessingJob.status == ProcessingJobStatus.QUEUED,
        )
        .values(
            status=ProcessingJobStatus.CANCELLED,
            updated_at=now,
            completed_at=now,
        )
    )
    if cancelled.rowcount != 1:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Only queued processing jobs can be cancelled",
        )
    record_case_audit(
        db,
        case_id=job.case_id,
        actor_id=current.user.id,
        action="processing_job.cancelled",
        target_type="processing_job",
        target_id=job.id,
    )
    db.commit()
    db.refresh(job)
    return _job_response(job)
