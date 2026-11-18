import argparse
import json
import logging
import os
import socket
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

from sqlalchemy import select, update
from sqlalchemy.orm import Session, sessionmaker

from digital_forensics.database import create_database_engine, create_session_factory
from digital_forensics.exiftool_broker import ExifToolBrokerClient
from digital_forensics.models import (
    CaseStatus,
    CustodyEvent,
    EvidenceItem,
    InvestigationCase,
    ProcessingJob,
    ProcessingJobStatus,
    utc_now,
)
from digital_forensics.processing import ExifToolMetadataAdapter, ProcessingContext, get_adapter
from digital_forensics.settings import get_settings
from digital_forensics.working_copy import resolve_verified_working_copy

logger = logging.getLogger(__name__)
MAX_RESULT_BYTES = 1_000_000


def recover_expired_jobs(db: Session, *, now: datetime | None = None) -> int:
    current_time = now or utc_now()
    expired_jobs = db.scalars(
        select(ProcessingJob)
        .where(
            ProcessingJob.status == ProcessingJobStatus.RUNNING,
            ProcessingJob.lease_expires_at <= current_time,
        )
        .with_for_update(skip_locked=True)
    ).all()
    for job in expired_jobs:
        job.worker_id = None
        job.lease_expires_at = None
        job.updated_at = current_time
        job.error_code = "worker_lease_expired"
        if job.attempt_count < job.max_attempts:
            job.status = ProcessingJobStatus.QUEUED
            job.completed_at = None
        else:
            job.status = ProcessingJobStatus.FAILED
            job.completed_at = current_time
    return len(expired_jobs)


def claim_next_job(
    session_factory: sessionmaker[Session],
    *,
    worker_id: str,
    lease_seconds: int = 300,
) -> UUID | None:
    now = utc_now()
    with session_factory() as db:
        recover_expired_jobs(db, now=now)
        db.flush()
        job_id = db.scalar(
            select(ProcessingJob.id)
            .where(
                ProcessingJob.status == ProcessingJobStatus.QUEUED,
                ProcessingJob.attempt_count < ProcessingJob.max_attempts,
            )
            .order_by(ProcessingJob.created_at, ProcessingJob.id)
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        if job_id is None:
            db.commit()
            return None

        claimed = db.execute(
            update(ProcessingJob)
            .where(
                ProcessingJob.id == job_id,
                ProcessingJob.status == ProcessingJobStatus.QUEUED,
                ProcessingJob.attempt_count < ProcessingJob.max_attempts,
            )
            .values(
                status=ProcessingJobStatus.RUNNING,
                worker_id=worker_id,
                attempt_count=ProcessingJob.attempt_count + 1,
                started_at=now,
                completed_at=None,
                lease_expires_at=now + timedelta(seconds=lease_seconds),
                updated_at=now,
            )
        )
        if claimed.rowcount != 1:
            db.rollback()
            return None
        db.commit()
        return job_id


def run_next_job(
    session_factory: sessionmaker[Session],
    *,
    worker_id: str,
    lease_seconds: int = 300,
    working_copy_root: Path | None = None,
    exiftool_executable: str = "exiftool",
    exiftool_sandbox_enabled: bool = False,
    exiftool_broker_socket_path: Path | None = None,
) -> bool:
    job_id = claim_next_job(
        session_factory,
        worker_id=worker_id,
        lease_seconds=lease_seconds,
    )
    if job_id is None:
        return False

    try:
        context, adapter_name, adapter_version = _load_processing_context(
            session_factory,
            job_id,
            worker_id=worker_id,
        )
        adapter = get_adapter(adapter_name)
        if adapter is None or adapter.version != adapter_version:
            raise RuntimeError("adapter_unavailable")
        sandbox_configured = (
            adapter.name == "exiftool-metadata"
            and exiftool_sandbox_enabled
            and exiftool_broker_socket_path is not None
            and working_copy_root is not None
        )
        if not adapter.enabled and not sandbox_configured:
            raise RuntimeError("adapter_disabled")
        if adapter.name == "exiftool-metadata":
            if not sandbox_configured:
                raise RuntimeError("adapter_disabled")
            if working_copy_root is None or exiftool_broker_socket_path is None:
                raise RuntimeError("working_copy_root_unconfigured")
            try:
                context = replace(
                    context,
                    working_copy_path=resolve_verified_working_copy(
                        working_copy_root,
                        context.evidence_id,
                        context.expected_sha256 or "",
                    ),
                    exiftool_executable=exiftool_executable,
                )
            except (OSError, ValueError) as error:
                raise RuntimeError("working_copy_invalid") from error
            if not isinstance(adapter, ExifToolMetadataAdapter):
                raise RuntimeError("adapter_unavailable")
            result = adapter.run(
                context,
                broker=ExifToolBrokerClient(exiftool_broker_socket_path),
            )
        else:
            result = adapter.run(context)
        if not isinstance(result, dict):
            raise ValueError("adapter_result_not_object")
        serialized_result = json.dumps(result, sort_keys=True, allow_nan=False)
        if len(serialized_result.encode("utf-8")) > MAX_RESULT_BYTES:
            raise ValueError("adapter_result_too_large")
    except Exception as error:
        error_code = str(error) if str(error) in {
            "adapter_unavailable",
            "adapter_disabled",
            "case_closed",
            "invalid_processing_context",
            "adapter_result_too_large",
            "adapter_result_not_object",
            "working_copy_root_unconfigured",
            "working_copy_invalid",
            "working_copy_digest_mismatch",
            "working_copy_unavailable",
            "working_copy_digest_unavailable",
        } else type(error).__name__
        retryable = error_code not in {
            "adapter_unavailable",
            "adapter_disabled",
            "case_closed",
            "invalid_processing_context",
            "adapter_result_too_large",
            "adapter_result_not_object",
            "working_copy_root_unconfigured",
            "working_copy_invalid",
            "working_copy_digest_mismatch",
            "working_copy_unavailable",
            "working_copy_digest_unavailable",
        }
        finished = _finish_job(
            session_factory,
            job_id=job_id,
            worker_id=worker_id,
            error_code=error_code,
            retryable=retryable,
        )
        if finished:
            logger.warning("Processing job %s failed: %s", job_id, error_code)
        else:
            logger.warning("Processing job %s lost its worker lease before failure was saved", job_id)
    else:
        finished = _finish_job(
            session_factory,
            job_id=job_id,
            worker_id=worker_id,
            result=result,
        )
        if finished:
            logger.info("Processing job %s completed", job_id)
        else:
            logger.warning("Processing job %s lost its worker lease before completion was saved", job_id)
    return True


def _load_processing_context(
    session_factory: sessionmaker[Session], job_id: UUID, *, worker_id: str
) -> tuple[ProcessingContext, str, str]:
    with session_factory() as db:
        job = db.get(ProcessingJob, job_id)
        if (
            job is None
            or job.status != ProcessingJobStatus.RUNNING
            or job.worker_id != worker_id
        ):
            raise RuntimeError("invalid_processing_context")
        case = db.get(InvestigationCase, job.case_id)
        evidence = db.get(EvidenceItem, job.evidence_id)
        if case is None or evidence is None or evidence.case_id != case.id:
            raise RuntimeError("invalid_processing_context")
        if case.status != CaseStatus.OPEN:
            raise RuntimeError("case_closed")
        events = tuple(
            db.scalars(
                select(CustodyEvent)
                .where(CustodyEvent.evidence_id == evidence.id)
                .order_by(CustodyEvent.sequence)
            ).all()
        )
        context = ProcessingContext(
            job_id=job.id,
            case_id=job.case_id,
            evidence_id=job.evidence_id,
            parameters=job.parameters,
            custody_events=events,
            expected_sha256=evidence.original_sha256,
        )
        return context, job.adapter_name, job.adapter_version


def _finish_job(
    session_factory: sessionmaker[Session],
    *,
    job_id: UUID,
    worker_id: str,
    result: dict[str, object] | None = None,
    error_code: str | None = None,
    retryable: bool = True,
) -> bool:
    now = utc_now()
    with session_factory() as db:
        job = db.scalar(
            select(ProcessingJob)
            .where(ProcessingJob.id == job_id)
            .with_for_update()
        )
        if (
            job is None
            or job.status != ProcessingJobStatus.RUNNING
            or job.worker_id != worker_id
        ):
            return False

        job.updated_at = now
        job.lease_expires_at = None
        job.result = result
        job.error_code = error_code
        if error_code is None:
            job.status = ProcessingJobStatus.SUCCEEDED
            job.completed_at = now
        elif retryable and job.attempt_count < job.max_attempts:
            job.status = ProcessingJobStatus.QUEUED
            job.worker_id = None
            job.completed_at = None
        else:
            job.status = ProcessingJobStatus.FAILED
            job.completed_at = now
        db.commit()
        return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the digital-forensics processing worker.")
    parser.add_argument("--poll-interval-seconds", type=int, default=2)
    parser.add_argument("--lease-seconds", type=int, default=300)
    args = parser.parse_args()
    if not 1 <= args.poll_interval_seconds <= 60:
        parser.error("--poll-interval-seconds must be between 1 and 60")
    if not 30 <= args.lease_seconds <= 3600:
        parser.error("--lease-seconds must be between 30 and 3600")

    settings = get_settings()
    if settings.database_url is None:
        parser.error("DIGITAL_FORENSICS_DATABASE_URL must be configured")

    logging.basicConfig(level=settings.log_level)
    engine = create_database_engine(settings.database_url.get_secret_value())
    session_factory = create_session_factory(engine)
    worker_id = f"{socket.gethostname()}:{os.getpid()}:{uuid4()}"
    logger.info("Processing worker started")
    try:
        while True:
            processed = run_next_job(
                session_factory,
                worker_id=worker_id,
                lease_seconds=args.lease_seconds,
                working_copy_root=settings.working_copy_root,
                exiftool_executable=settings.exiftool_executable,
                exiftool_sandbox_enabled=settings.exiftool_sandbox_enabled,
                exiftool_broker_socket_path=settings.exiftool_broker_socket_path,
            )
            if not processed:
                time.sleep(args.poll_interval_seconds)
    except KeyboardInterrupt:
        logger.info("Processing worker stopped")
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
