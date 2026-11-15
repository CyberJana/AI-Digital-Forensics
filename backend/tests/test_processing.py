import hashlib
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi import FastAPI
from httpx import AsyncClient
from sqlalchemy import select

from digital_forensics.models import (
    CaseAssignment,
    CaseRole,
    CaseStatus,
    EvidenceItem,
    InvestigationCase,
    ProcessingJob,
    ProcessingJobStatus,
    utc_now,
)
from digital_forensics.worker import claim_next_job, run_next_job
from digital_forensics.working_copy import create_verified_working_copy

from support import authenticate, create_test_identity


async def _create_case_evidence_and_job(
    client: AsyncClient,
    identity: dict[str, object],
) -> tuple[str, str, dict[str, object]]:
    headers = {"X-CSRF-Token": str(identity["csrf_token"])}
    case_response = await client.post(
        f"/organizations/{identity['organization_id']}/cases",
        json={"case_number": "JOB-001", "name": "Processing test"},
        headers=headers,
    )
    assert case_response.status_code == 201
    case_id = case_response.json()["id"]
    evidence_response = await client.post(
        f"/cases/{case_id}/evidence",
        json={
            "evidence_number": "JOB-E1",
            "name": "Metadata-only evidence",
            "size_bytes": 4,
            "original_sha256": hashlib.sha256(b"data").hexdigest(),
            "acquisition_method": "test fixture",
            "source_description": "Synthetic test data",
            "acquired_at": datetime.now(UTC).isoformat(),
        },
        headers=headers,
    )
    assert evidence_response.status_code == 201
    evidence_id = evidence_response.json()["id"]
    job_response = await client.post(
        f"/cases/{case_id}/processing-jobs",
        json={
            "evidence_id": evidence_id,
            "adapter_name": "custody-chain-verification",
        },
        headers=headers,
    )
    assert job_response.status_code == 202
    return case_id, evidence_id, job_response.json()


@pytest.mark.anyio
async def test_worker_executes_registered_adapter_and_persists_result(
    client: AsyncClient, app: FastAPI
) -> None:
    identity = create_test_identity(app)
    authenticate(client, identity)
    case_id, evidence_id, job = await _create_case_evidence_and_job(client, identity)

    processed = run_next_job(
        app.state.session_factory,
        worker_id="test-worker",
    )
    response = await client.get(f"/processing-jobs/{job['id']}")

    assert processed is True
    assert response.status_code == 200
    assert response.json()["status"] == "succeeded"
    assert response.json()["attempt_count"] == 1
    assert response.json()["result"]["valid"] is True
    assert response.json()["result"]["event_count"] == 1
    assert len(response.json()["result"]["head_hash"]) == 64
    assert response.json()["case_id"] == case_id
    assert response.json()["evidence_id"] == evidence_id
    assert "path" not in response.json()


@pytest.mark.anyio
async def test_queued_job_can_be_cancelled_before_worker_claims_it(
    client: AsyncClient, app: FastAPI
) -> None:
    identity = create_test_identity(app)
    authenticate(client, identity)
    _, _, job = await _create_case_evidence_and_job(client, identity)

    cancelled = await client.post(
        f"/processing-jobs/{job['id']}/cancel",
        headers={"X-CSRF-Token": str(identity["csrf_token"])},
    )
    processed = run_next_job(app.state.session_factory, worker_id="test-worker")

    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"
    assert processed is False


@pytest.mark.anyio
async def test_unknown_adapter_and_adapter_parameters_are_rejected(
    client: AsyncClient, app: FastAPI
) -> None:
    identity = create_test_identity(app)
    authenticate(client, identity)
    case_id, evidence_id, _ = await _create_case_evidence_and_job(client, identity)
    headers = {"X-CSRF-Token": str(identity["csrf_token"])}

    unknown = await client.post(
        f"/cases/{case_id}/processing-jobs",
        json={"evidence_id": evidence_id, "adapter_name": "not-registered"},
        headers=headers,
    )
    unsupported_parameters = await client.post(
        f"/cases/{case_id}/processing-jobs",
        json={
            "evidence_id": evidence_id,
            "adapter_name": "custody-chain-verification",
            "parameters": {"source_path": "C:\\evidence\\disk.E01"},
        },
        headers=headers,
    )
    disabled_adapter = await client.post(
        f"/cases/{case_id}/processing-jobs",
        json={"evidence_id": evidence_id, "adapter_name": "exiftool-metadata"},
        headers=headers,
    )

    assert unknown.status_code == 422
    assert unsupported_parameters.status_code == 422
    assert disabled_adapter.status_code == 503
    assert disabled_adapter.json()["detail"] == (
        "Adapter execution is disabled until sandboxing is approved"
    )


@pytest.mark.anyio
async def test_worker_fails_closed_for_directly_queued_disabled_adapter(
    client: AsyncClient,
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = create_test_identity(app)
    authenticate(client, identity)
    _, _, initial_job = await _create_case_evidence_and_job(client, identity)
    await client.post(
        f"/processing-jobs/{initial_job['id']}/cancel",
        headers={"X-CSRF-Token": str(identity["csrf_token"])},
    )
    with app.state.session_factory() as db:
        evidence = db.scalar(
            select(EvidenceItem).where(EvidenceItem.evidence_number == "JOB-E1")
        )
        assert evidence is not None
        job = ProcessingJob(
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            requested_by=identity["user_id"],
            adapter_name="exiftool-metadata",
            adapter_version="1.0",
            status=ProcessingJobStatus.QUEUED,
            parameters={},
        )
        db.add(job)
        db.commit()
        job_id = job.id

    def unexpected_execution(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("ExifTool must not be executed")

    monkeypatch.setattr(
        "digital_forensics.processing.ExifToolMetadataAdapter.run",
        unexpected_execution,
    )

    assert run_next_job(app.state.session_factory, worker_id="test-worker") is True
    with app.state.session_factory() as db:
        failed_job = db.get(ProcessingJob, job_id)
        assert failed_job is not None
        assert failed_job.status == ProcessingJobStatus.FAILED
        assert failed_job.error_code == "adapter_disabled"
        assert failed_job.attempt_count == 1


def test_expired_worker_lease_requeues_job_and_enforces_attempt_limit(
    app: FastAPI,
) -> None:
    user = create_test_identity(app)
    with app.state.session_factory() as db:
        case = InvestigationCase(
            organization_id=user["organization_id"],
            case_number="LEASE-001",
            name="Lease recovery",
            created_by=user["user_id"],
            status=CaseStatus.OPEN,
        )
        db.add(case)
        db.flush()
        db.add(CaseAssignment(case_id=case.id, user_id=user["user_id"], role=CaseRole.OWNER))
        evidence = EvidenceItem(
            case_id=case.id,
            evidence_number="LEASE-E1",
            name="Lease test",
            size_bytes=0,
            original_sha256="a" * 64,
            registered_by=user["user_id"],
        )
        db.add(evidence)
        db.flush()
        retryable = ProcessingJob(
            case_id=case.id,
            evidence_id=evidence.id,
            requested_by=user["user_id"],
            adapter_name="custody-chain-verification",
            adapter_version="1.0",
            status=ProcessingJobStatus.RUNNING,
            attempt_count=1,
            max_attempts=3,
            worker_id="abandoned",
            lease_expires_at=utc_now() - timedelta(seconds=1),
        )
        exhausted = ProcessingJob(
            case_id=case.id,
            evidence_id=evidence.id,
            requested_by=user["user_id"],
            adapter_name="custody-chain-verification",
            adapter_version="1.0",
            status=ProcessingJobStatus.RUNNING,
            attempt_count=3,
            max_attempts=3,
            worker_id="abandoned",
            lease_expires_at=utc_now() - timedelta(seconds=1),
        )
        db.add_all([retryable, exhausted])
        db.commit()
        retryable_id = retryable.id
        exhausted_id = exhausted.id

    claimed_id = claim_next_job(
        app.state.session_factory,
        worker_id="recovery-worker",
    )
    with app.state.session_factory() as db:
        requeued = db.get(ProcessingJob, retryable_id)
        failed = db.get(ProcessingJob, exhausted_id)
        assert requeued is not None
        assert failed is not None
        assert claimed_id == retryable_id
        assert requeued.status == ProcessingJobStatus.RUNNING
        assert requeued.attempt_count == 2
        assert requeued.worker_id == "recovery-worker"
        assert failed.status == ProcessingJobStatus.FAILED
        assert failed.error_code == "worker_lease_expired"


@pytest.mark.anyio
async def test_verified_working_copy_is_read_only_and_matches_source(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.img"
    destination = tmp_path / "working" / "copy.img"
    destination.parent.mkdir()
    content = b"synthetic evidence bytes"
    source.write_bytes(content)

    result = create_verified_working_copy(source, destination)

    assert result.sha256 == hashlib.sha256(content).hexdigest()
    assert result.size_bytes == len(content)
    assert destination.read_bytes() == content
    assert source.read_bytes() == content
    assert destination.stat().st_mode & stat.S_IWRITE == 0
    with pytest.raises(FileExistsError):
        create_verified_working_copy(source, destination)
