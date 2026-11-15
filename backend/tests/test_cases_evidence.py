import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from fastapi import FastAPI
from httpx import AsyncClient
from sqlalchemy import select

from digital_forensics.auth import CSRF_COOKIE, SESSION_COOKIE
from digital_forensics.identity import digest_token
from digital_forensics.models import (
    AuthSession,
    CaseRole,
    CustodyEvent,
    Membership,
    MembershipRole,
    User,
)
from digital_forensics.hashing import hash_file_read_only

from support import authenticate, create_test_identity


def _headers(identity: dict[str, object]) -> dict[str, str]:
    return {"X-CSRF-Token": str(identity["csrf_token"])}


async def _create_case(client: AsyncClient, identity: dict[str, object]) -> str:
    response = await client.post(
        f"/organizations/{identity['organization_id']}/cases",
        json={"case_number": "CASE-001", "name": "Test case"},
        headers=_headers(identity),
    )
    assert response.status_code == 201
    return response.json()["id"]


@pytest.mark.anyio
async def test_evidence_hash_verification_and_custody_chain(
    client: AsyncClient, app: FastAPI
) -> None:
    identity = create_test_identity(app)
    authenticate(client, identity)
    case_id = await _create_case(client, identity)
    original_hash = "a" * 64

    registered = await client.post(
        f"/cases/{case_id}/evidence",
        json={
            "evidence_number": "E-001",
            "name": "Disk image",
            "size_bytes": 100,
            "original_sha256": original_hash,
            "acquisition_method": "write-blocked image",
            "source_description": "Seized workstation",
            "acquired_at": datetime.now(UTC).isoformat(),
        },
        headers=_headers(identity),
    )

    assert registered.status_code == 201
    evidence = registered.json()
    assert evidence["binary_available"] is False
    evidence_id = evidence["id"]

    acquisitions = await client.get(f"/evidence/{evidence_id}/acquisitions")
    assert acquisitions.status_code == 200
    assert acquisitions.json()[0]["acquisition_method"] == "write-blocked image"

    mismatch = await client.post(
        f"/evidence/{evidence_id}/hash-verifications",
        json={"submitted_sha256": "b" * 64},
        headers=_headers(identity),
    )
    assert mismatch.status_code == 201
    assert mismatch.json()["matched"] is False
    verifications = await client.get(f"/evidence/{evidence_id}/hash-verifications")
    assert verifications.status_code == 200
    assert verifications.json()[0]["matched"] is False

    recorded_event = await client.post(
        f"/evidence/{evidence_id}/custody-events",
        json={"event_type": "transferred", "notes": "Transferred to examiner"},
        headers=_headers(identity),
    )
    assert recorded_event.status_code == 201

    verified = await client.get(f"/evidence/{evidence_id}/custody-events/verification")
    assert verified.status_code == 200
    assert verified.json()["valid"] is True
    assert verified.json()["event_count"] == 3

    with app.state.session_factory() as db:
        first_event = db.scalar(
            select(CustodyEvent)
            .where(CustodyEvent.evidence_id == UUID(evidence_id))
            .order_by(CustodyEvent.sequence)
            .limit(1)
        )
        assert first_event is not None
        first_event.notes = "Tampered"
        db.commit()

    tampered = await client.get(f"/evidence/{evidence_id}/custody-events/verification")
    assert tampered.json()["valid"] is False


@pytest.mark.anyio
async def test_case_assignment_is_required_and_viewers_cannot_write_evidence(
    client: AsyncClient, app: FastAPI
) -> None:
    owner_identity = create_test_identity(app)
    authenticate(client, owner_identity)
    case_id = await _create_case(client, owner_identity)
    target_token = "target-session-token"
    target_csrf = "target-csrf-token"

    with app.state.session_factory() as db:
        target = User(email="viewer@example.test", display_name="Case Viewer")
        db.add(target)
        db.flush()
        db.add_all(
            [
                Membership(
                    organization_id=owner_identity["organization_id"],
                    user_id=target.id,
                    role=MembershipRole.EXAMINER,
                ),
                AuthSession(
                    user_id=target.id,
                    token_digest=digest_token(target_token),
                    csrf_digest=digest_token(target_csrf),
                    expires_at=datetime.now(UTC) + timedelta(hours=1),
                ),
            ]
        )
        db.commit()
        target_id = target.id

    client.cookies.set(SESSION_COOKIE, target_token)
    client.cookies.set(CSRF_COOKIE, target_csrf)
    unassigned = await client.get(f"/cases/{case_id}")
    assert unassigned.status_code == 404

    client.cookies.set(SESSION_COOKIE, str(owner_identity["raw_session_token"]))
    client.cookies.set(CSRF_COOKIE, str(owner_identity["csrf_token"]))
    assigned = await client.post(
        f"/cases/{case_id}/members",
        json={"user_id": str(target_id), "role": "viewer"},
        headers=_headers(owner_identity),
    )
    assert assigned.status_code == 201
    membership_removal = await client.delete(
        f"/organizations/{owner_identity['organization_id']}/members/{target_id}",
        headers=_headers(owner_identity),
    )
    assert membership_removal.status_code == 409

    client.cookies.set(SESSION_COOKIE, target_token)
    client.cookies.set(CSRF_COOKIE, target_csrf)
    visible_case = await client.get(f"/cases/{case_id}")
    forbidden_write = await client.post(
        f"/cases/{case_id}/evidence",
        json={
            "evidence_number": "E-002",
            "name": "Not authorized",
            "size_bytes": 0,
            "original_sha256": "c" * 64,
            "acquisition_method": "manual",
            "source_description": "Test",
            "acquired_at": datetime.now(UTC).isoformat(),
        },
        headers={"X-CSRF-Token": target_csrf},
    )
    assert visible_case.status_code == 200
    assert forbidden_write.status_code == 403


@pytest.mark.anyio
async def test_closed_case_rejects_evidence_writes(client: AsyncClient, app: FastAPI) -> None:
    identity = create_test_identity(app)
    authenticate(client, identity)
    case_id = await _create_case(client, identity)

    closed = await client.patch(
        f"/cases/{case_id}",
        json={"status": "closed"},
        headers=_headers(identity),
    )
    registration = await client.post(
        f"/cases/{case_id}/evidence",
        json={
            "evidence_number": "E-003",
            "name": "Closed-case item",
            "size_bytes": 0,
            "original_sha256": "d" * 64,
            "acquisition_method": "manual",
            "source_description": "Test",
            "acquired_at": datetime.now(UTC).isoformat(),
        },
        headers=_headers(identity),
    )

    assert closed.status_code == 200
    assert registration.status_code == 409


@pytest.mark.anyio
async def test_case_must_retain_at_least_one_owner(
    client: AsyncClient, app: FastAPI
) -> None:
    identity = create_test_identity(app)
    authenticate(client, identity)
    case_id = await _create_case(client, identity)
    with app.state.session_factory() as db:
        target = User(email="owner@example.test", display_name="Case Owner")
        db.add(target)
        db.flush()
        db.add(
            Membership(
                organization_id=identity["organization_id"],
                user_id=target.id,
                role=MembershipRole.EXAMINER,
            )
        )
        db.commit()
        target_id = target.id

    headers = _headers(identity)
    assigned = await client.post(
        f"/cases/{case_id}/members",
        json={"user_id": str(target_id), "role": "examiner"},
        headers=headers,
    )
    promoted = await client.patch(
        f"/cases/{case_id}/members/{target_id}",
        json={"role": CaseRole.OWNER.value},
        headers=headers,
    )
    removed_original_owner = await client.delete(
        f"/cases/{case_id}/members/{identity['user_id']}",
        headers=headers,
    )
    demoted_last_owner = await client.patch(
        f"/cases/{case_id}/members/{target_id}",
        json={"role": CaseRole.EXAMINER.value},
        headers=headers,
    )
    removed_last_owner = await client.delete(
        f"/cases/{case_id}/members/{target_id}",
        headers=headers,
    )

    assert assigned.status_code == 201
    assert promoted.status_code == 200
    assert removed_original_owner.status_code == 204
    assert demoted_last_owner.status_code == 409
    assert removed_last_owner.status_code == 409


def test_hash_file_read_only_returns_digest_without_changing_source(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    original_content = b"forensic test data"
    source.write_bytes(original_content)

    result = hash_file_read_only(source)

    assert result.sha256 == hashlib.sha256(original_content).hexdigest()
    assert result.size_bytes == len(original_content)
    assert source.read_bytes() == original_content
