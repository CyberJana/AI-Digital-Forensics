from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from httpx import AsyncClient

from digital_forensics.identity import digest_token
from digital_forensics.models import (
    AuthSession,
    CaseRole,
    Membership,
    MembershipRole,
    User,
)

from support import authenticate, create_test_identity


def _headers(identity: dict[str, object]) -> dict[str, str]:
    return {"X-CSRF-Token": str(identity["csrf_token"])}


async def _create_case(client: AsyncClient, identity: dict[str, object]) -> str:
    response = await client.post(
        f"/organizations/{identity['organization_id']}/cases",
        json={"case_number": "REPORT-001", "name": "Reporting case"},
        headers=_headers(identity),
    )
    assert response.status_code == 201
    return response.json()["id"]


@pytest.mark.anyio
async def test_findings_reports_reviews_and_audit_are_case_scoped_and_immutable(
    client: AsyncClient,
    app: FastAPI,
) -> None:
    owner = create_test_identity(app)
    authenticate(client, owner)
    case_id = await _create_case(client, owner)

    created = await client.post(
        f"/cases/{case_id}/findings",
        json={
            "title": "Metadata supports acquisition time",
            "narrative": "The stored acquisition record identifies the acquisition time.",
            "source_record_ids": [case_id],
        },
        headers=_headers(owner),
    )
    assert created.status_code == 201
    finding = created.json()
    assert finding["review_status"] == "unreviewed"
    assert finding["source_snapshot"]["sources"][0]["source_type"] == "case"

    report_response = await client.post(
        f"/cases/{case_id}/reports",
        json={"title": "Initial report", "finding_ids": [finding["id"]]},
        headers=_headers(owner),
    )
    assert report_response.status_code == 201
    report = report_response.json()
    assert report["review_status"] == "unreviewed"
    assert "Metadata supports acquisition time" in report["body"]

    self_review = await client.post(
        f"/cases/{case_id}/findings/{finding['id']}/reviews",
        json={"decision": "approved"},
        headers=_headers(owner),
    )
    assert self_review.status_code == 409

    reviewer_token = "report-reviewer-session"
    reviewer_csrf = "report-reviewer-csrf"
    with app.state.session_factory() as db:
        reviewer = User(email="reviewer@example.test", display_name="Case Reviewer")
        db.add(reviewer)
        db.flush()
        db.add_all(
            [
                Membership(
                    organization_id=UUID(str(owner["organization_id"])),
                    user_id=reviewer.id,
                    role=MembershipRole.REVIEWER,
                ),
                AuthSession(
                    user_id=reviewer.id,
                    token_digest=digest_token(reviewer_token),
                    csrf_digest=digest_token(reviewer_csrf),
                    expires_at=datetime.now(UTC) + timedelta(hours=1),
                ),
            ]
        )
        db.commit()
        reviewer_id = reviewer.id

    assigned = await client.post(
        f"/cases/{case_id}/members",
        json={"user_id": str(reviewer_id), "role": CaseRole.REVIEWER.value},
        headers=_headers(owner),
    )
    assert assigned.status_code == 201
    authenticate(
        client,
        {"raw_session_token": reviewer_token, "csrf_token": reviewer_csrf},
    )

    finding_review = await client.post(
        f"/cases/{case_id}/findings/{finding['id']}/reviews",
        json={"decision": "approved", "notes": "Sources checked."},
        headers={"X-CSRF-Token": reviewer_csrf},
    )
    report_review = await client.post(
        f"/cases/{case_id}/reports/{report['id']}/reviews",
        json={"decision": "rejected", "notes": "Needs additional context."},
        headers={"X-CSRF-Token": reviewer_csrf},
    )
    assert finding_review.status_code == 201
    assert report_review.status_code == 201

    findings = await client.get(f"/cases/{case_id}/findings")
    reports = await client.get(f"/cases/{case_id}/reports")
    audits = await client.get(f"/cases/{case_id}/audit-log")
    search = await client.get(f"/cases/{case_id}/search", params={"q": "acquisition"})
    assert findings.json()[0]["review_status"] == "approved"
    assert findings.json()[0]["review_history"][0]["decision"] == "approved"
    assert reports.json()[0]["review_status"] == "rejected"
    assert reports.json()[0]["review_history"][0]["decision"] == "rejected"
    assert {event["action"] for event in audits.json()} >= {
        "finding.created",
        "finding.approved",
        "report.created",
        "report.rejected",
    }
    assert any(hit["source_record_id"] == finding["id"] for hit in search.json())


@pytest.mark.anyio
async def test_finding_rejects_sources_outside_the_case(
    client: AsyncClient,
    app: FastAPI,
) -> None:
    owner = create_test_identity(app)
    authenticate(client, owner)
    case_id = await _create_case(client, owner)
    response = await client.post(
        f"/cases/{case_id}/findings",
        json={
            "title": "Invalid source",
            "narrative": "This citation does not belong to the case.",
            "source_record_ids": [str(uuid4())],
        },
        headers=_headers(owner),
    )
    assert response.status_code == 422


@pytest.mark.anyio
async def test_reporting_endpoints_hide_cases_from_unassigned_users(
    client: AsyncClient,
    app: FastAPI,
) -> None:
    owner = create_test_identity(app)
    authenticate(client, owner)
    case_id = await _create_case(client, owner)
    outsider_token = "report-outsider-session"
    outsider_csrf = "report-outsider-csrf"
    with app.state.session_factory() as db:
        outsider = User(email="outsider@example.test", display_name="Unassigned User")
        db.add(outsider)
        db.flush()
        db.add(
            AuthSession(
                user_id=outsider.id,
                token_digest=digest_token(outsider_token),
                csrf_digest=digest_token(outsider_csrf),
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        )
        db.commit()
    authenticate(
        client,
        {"raw_session_token": outsider_token, "csrf_token": outsider_csrf},
    )

    responses = [
        await client.get(f"/cases/{case_id}/search", params={"q": "report"}),
        await client.get(f"/cases/{case_id}/findings"),
        await client.get(f"/cases/{case_id}/reports"),
        await client.get(f"/cases/{case_id}/audit-log"),
    ]
    assert [response.status_code for response in responses] == [404, 404, 404, 404]
