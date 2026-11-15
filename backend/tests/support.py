from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import FastAPI
from httpx import AsyncClient
from sqlalchemy.orm import Session

from digital_forensics.auth import CSRF_COOKIE, SESSION_COOKIE
from digital_forensics.identity import digest_token
from digital_forensics.models import AuthSession, Membership, MembershipRole, Organization, User


def create_test_identity(
    app: FastAPI,
    *,
    role: MembershipRole = MembershipRole.OWNER,
    expired: bool = False,
) -> dict[str, object]:
    raw_session_token = "test-session-token"
    csrf_token = "test-csrf-token"
    with app.state.session_factory() as db:
        user = User(email="examiner@example.test", display_name="Test Examiner")
        organization = Organization(name="Test Organization", slug="test-organization")
        other_organization = Organization(name="Other Organization", slug="other-organization")
        db.add_all([user, organization, other_organization])
        db.flush()
        db.add(
            Membership(
                organization_id=organization.id,
                user_id=user.id,
                role=role,
            )
        )
        auth_session = AuthSession(
            user_id=user.id,
            token_digest=digest_token(raw_session_token),
            csrf_digest=digest_token(csrf_token),
            expires_at=datetime.now(UTC) - timedelta(minutes=1)
            if expired
            else datetime.now(UTC) + timedelta(hours=1),
        )
        db.add(auth_session)
        db.commit()
        return {
            "user_id": user.id,
            "organization_id": organization.id,
            "other_organization_id": other_organization.id,
            "raw_session_token": raw_session_token,
            "csrf_token": csrf_token,
            "auth_session_id": auth_session.id,
        }


def create_test_user(db: Session) -> UUID:
    user = User(email="new-user@example.test", display_name="New User")
    db.add(user)
    db.commit()
    return user.id


def authenticate(client: AsyncClient, identity: dict[str, object]) -> None:
    client.cookies.set(SESSION_COOKIE, str(identity["raw_session_token"]))
    client.cookies.set(CSRF_COOKIE, str(identity["csrf_token"]))
