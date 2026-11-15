import pytest
from fastapi import FastAPI
from httpx import AsyncClient
from pydantic import SecretStr
from sqlalchemy import select

from digital_forensics.auth import SESSION_COOKIE
from digital_forensics.identity import digest_token
from digital_forensics.models import AuthSession, ExternalIdentity, MembershipRole, User
from digital_forensics.settings import Settings
from digital_forensics.main import create_app

from support import authenticate, create_test_identity, create_test_user


@pytest.mark.anyio
async def test_authentication_is_unavailable_without_oidc_configuration(
    client: AsyncClient,
) -> None:
    response = await client.get("/auth/login")

    assert response.status_code == 503


@pytest.mark.anyio
async def test_me_requires_a_valid_session(client: AsyncClient) -> None:
    response = await client.get("/auth/me")

    assert response.status_code == 401


@pytest.mark.anyio
async def test_expired_session_is_rejected(client: AsyncClient, app: FastAPI) -> None:
    identity = create_test_identity(app, expired=True)
    client.cookies.set(SESSION_COOKIE, str(identity["raw_session_token"]))

    response = await client.get("/auth/me")

    assert response.status_code == 401


@pytest.mark.anyio
async def test_organization_access_is_limited_to_memberships(
    client: AsyncClient, app: FastAPI
) -> None:
    identity = create_test_identity(app)
    authenticate(client, identity)

    organizations = await client.get("/organizations")
    other_org = await client.get(
        f"/organizations/{identity['other_organization_id']}/members"
    )

    assert organizations.status_code == 200
    assert len(organizations.json()) == 1
    assert organizations.json()[0]["id"] == str(identity["organization_id"])
    assert other_org.status_code == 404


@pytest.mark.anyio
async def test_owner_can_add_existing_user_with_csrf_protection(
    client: AsyncClient, app: FastAPI
) -> None:
    identity = create_test_identity(app)
    with app.state.session_factory() as db:
        target_user_id = create_test_user(db)
    authenticate(client, identity)

    response = await client.post(
        f"/organizations/{identity['organization_id']}/members",
        json={"user_id": str(target_user_id), "role": "examiner"},
        headers={"X-CSRF-Token": str(identity["csrf_token"])},
    )

    assert response.status_code == 201
    assert response.json()["user_id"] == str(target_user_id)
    assert response.json()["role"] == "examiner"

    with app.state.session_factory() as db:
        saved_session = db.get(AuthSession, identity["auth_session_id"])
        assert saved_session is not None
        assert saved_session.token_digest == digest_token(str(identity["raw_session_token"]))


@pytest.mark.anyio
async def test_membership_changes_require_valid_csrf_and_privileged_role(
    client: AsyncClient, app: FastAPI
) -> None:
    identity = create_test_identity(app, role=MembershipRole.VIEWER)
    with app.state.session_factory() as db:
        target_user_id = create_test_user(db)
    authenticate(client, identity)
    request_path = f"/organizations/{identity['organization_id']}/members"
    payload = {"user_id": str(target_user_id), "role": "examiner"}

    missing_csrf = await client.post(request_path, json=payload)
    insufficient_role = await client.post(
        request_path,
        json=payload,
        headers={"X-CSRF-Token": str(identity["csrf_token"])},
    )

    assert missing_csrf.status_code == 403
    assert insufficient_role.status_code == 403


@pytest.mark.anyio
async def test_last_organization_owner_cannot_be_removed(
    client: AsyncClient, app: FastAPI
) -> None:
    identity = create_test_identity(app)
    authenticate(client, identity)

    response = await client.delete(
        f"/organizations/{identity['organization_id']}/members/{identity['user_id']}",
        headers={"X-CSRF-Token": str(identity["csrf_token"])},
    )

    assert response.status_code == 409


@pytest.mark.anyio
async def test_owner_can_transfer_ownership_before_leaving(
    client: AsyncClient, app: FastAPI
) -> None:
    identity = create_test_identity(app)
    with app.state.session_factory() as db:
        target_user_id = create_test_user(db)
    authenticate(client, identity)
    organization_path = f"/organizations/{identity['organization_id']}"
    headers = {"X-CSRF-Token": str(identity["csrf_token"])}

    added = await client.post(
        f"{organization_path}/members",
        json={"user_id": str(target_user_id), "role": "examiner"},
        headers=headers,
    )
    promoted = await client.patch(
        f"{organization_path}/members/{target_user_id}",
        json={"role": "owner"},
        headers=headers,
    )
    removed = await client.delete(
        f"{organization_path}/members/{identity['user_id']}",
        headers=headers,
    )

    assert added.status_code == 201
    assert promoted.status_code == 200
    assert promoted.json()["role"] == "owner"
    assert removed.status_code == 204


@pytest.mark.anyio
async def test_oidc_callback_provisions_identity_and_opaque_session(
    client: AsyncClient, app: FastAPI
) -> None:
    class TestOidcClient:
        async def authorize_access_token(self, request: object) -> dict[str, object]:
            return {
                "id_token": "validated-by-test-provider",
                "userinfo": {
                    "sub": "provider-user-123",
                    "email": "verified@example.test",
                    "email_verified": True,
                    "name": "Verified User",
                },
            }

    app.state.settings.oidc_issuer = "https://issuer.example.test"
    app.state.oidc_client = TestOidcClient()

    response = await client.get("/auth/callback")

    assert response.status_code == 303
    raw_session_token = client.cookies.get(SESSION_COOKIE)
    assert raw_session_token
    with app.state.session_factory() as db:
        identity = db.scalar(
            select(ExternalIdentity).where(
                ExternalIdentity.issuer == "https://issuer.example.test",
                ExternalIdentity.subject == "provider-user-123",
            )
        )
        assert identity is not None
        user = db.get(User, identity.user_id)
        assert user is not None
        assert user.email == "verified@example.test"
        auth_session = db.scalar(
            select(AuthSession).where(AuthSession.user_id == user.id)
        )
        assert auth_session is not None
        assert auth_session.token_digest == digest_token(raw_session_token)
        assert auth_session.token_digest != raw_session_token


@pytest.mark.anyio
async def test_oidc_callback_rejects_missing_subject(client: AsyncClient, app: FastAPI) -> None:
    class TestOidcClient:
        async def authorize_access_token(self, request: object) -> dict[str, object]:
            return {
                "id_token": "validated-by-test-provider",
                "userinfo": {"email": "missing-subject@example.test"},
            }

    app.state.settings.oidc_issuer = "https://issuer.example.test"
    app.state.oidc_client = TestOidcClient()

    response = await client.get("/auth/callback")

    assert response.status_code == 401


@pytest.mark.anyio
async def test_logout_revokes_session_and_clears_cookies(
    client: AsyncClient, app: FastAPI
) -> None:
    identity = create_test_identity(app)
    authenticate(client, identity)

    response = await client.post(
        "/auth/logout",
        headers={"X-CSRF-Token": str(identity["csrf_token"])},
    )
    after_logout = await client.get("/auth/me")

    assert response.status_code == 204
    assert after_logout.status_code == 401


def test_complete_oidc_configuration_registers_provider_client() -> None:
    settings = Settings(
        database_url=SecretStr("sqlite://"),
        oidc_issuer="https://issuer.example.test",
        oidc_client_id="client-id",
        oidc_client_secret=SecretStr("client-secret"),
        oidc_redirect_uri="https://api.example.test/auth/callback",
        session_signing_key=SecretStr("test-signing-key-with-at-least-32-bytes"),
        frontend_origin="https://app.example.test",
    )
    application = create_app(settings)

    try:
        assert application.state.oidc_client is not None
    finally:
        application.state.engine.dispose()
