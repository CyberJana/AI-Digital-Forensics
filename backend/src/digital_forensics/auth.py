import logging
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Annotated

from authlib.integrations.base_client.errors import OAuthError
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from digital_forensics.database import get_db_session
from digital_forensics.identity import (
    CSRF_COOKIE,
    SESSION_COOKIE,
    AuthenticatedUser,
    create_token,
    digest_token,
    get_authenticated_user,
    is_valid_csrf_token,
    require_csrf,
)
from digital_forensics.models import AuthSession, ExternalIdentity, Membership, Organization, User
from digital_forensics.settings import Settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["authentication"])
DatabaseSession = Annotated[Session, Depends(get_db_session)]
CurrentUser = Annotated[AuthenticatedUser, Depends(get_authenticated_user)]
CsrfProtected = Annotated[None, Depends(require_csrf)]


def get_app_settings(request: Request) -> Settings:
    return request.app.state.settings


@router.get("/login")
async def login(request: Request) -> RedirectResponse:
    client = request.app.state.oidc_client
    settings: Settings = request.app.state.settings
    if client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC authentication is not configured",
        )
    return await client.authorize_redirect(request, settings.oidc_redirect_uri)


@router.get("/callback")
async def callback(request: Request, db: DatabaseSession) -> RedirectResponse:
    client = request.app.state.oidc_client
    settings: Settings = request.app.state.settings
    if client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC authentication is not configured",
        )

    try:
        token = await client.authorize_access_token(request)
    except OAuthError as error:
        logger.warning("OIDC callback rejected: %s", error.error)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identity provider authentication failed",
        ) from error

    claims = token.get("userinfo")
    if not isinstance(claims, Mapping) or not isinstance(token.get("id_token"), str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identity provider returned no verified identity",
        )

    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject or len(subject) > 255:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identity provider returned an invalid subject",
        )

    email_claim = claims.get("email")
    verified_email = email_claim if claims.get("email_verified") is True else None
    if verified_email is not None and (
        not isinstance(verified_email, str) or len(verified_email) > 320
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identity provider returned an invalid email",
        )
    display_name = claims.get("name")
    if display_name is not None and (
        not isinstance(display_name, str) or len(display_name) > 200
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identity provider returned an invalid name",
        )

    identity = db.scalar(
        select(ExternalIdentity).where(
            ExternalIdentity.issuer == settings.oidc_issuer,
            ExternalIdentity.subject == subject,
        )
    )
    if identity is None:
        user = User(email=verified_email, display_name=display_name)
        db.add(user)
        db.flush()
        identity = ExternalIdentity(
            user_id=user.id,
            issuer=settings.oidc_issuer,
            subject=subject,
            email_verified=verified_email is not None,
        )
        db.add(identity)
    else:
        user = db.get(User, identity.user_id)
        if user is None or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is inactive",
            )
        user.email = verified_email
        if display_name is not None:
            user.display_name = display_name
        identity.email_verified = verified_email is not None

    session_token = create_token()
    csrf_token = create_token()
    auth_session = AuthSession(
        user_id=user.id,
        token_digest=digest_token(session_token),
        csrf_digest=digest_token(csrf_token),
        expires_at=datetime.now(UTC) + timedelta(seconds=settings.session_ttl_seconds),
    )
    db.add(auth_session)
    db.commit()

    response = RedirectResponse(settings.frontend_origin, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        SESSION_COOKIE,
        session_token,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        CSRF_COOKIE,
        csrf_token,
        max_age=settings.session_ttl_seconds,
        httponly=False,
        secure=settings.session_cookie_secure,
        samesite="lax",
        path="/",
    )
    return response


@router.get("/me")
def me(db: DatabaseSession, current: CurrentUser) -> dict[str, object]:
    organizations = db.execute(
        select(Organization, Membership.role)
        .join(Membership, Membership.organization_id == Organization.id)
        .where(Membership.user_id == current.user.id, Organization.is_active.is_(True))
        .order_by(Organization.name)
    ).all()
    return {
        "id": current.user.id,
        "email": current.user.email,
        "display_name": current.user.display_name,
        "organizations": [
            {"id": organization.id, "name": organization.name, "role": role.value}
            for organization, role in organizations
        ],
    }


@router.get("/csrf")
def get_csrf_token(
    request: Request,
    response: Response,
    db: DatabaseSession,
    current: CurrentUser,
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> dict[str, str]:
    csrf_token = request.cookies.get(CSRF_COOKIE)
    if not is_valid_csrf_token(
        csrf_token, csrf_token, current.session.csrf_digest
    ):
        csrf_token = create_token()
        current.session.csrf_digest = digest_token(csrf_token)
        db.commit()
        response.set_cookie(
            CSRF_COOKIE,
            csrf_token,
            max_age=settings.session_ttl_seconds,
            httponly=False,
            secure=settings.session_cookie_secure,
            samesite="lax",
            path="/",
        )
    return {"csrf_token": csrf_token}


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    db: DatabaseSession,
    current: CurrentUser,
    _: CsrfProtected,
) -> Response:
    current.session.revoked_at = datetime.now(UTC)
    db.commit()
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(SESSION_COOKIE, path="/", samesite="lax")
    response.delete_cookie(CSRF_COOKIE, path="/", samesite="lax")
    return response
