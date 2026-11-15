import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from digital_forensics.database import get_db_session
from digital_forensics.models import AuthSession, User

SESSION_COOKIE = "df_session"
CSRF_COOKIE = "df_csrf"


@dataclass(frozen=True)
class AuthenticatedUser:
    user: User
    session: AuthSession


def digest_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_token() -> str:
    return secrets.token_urlsafe(32)


def get_authenticated_user(
    request: Request,
    db: Annotated[Session, Depends(get_db_session)],
) -> AuthenticatedUser:
    raw_token = request.cookies.get(SESSION_COOKIE)
    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    auth_session = db.scalar(
        select(AuthSession).where(
            AuthSession.token_digest == digest_token(raw_token),
            AuthSession.revoked_at.is_(None),
        )
    )
    if auth_session is None or _as_utc(auth_session.expires_at) <= datetime.now(UTC):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    user = db.get(User, auth_session.user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    return AuthenticatedUser(user=user, session=auth_session)


def require_csrf(
    request: Request,
    authenticated: Annotated[AuthenticatedUser, Depends(get_authenticated_user)],
) -> None:
    header_token = request.headers.get("x-csrf-token")
    cookie_token = request.cookies.get(CSRF_COOKIE)
    if not is_valid_csrf_token(
        header_token, cookie_token, authenticated.session.csrf_digest
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Valid CSRF token required",
        )


def is_valid_csrf_token(
    header_token: str | None, cookie_token: str | None, digest: str
) -> bool:
    return bool(
        header_token
        and cookie_token
        and secrets.compare_digest(header_token, cookie_token)
        and secrets.compare_digest(digest_token(header_token), digest)
    )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
