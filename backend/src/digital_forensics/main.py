import logging
from contextlib import asynccontextmanager
from threading import BoundedSemaphore
from typing import AsyncIterator

from authlib.integrations.starlette_client import OAuth
from fastapi import FastAPI, HTTPException, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from digital_forensics.ai_summaries import router as ai_summaries_router
from digital_forensics.auth import router as auth_router
from digital_forensics.cases import router as cases_router
from digital_forensics.database import create_database_engine, create_session_factory
from digital_forensics.evidence import router as evidence_router
from digital_forensics.jobs import router as processing_router
from digital_forensics.organizations import router as organizations_router
from digital_forensics.reporting import router as reporting_router
from digital_forensics.settings import Settings, get_settings
from digital_forensics.storage import EvidenceObjectStore
from digital_forensics.timeline import router as timeline_router


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    settings: Settings = application.state.settings
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    try:
        yield
    finally:
        evidence_storage = application.state.evidence_storage
        if evidence_storage is not None:
            evidence_storage.close()
        engine = application.state.engine
        if engine is not None:
            engine.dispose()


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    application = FastAPI(title=settings.app_name, lifespan=lifespan)
    application.state.settings = settings
    application.state.engine = None
    application.state.session_factory = None
    application.state.oidc_client = None
    application.state.evidence_storage = (
        EvidenceObjectStore(settings) if settings.evidence_storage_enabled else None
    )
    application.state.evidence_upload_gate = BoundedSemaphore(1)

    if settings.database_url is not None:
        engine = create_database_engine(settings.database_url.get_secret_value())
        application.state.engine = engine
        application.state.session_factory = create_session_factory(engine)

    if settings.session_signing_key is not None:
        application.add_middleware(
            SessionMiddleware,
            secret_key=settings.session_signing_key.get_secret_value(),
            same_site="lax",
            https_only=settings.session_cookie_secure,
            max_age=600,
        )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.frontend_origin],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "X-CSRF-Token"],
    )

    application.state.oidc_client = create_oidc_client(settings)

    application.include_router(auth_router)
    application.include_router(organizations_router)
    application.include_router(cases_router)
    application.include_router(evidence_router)
    application.include_router(processing_router)
    application.include_router(timeline_router)
    application.include_router(ai_summaries_router)
    application.include_router(reporting_router)

    @application.get("/health", tags=["health"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/health/ready", tags=["health"])
    def readiness() -> dict[str, str]:
        engine = application.state.engine
        if engine is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="database_not_configured",
            )
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except SQLAlchemyError as error:
            logging.getLogger(__name__).error(
                "Readiness check failed: database unavailable (%s)",
                type(error).__name__,
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="database_unavailable",
            ) from error
        return {"status": "ready"}

    return application


def create_oidc_client(settings: Settings) -> object | None:
    if not settings.oidc_enabled:
        return None
    if (
        settings.oidc_issuer is None
        or settings.oidc_client_id is None
        or settings.oidc_client_secret is None
    ):
        raise RuntimeError("OIDC configuration is incomplete")

    oauth = OAuth()
    oauth.register(
        name="identity_provider",
        client_id=settings.oidc_client_id,
        client_secret=settings.oidc_client_secret.get_secret_value(),
        server_metadata_url=(
            f"{settings.oidc_issuer.rstrip('/')}/.well-known/openid-configuration"
        ),
        client_kwargs={"scope": "openid email profile"},
    )
    return oauth.create_client("identity_provider")


app = create_app()
