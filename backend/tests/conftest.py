from collections.abc import AsyncIterator, Iterator

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

from digital_forensics.main import create_app
from digital_forensics.models import Base
from digital_forensics.settings import Settings
from support import create_test_identity


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def app() -> Iterator[FastAPI]:
    settings = Settings(
        database_url=SecretStr("sqlite://"),
        session_signing_key=SecretStr("test-signing-key-with-at-least-32-bytes"),
        session_cookie_secure=False,
    )
    application = create_app(settings)
    Base.metadata.create_all(application.state.engine)
    yield application
    application.state.engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as test_client:
        yield test_client
