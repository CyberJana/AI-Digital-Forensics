import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

from digital_forensics.main import create_app
from digital_forensics.settings import Settings


@pytest.mark.anyio
async def test_health_endpoint_returns_ok() -> None:
    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.anyio
async def test_readiness_requires_a_reachable_database() -> None:
    application = create_app(Settings(database_url=SecretStr("sqlite://")))
    try:
        transport = ASGITransport(app=application)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get("/health/ready")
        assert response.status_code == 200
        assert response.json() == {"status": "ready"}
    finally:
        application.state.engine.dispose()

    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/health/ready")
    assert response.status_code == 503
