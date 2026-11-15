import json
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from httpx import AsyncClient
from pydantic import SecretStr, ValidationError
from urllib.request import ProxyHandler

from digital_forensics.ai_summaries import (
    SummaryDraft,
    _NoRedirectHandler,
    _call_ollama,
)
from digital_forensics.settings import Settings

from support import authenticate, create_test_identity


async def _create_case_with_evidence(
    client: AsyncClient,
    app: FastAPI,
) -> tuple[dict[str, object], str]:
    identity = create_test_identity(app)
    authenticate(client, identity)
    headers = {"X-CSRF-Token": str(identity["csrf_token"])}
    case_response = await client.post(
        f"/organizations/{identity['organization_id']}/cases",
        json={"case_number": "AI-001", "name": "AI summary case"},
        headers=headers,
    )
    assert case_response.status_code == 201
    case_id = case_response.json()["id"]
    evidence_response = await client.post(
        f"/cases/{case_id}/evidence",
        json={
            "evidence_number": "AI-E1",
            "name": "Synthetic evidence",
            "size_bytes": 4,
            "original_sha256": "a" * 64,
            "acquisition_method": "write blocker",
            "source_description": "Synthetic test fixture",
            "acquired_at": datetime.now(UTC).isoformat(),
        },
        headers=headers,
    )
    assert evidence_response.status_code == 201
    return identity, case_id


@pytest.mark.anyio
async def test_case_summary_is_saved_unreviewed_with_sources_and_provenance(
    client: AsyncClient,
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity, case_id = await _create_case_with_evidence(client, app)
    app.state.settings.ollama_model = "test-model"
    timeline = await client.get(f"/cases/{case_id}/timeline")
    source_id = UUID(timeline.json()["events"][0]["source_record_id"])
    draft = SummaryDraft(
        summary="The case contains one registered evidence item.",
        source_record_ids=[source_id],
        key_points=[
            {
                "text": "The evidence was acquired using a write blocker.",
                "source_record_ids": [source_id],
            }
        ],
    )
    monkeypatch.setattr(
        "digital_forensics.ai_summaries._call_ollama",
        lambda _settings, _snapshot: (draft, "test-model"),
    )

    created = await client.post(
        f"/cases/{case_id}/ai-summaries",
        headers={"X-CSRF-Token": str(identity["csrf_token"])},
    )

    assert created.status_code == 201
    result = created.json()
    assert result["review_status"] == "unreviewed"
    assert result["provider"] == "ollama"
    assert result["model_name"] == "test-model"
    assert result["prompt_version"] == "case-summary-v1"
    assert result["summary"] == draft.summary
    assert result["summary_source_record_ids"] == [str(source_id)]
    assert result["source_snapshot"]["case"]["case_number"] == "AI-001"

    listed = await client.get(f"/cases/{case_id}/ai-summaries")
    detail = await client.get(f"/ai-summaries/{result['id']}")
    assert listed.status_code == 200
    assert listed.json()[0]["id"] == result["id"]
    assert "source_snapshot" not in listed.json()[0]
    assert detail.status_code == 200
    assert detail.json()["source_snapshot"] == result["source_snapshot"]


@pytest.mark.anyio
async def test_unconfigured_ai_returns_service_unavailable_without_calling_provider(
    client: AsyncClient,
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity, case_id = await _create_case_with_evidence(client, app)

    def unexpected_call(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Unconfigured Ollama must not be called")

    monkeypatch.setattr("digital_forensics.ai_summaries._call_ollama", unexpected_call)
    response = await client.post(
        f"/cases/{case_id}/ai-summaries",
        headers={"X-CSRF-Token": str(identity["csrf_token"])},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "local_ai_not_configured"


@pytest.mark.anyio
async def test_summary_rejects_citations_outside_the_case_sources(
    client: AsyncClient,
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity, case_id = await _create_case_with_evidence(client, app)
    app.state.settings.ollama_model = "test-model"
    invalid_source_id = uuid4()
    draft = SummaryDraft(
        summary="Unsupported statement.",
        source_record_ids=[invalid_source_id],
        key_points=[
            {
                "text": "Unsupported point.",
                "source_record_ids": [invalid_source_id],
            }
        ],
    )
    monkeypatch.setattr(
        "digital_forensics.ai_summaries._call_ollama",
        lambda _settings, _snapshot: (draft, "test-model"),
    )

    response = await client.post(
        f"/cases/{case_id}/ai-summaries",
        headers={"X-CSRF-Token": str(identity["csrf_token"])},
    )

    assert response.status_code == 502
    assert response.json()["detail"] == "local_ai_citations_invalid"
    assert (await client.get(f"/cases/{case_id}/ai-summaries")).json() == []


def test_ollama_call_is_json_and_uses_only_configured_loopback_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_id = uuid4()
    source_snapshot = {
        "case": {"source_record_id": str(source_id)},
        "events": [],
        "custody_verification": [],
    }
    output = {
        "summary": "The case is open.",
        "source_record_ids": [str(source_id)],
        "key_points": [],
    }
    provider_body = {
        "model": "test-model",
        "message": {"content": json.dumps(output)},
    }
    calls: list[tuple[str, dict[str, object], int]] = []

    class FakeResponse:
        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return json.dumps(provider_body).encode("utf-8")

    class FakeOpener:
        def open(self, request: object, *, timeout: int) -> FakeResponse:
            calls.append(
                (
                    request.full_url,
                    json.loads(request.data),
                    timeout,
                )
            )
            return FakeResponse()

    def fake_build_opener(*handlers: object) -> FakeOpener:
        assert any(isinstance(handler, ProxyHandler) for handler in handlers)
        assert any(isinstance(handler, _NoRedirectHandler) for handler in handlers)
        return FakeOpener()

    monkeypatch.setattr("digital_forensics.ai_summaries.build_opener", fake_build_opener)
    settings = Settings(
        ollama_model="test-model",
        ollama_timeout_seconds=45,
        database_url=SecretStr("sqlite://"),
    )

    draft, model_name = _call_ollama(settings, source_snapshot)

    assert model_name == "test-model"
    assert draft.summary == output["summary"]
    assert calls[0][0] == "http://127.0.0.1:11434/api/chat"
    assert calls[0][1]["format"] == "json"
    assert calls[0][1]["stream"] is False
    assert calls[0][2] == 45


def test_settings_reject_non_loopback_ollama_endpoints() -> None:
    with pytest.raises(ValidationError, match="loopback"):
        Settings(ollama_base_url="http://example.com:11434")
