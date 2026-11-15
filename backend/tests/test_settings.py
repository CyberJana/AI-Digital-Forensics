from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from digital_forensics.settings import Settings


def _production_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "environment": "staging",
        "database_url": SecretStr("postgresql+psycopg://user:pass@db/forensics"),
        "oidc_issuer": "https://identity.example.test",
        "oidc_client_id": "forensics-client",
        "oidc_client_secret": SecretStr("test-client-secret"),
        "oidc_redirect_uri": "https://forensics.example.test/auth/callback",
        "session_signing_key": SecretStr("s" * 48),
        "session_cookie_secure": True,
        "frontend_origin": "https://forensics.example.test",
        "evidence_s3_bucket": "forensics-evidence",
        "vault_addr": "https://vault.example.test",
        "vault_token_file": Path("/run/secrets/vault-token"),
        "vault_transit_key": "evidence",
    }
    values.update(overrides)
    return Settings(**values)


def test_staging_configuration_requires_secure_origins_and_cookie() -> None:
    with pytest.raises(ValidationError, match="Frontend origin must use HTTPS"):
        _production_settings(frontend_origin="http://forensics.example.test")

    with pytest.raises(ValidationError, match="Session cookies must use HTTPS"):
        _production_settings(session_cookie_secure=False)


def test_staging_configuration_requires_oidc_and_postgresql() -> None:
    with pytest.raises(ValidationError, match="require database and OIDC"):
        Settings(environment="production")

    with pytest.raises(ValidationError, match="require PostgreSQL"):
        _production_settings(database_url=SecretStr("sqlite:///forensics.db"))


def test_staging_requires_encrypted_storage_and_vault_agent_auth() -> None:
    with pytest.raises(ValidationError, match="require encrypted evidence storage"):
        _production_settings(
            evidence_s3_bucket=None,
            vault_addr=None,
            vault_token_file=None,
            vault_transit_key=None,
        )

    with pytest.raises(ValidationError, match="Vault Agent token file"):
        _production_settings(
            vault_token_file=None,
            vault_token=SecretStr("static-token"),
        )


def test_storage_configuration_requires_vault_and_paired_s3_credentials() -> None:
    with pytest.raises(ValidationError, match="requires S3 and Vault Transit"):
        Settings(evidence_s3_bucket="evidence")

    with pytest.raises(ValidationError, match="configured together"):
        Settings(
            evidence_s3_bucket="evidence",
            evidence_s3_access_key_id=SecretStr("access"),
            vault_addr="http://127.0.0.1:8200",
            vault_token=SecretStr("token"),
            vault_transit_key="evidence",
        )
