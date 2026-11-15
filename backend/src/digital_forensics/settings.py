import ipaddress
import re
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AI Digital Forensics API"
    environment: Literal["development", "staging", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    database_url: SecretStr | None = None
    working_copy_root: Path | None = None
    exiftool_executable: str = "exiftool"
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str | None = None
    ollama_timeout_seconds: int = 120
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: SecretStr | None = None
    oidc_redirect_uri: str | None = None
    session_signing_key: SecretStr | None = None
    evidence_s3_bucket: str | None = None
    evidence_s3_region: str = "us-east-1"
    evidence_s3_endpoint_url: str | None = None
    evidence_s3_access_key_id: SecretStr | None = None
    evidence_s3_secret_access_key: SecretStr | None = None
    vault_addr: str | None = None
    vault_token: SecretStr | None = None
    vault_token_file: Path | None = None
    vault_namespace: str | None = None
    vault_transit_key: str | None = None
    session_cookie_secure: bool = True
    session_ttl_seconds: int = 28_800
    frontend_origin: str = "http://localhost:3000"

    model_config = SettingsConfigDict(
        env_prefix="DIGITAL_FORENSICS_",
        env_file=".env",
        env_ignore_empty=True,
        extra="ignore",
    )

    @field_validator("ollama_base_url")
    @classmethod
    def validate_ollama_base_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        try:
            address = ipaddress.ip_address(parsed.hostname or "")
            parsed.port
        except ValueError as error:
            raise ValueError("Ollama must use a loopback IP address") from error
        if (
            parsed.scheme not in {"http", "https"}
            or not address.is_loopback
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Ollama must use a loopback HTTP(S) URL without a path")
        return value.rstrip("/")

    @field_validator("ollama_model")
    @classmethod
    def validate_ollama_model(cls, value: str | None) -> str | None:
        if value is not None and (not value.strip() or len(value) > 200):
            raise ValueError("Ollama model must be non-empty and at most 200 characters")
        return value.strip() if value is not None else None

    @field_validator("ollama_timeout_seconds")
    @classmethod
    def validate_ollama_timeout(cls, value: int) -> int:
        if not 1 <= value <= 600:
            raise ValueError("Ollama timeout must be between 1 and 600 seconds")
        return value

    @field_validator(
        "evidence_s3_access_key_id",
        "evidence_s3_secret_access_key",
        "vault_token",
    )
    @classmethod
    def validate_storage_secret(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and not value.get_secret_value().strip():
            raise ValueError("Storage credentials cannot be empty")
        return value

    @model_validator(mode="after")
    def validate_session_settings(self) -> "Settings":
        if self.environment != "development" and not self.oidc_enabled:
            raise ValueError("Staging and production require database and OIDC configuration")
        if self.environment != "development" and not self.session_cookie_secure:
            raise ValueError("Session cookies must use HTTPS outside development")
        storage_fields = (
            self.evidence_s3_bucket,
            self.evidence_s3_endpoint_url,
            self.evidence_s3_access_key_id,
            self.evidence_s3_secret_access_key,
            self.vault_addr,
            self.vault_token,
            self.vault_token_file,
            self.vault_namespace,
            self.vault_transit_key,
        )
        if any(value is not None for value in storage_fields) and not self.evidence_storage_enabled:
            raise ValueError("Evidence storage requires S3 and Vault Transit configuration")
        if self.environment != "development":
            if not self.evidence_storage_enabled:
                raise ValueError("Staging and production require encrypted evidence storage")
            if self.vault_token_file is None:
                raise ValueError("Staging and production require a Vault Agent token file")
        if bool(self.evidence_s3_access_key_id) != bool(self.evidence_s3_secret_access_key):
            raise ValueError("S3 access key ID and secret access key must be configured together")
        if self.vault_token is not None and self.vault_token_file is not None:
            raise ValueError("Configure either a Vault token or token file, not both")
        if self.evidence_s3_endpoint_url is not None:
            endpoint = urlsplit(self.evidence_s3_endpoint_url)
            if (
                endpoint.scheme not in {"http", "https"}
                or not endpoint.netloc
                or endpoint.username is not None
                or endpoint.password is not None
                or endpoint.path
                or endpoint.query
                or endpoint.fragment
            ):
                raise ValueError("S3 endpoint must be an HTTP(S) origin")
            if self.environment != "development" and endpoint.scheme != "https":
                raise ValueError("S3 endpoint must use HTTPS outside development")
        if self.vault_addr is not None:
            vault = urlsplit(self.vault_addr)
            if (
                vault.scheme not in {"http", "https"}
                or not vault.netloc
                or vault.username is not None
                or vault.password is not None
                or vault.path
                or vault.query
                or vault.fragment
            ):
                raise ValueError("Vault address must be an HTTP(S) origin")
            if self.environment != "development" and vault.scheme != "https":
                raise ValueError("Vault address must use HTTPS outside development")
        if self.vault_transit_key is not None and not re.fullmatch(
            r"[A-Za-z0-9._-]{1,128}", self.vault_transit_key
        ):
            raise ValueError("Vault Transit key name contains unsupported characters")
        if self.vault_namespace is not None and any(
            character in self.vault_namespace for character in "\r\n"
        ):
            raise ValueError("Vault namespace contains unsupported characters")
        if (
            self.environment != "development"
            and self.database_url is not None
            and not self.database_url.get_secret_value().startswith("postgresql+psycopg://")
        ):
            raise ValueError("Staging and production require PostgreSQL")
        for label, value in (
            ("OIDC issuer", self.oidc_issuer),
            ("OIDC redirect URI", self.oidc_redirect_uri),
        ):
            if value is not None:
                parsed = urlsplit(value)
                if (
                    parsed.scheme not in {"http", "https"}
                    or not parsed.netloc
                    or parsed.query
                    or parsed.fragment
                ):
                    raise ValueError(f"{label} must be a valid HTTP(S) URL")
                if self.environment != "development" and parsed.scheme != "https":
                    raise ValueError(f"{label} must use HTTPS outside development")
        origin = urlsplit(self.frontend_origin)
        if (
            origin.scheme not in {"http", "https"}
            or not origin.netloc
            or origin.path
            or origin.query
            or origin.fragment
        ):
            raise ValueError("Frontend origin must be a valid origin without path or query")
        if self.environment != "development" and origin.scheme != "https":
            raise ValueError("Frontend origin must use HTTPS outside development")
        if (
            self.session_signing_key is not None
            and len(self.session_signing_key.get_secret_value()) < 32
        ):
            raise ValueError("Session signing key must contain at least 32 characters")
        if not 60 <= self.session_ttl_seconds <= 604_800:
            raise ValueError("Session TTL must be between 60 seconds and 7 days")
        return self

    @property
    def oidc_enabled(self) -> bool:
        return bool(
            self.oidc_issuer
            and self.oidc_client_id
            and self.oidc_client_secret
            and self.oidc_client_secret.get_secret_value()
            and self.oidc_redirect_uri
            and self.session_signing_key
            and self.session_signing_key.get_secret_value()
            and self.database_url
            and self.database_url.get_secret_value()
        )

    @property
    def evidence_storage_enabled(self) -> bool:
        return bool(
            self.evidence_s3_bucket
            and self.vault_addr
            and (self.vault_token or self.vault_token_file)
            and self.vault_transit_key
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
