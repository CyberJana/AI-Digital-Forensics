from functools import lru_cache
from typing import Literal
from urllib.parse import urlsplit

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AI Digital Forensics API"
    environment: Literal["development", "staging", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    database_url: SecretStr | None = None
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: SecretStr | None = None
    oidc_redirect_uri: str | None = None
    session_signing_key: SecretStr | None = None
    session_cookie_secure: bool = True
    session_ttl_seconds: int = 28_800
    frontend_origin: str = "http://localhost:3000"

    model_config = SettingsConfigDict(
        env_prefix="DIGITAL_FORENSICS_",
        env_file=".env",
        env_ignore_empty=True,
        extra="ignore",
    )

    @model_validator(mode="after")
    def validate_session_settings(self) -> "Settings":
        if self.environment != "development" and not self.oidc_enabled:
            raise ValueError("Staging and production require database and OIDC configuration")
        if self.environment != "development" and not self.session_cookie_secure:
            raise ValueError("Session cookies must use HTTPS outside development")
        if (
            self.environment != "development"
            and self.database_url is not None
            and self.database_url.get_secret_value().startswith("sqlite")
        ):
            raise ValueError("SQLite is only supported for development and tests")
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


@lru_cache
def get_settings() -> Settings:
    return Settings()
