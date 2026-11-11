"""Centralized configuration helpers for microservices.

Each service reads its own DATABASE_URL so databases remain strictly isolated
(Database-per-Service). Local defaults use separate SQLite files under ./data/,
while production overrides use isolated PostgreSQL instances behind PgBouncer.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class BaseServiceSettings(BaseSettings):
    """Common security, cryptographic, and service discovery settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    environment: str = Field(default="development")
    service_name: str = Field(default="eventpass-service")
    data_dir: Path = Field(default=Path("data"))

    # Key paths / secrets (in production injected via KMS / Vault / Secret Manager)
    keys_dir: Path = Field(default=Path("data/keys"))
    pii_master_key_b64: str = Field(
        default="MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        description="32-byte base64 key for AES-256-GCM PII encryption.",
    )
    dni_blind_index_pepper: str = Field(
        default="dev-only-change-in-production-dni-pepper-9f8a7b6c",
        description="Secret pepper for HMAC-SHA256 DNI blind indexing.",
    )
    payment_webhook_secret: str = Field(
        default="dev-only-change-in-production-webhook-hmac-secret",
        description="Shared HMAC-SHA256 secret for verifying payment gateway webhooks.",
    )
    internal_service_token: str = Field(
        default="dev-only-internal-service-mesh-token",
        description="Internal mTLS fallback / service-to-service header token.",
    )

    # Downstream service URLs (empty = in-process/disabled in unit isolation)
    auth_service_url: str = Field(default="http://localhost:8001")
    registration_service_url: str = Field(default="http://localhost:8002")
    accreditation_service_url: str = Field(default="http://localhost:8003")
    audit_service_url: str = Field(default="http://localhost:8004")

    # Rate limit defaults
    rate_limit_requests: int = Field(default=120)
    rate_limit_window_seconds: int = Field(default=60)


@lru_cache
def get_base_settings() -> BaseServiceSettings:
    """Return cached base settings."""
    return BaseServiceSettings()
