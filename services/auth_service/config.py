"""Configuration for auth-service with its own isolated database."""

from __future__ import annotations

from pydantic import Field

from shared_kernel.config import BaseServiceSettings


class AuthSettings(BaseServiceSettings):
    """Auth microservice configuration."""

    service_name: str = "auth-service"
    database_url: str = Field(default="sqlite+aiosqlite:///./data/auth_db.sqlite3")
    access_token_ttl_minutes: int = Field(default=15)
    refresh_token_ttl_minutes: int = Field(default=60 * 24 * 7)
    max_failed_login_attempts: int = Field(default=5)
    lockout_minutes: int = Field(default=15)
