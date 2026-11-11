"""Configuration for registration-service with its own isolated database."""

from __future__ import annotations

from pydantic import Field

from shared_kernel.config import BaseServiceSettings


class RegistrationSettings(BaseServiceSettings):
    """Registration & Ticketing microservice configuration."""

    service_name: str = "registration-service"
    database_url: str = Field(default="sqlite+aiosqlite:///./data/registration_db.sqlite3")
    reservation_ttl_minutes: int = Field(default=10)
