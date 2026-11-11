"""Configuration for accreditation-service with its own isolated database."""

from __future__ import annotations

from pydantic import Field

from shared_kernel.config import BaseServiceSettings


class AccreditationSettings(BaseServiceSettings):
    """Accreditation microservice configuration."""

    service_name: str = "accreditation-service"
    database_url: str = Field(default="sqlite+aiosqlite:///./data/accreditation_db.sqlite3")
    default_staff_quota: int = Field(default=6)
    supervisor_max_staff_quota: int = Field(default=10)
    invite_link_ttl_hours: int = Field(default=72)
