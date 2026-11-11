"""Configuration for audit-service with its own isolated database."""

from __future__ import annotations

from pydantic import Field

from shared_kernel.config import BaseServiceSettings


class AuditSettings(BaseServiceSettings):
    """Audit microservice configuration."""

    service_name: str = "audit-service"
    database_url: str = Field(default="sqlite+aiosqlite:///./data/audit_db.sqlite3")
