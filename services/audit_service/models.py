"""SQLAlchemy models for hash-chained append-only audit_db."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from shared_kernel.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class AuditEntry(Base):
    """Tamper-evident hash-chained audit record."""

    __tablename__ = "audit_entries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    seq: Mapped[int] = mapped_column(Integer, unique=True, nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    service: Mapped[str] = mapped_column(String(60), nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_role: Mapped[str] = mapped_column(String(30), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(64), nullable=False)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
