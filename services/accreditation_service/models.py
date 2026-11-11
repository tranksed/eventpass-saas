"""SQLAlchemy models for accreditation_db (isolated from auth_db and registration_db)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from shared_kernel.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class AccreditedCompany(Base):
    """Represented company receiving a private accreditation link with expandable staff quota."""

    __tablename__ = "accredited_companies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    event_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    company_name: Mapped[str] = mapped_column(String(160), nullable=False)
    contact_email_encrypted: Mapped[str] = mapped_column(String(512), nullable=False)
    invite_token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    staff_quota: Mapped[int] = mapped_column(Integer, default=6, nullable=False)
    staff_used: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    link_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_by: Mapped[str] = mapped_column(String(36), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class StaffMember(Base):
    """Staff member registered by an accredited company through its private invite link."""

    __tablename__ = "staff_members"
    __table_args__ = (
        UniqueConstraint("company_id", "dni_blind_index", name="uq_staff_company_dni"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    event_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    company_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("accredited_companies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    dni_blind_index: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    dni_encrypted: Mapped[str] = mapped_column(String(512), nullable=False)
    dni_last4: Mapped[str] = mapped_column(String(8), nullable=False)
    full_name_encrypted: Mapped[str] = mapped_column(String(512), nullable=False)
    role_title: Mapped[str] = mapped_column(String(100), nullable=False)
    credential_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Credential(Base):
    """Ed25519-signed QR credential for both paying participants and accredited company staff."""

    __tablename__ = "credentials"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    event_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    order_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    company_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    holder_type: Mapped[str] = mapped_column(String(20), nullable=False)  # PARTICIPANT | STAFF
    holder_ref_id: Mapped[str] = mapped_column(String(36), nullable=False)
    display_name: Mapped[str] = mapped_column(String(150), nullable=False)
    company_label: Mapped[str | None] = mapped_column(String(160), nullable=True)
    dni_last4: Mapped[str] = mapped_column(String(8), nullable=False)
    entitlements_json: Mapped[str] = mapped_column(Text, nullable=False)
    redeemed_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE", nullable=False, index=True)
    qr_token: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class CheckInLog(Base):
    """Immutable check-in & offline sync log with idempotent client_scan_id."""

    __tablename__ = "checkin_logs"
    __table_args__ = (
        UniqueConstraint("event_id", "client_scan_id", name="uq_checkin_event_client_scan"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    event_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    credential_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    entitlement_code: Mapped[str] = mapped_column(String(40), nullable=False)
    mode: Mapped[str] = mapped_column(String(20), nullable=False)  # ONLINE | OFFLINE_SYNC
    outcome: Mapped[str] = mapped_column(String(40), nullable=False)
    gate_id: Mapped[str] = mapped_column(String(64), nullable=False)
    device_id: Mapped[str] = mapped_column(String(120), nullable=False)
    validator_user_id: Mapped[str] = mapped_column(String(36), nullable=False)
    client_scan_id: Mapped[str] = mapped_column(String(120), nullable=False)
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
