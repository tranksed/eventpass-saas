"""SQLAlchemy models for registration_db (strictly isolated from auth_db and accreditation_db)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    CheckConstraint,
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


class Event(Base):
    """Tenant-owned event with configurable DNI purchase limit (1..10)."""

    __tablename__ = "events"
    __table_args__ = (
        UniqueConstraint("tenant_id", "slug", name="uq_events_tenant_slug"),
        CheckConstraint(
            "max_purchases_per_dni >= 1 AND max_purchases_per_dni <= 10",
            name="ck_event_max_dni_range",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False)
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    max_purchases_per_dni: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class CatalogItem(Base):
    """Purchasable ticket or interaction (ENTRY, PHOTO, SIGNATURE, MERCH, etc.)."""

    __tablename__ = "catalog_items"
    __table_args__ = (UniqueConstraint("event_id", "code", name="uq_catalog_event_code"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    event_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("events.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    code: Mapped[str] = mapped_column(String(40), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    item_type: Mapped[str] = mapped_column(String(30), nullable=False)  # ENTRY | INTERACTION
    price_cents: Mapped[int] = mapped_column(Integer, nullable=False)
    stock_total: Mapped[int] = mapped_column(Integer, nullable=False)
    stock_reserved: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    stock_sold: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Participant(Base):
    """Registered buyer/participant with AES-256-GCM encrypted PII and blind-indexed DNI."""

    __tablename__ = "participants"
    __table_args__ = (
        UniqueConstraint("event_id", "dni_blind_index", name="uq_participant_event_dni"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    event_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("events.id", ondelete="CASCADE"), nullable=False, index=True
    )
    dni_blind_index: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    dni_encrypted: Mapped[str] = mapped_column(String(512), nullable=False)
    dni_last4: Mapped[str] = mapped_column(String(8), nullable=False)
    full_name_encrypted: Mapped[str] = mapped_column(String(512), nullable=False)
    email_encrypted: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Order(Base):
    """Idempotent purchase order linking participant DNI to payment gateway & issued QR."""

    __tablename__ = "orders"
    __table_args__ = (
        UniqueConstraint("event_id", "idempotency_key", name="uq_order_event_idempotency"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    event_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("events.id", ondelete="CASCADE"), nullable=False, index=True
    )
    participant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("participants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    dni_blind_index: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="PENDING", nullable=False, index=True)
    total_cents: Mapped[int] = mapped_column(Integer, nullable=False)
    payment_reference: Mapped[str | None] = mapped_column(String(120), nullable=True)
    credential_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    qr_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    paid_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class OrderItem(Base):
    """Line items within a participant order."""

    __tablename__ = "order_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    order_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("orders.id", ondelete="CASCADE"), nullable=False, index=True
    )
    catalog_item_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("catalog_items.id", ondelete="RESTRICT"), nullable=False
    )
    item_code: Mapped[str] = mapped_column(String(40), nullable=False)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False)
    unit_price_cents: Mapped[int] = mapped_column(Integer, nullable=False)


class OutboxEvent(Base):
    """Transactional Outbox table for reliable asynchronous delivery to accreditation & workers."""

    __tablename__ = "outbox_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)
    published: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
