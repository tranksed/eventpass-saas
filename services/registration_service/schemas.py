"""Strict Pydantic v2 schemas for registration-service."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ItemType(StrEnum):
    ENTRY = "ENTRY"
    INTERACTION = "INTERACTION"


class CreateEventRequest(StrictModel):
    name: str = Field(min_length=2, max_length=160)
    slug: str = Field(min_length=2, max_length=100, pattern=r"^[a-z0-9-]+$")
    starts_at: datetime
    ends_at: datetime
    max_purchases_per_dni: int = Field(default=1, ge=1, le=10)


class UpdateEventLimitRequest(StrictModel):
    max_purchases_per_dni: int = Field(ge=1, le=10)


class EventResponse(BaseModel):
    id: str
    tenant_id: str
    name: str
    slug: str
    starts_at: datetime
    ends_at: datetime
    max_purchases_per_dni: int
    is_active: bool


class CreateCatalogItemRequest(StrictModel):
    code: str = Field(min_length=2, max_length=40, pattern=r"^[A-Z0-9_]+$")
    name: str = Field(min_length=2, max_length=120)
    item_type: ItemType
    price_cents: int = Field(ge=0)
    stock_total: int = Field(ge=1, le=1_000_000)


class CatalogItemResponse(BaseModel):
    id: str
    event_id: str
    code: str
    name: str
    item_type: ItemType
    price_cents: int
    stock_available: int


class OrderItemRequest(StrictModel):
    item_id: str = Field(min_length=1, max_length=36)
    quantity: int = Field(ge=1, le=10)


class CreateOrderRequest(StrictModel):
    dni: str = Field(min_length=6, max_length=20)
    full_name: str = Field(min_length=2, max_length=150)
    email: str = Field(min_length=5, max_length=255)
    items: list[OrderItemRequest] = Field(min_length=1, max_length=20)


class OrderResponse(BaseModel):
    order_id: str
    event_id: str
    tenant_id: str
    status: str
    total_cents: int
    dni_last4: str
    expires_at: datetime
    checkout_url: str
    credential_id: str | None = None
    qr_token: str | None = None


class PaymentWebhookPayload(StrictModel):
    order_id: str = Field(min_length=1, max_length=36)
    payment_reference: str = Field(min_length=3, max_length=120)
    status: str = Field(pattern=r"^(PAID|FAILED)$")
