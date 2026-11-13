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
    venue: str = Field(default="Estadio / Centro de Convenciones, Lima", min_length=2, max_length=180)
    venue_address: str = Field(default="", max_length=255)
    description: str = Field(default="", max_length=4000)
    brand_color: str = Field(default="#8b5cf6", pattern=r"^#[0-9a-fA-F]{6}$")
    timezone_name: str = Field(default="America/Lima", min_length=3, max_length=60)
    banner_image_url: str = Field(default="", max_length=500000)
    logo_url: str = Field(default="", max_length=500000)
    map_coordinates: str = Field(default="", max_length=255)
    starts_at: datetime
    ends_at: datetime
    max_purchases_per_dni: int = Field(default=1, ge=1, le=10)


class UpdateEventLimitRequest(StrictModel):
    max_purchases_per_dni: int = Field(ge=1, le=10)


class UpdateEventDetailsRequest(StrictModel):
    name: str | None = Field(default=None, min_length=2, max_length=160)
    venue: str | None = Field(default=None, min_length=2, max_length=180)
    venue_address: str | None = Field(default=None, max_length=255)
    description: str | None = Field(default=None, max_length=4000)
    brand_color: str | None = Field(default=None, pattern=r"^#[0-9a-fA-F]{6}$")
    banner_image_url: str | None = Field(default=None, max_length=500000)
    logo_url: str | None = Field(default=None, max_length=500000)
    map_coordinates: str | None = Field(default=None, max_length=255)
    max_purchases_per_dni: int | None = Field(default=None, ge=1, le=10)


class EventResponse(BaseModel):
    id: str
    tenant_id: str
    name: str
    slug: str
    venue: str = "Centro de Convenciones, Lima"
    venue_address: str = ""
    description: str = ""
    brand_color: str = "#8b5cf6"
    timezone_name: str = "America/Lima"
    banner_image_url: str = ""
    logo_url: str = ""
    map_coordinates: str = ""
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
    payment_method: str = Field(default="MERCADOPAGO", max_length=40)
    promoter_id: str | None = Field(default=None, max_length=36)
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


class CreatePromoterRequest(StrictModel):
    name: str = Field(min_length=2, max_length=120)
    code_prefix: str = Field(min_length=2, max_length=20, pattern=r"^[A-Z0-9_-]+$")
    email: str = Field(min_length=5, max_length=255)


class PromoterStatsResponse(BaseModel):
    id: str
    name: str
    code_prefix: str
    email: str
    codes_total: int
    codes_redeemed: int
    orders_paid: int
    revenue_cents: int


class CreateCodeBatchRequest(StrictModel):
    catalog_item_id: str = Field(min_length=1, max_length=36)
    promoter_id: str | None = Field(default=None, max_length=36)
    quantity: int = Field(ge=1, le=500)


class CourtesyCodeResponse(BaseModel):
    id: str
    code: str
    catalog_item_id: str
    promoter_id: str | None = None
    status: str
    redeemed_at: datetime | None = None


class RedeemCodeRequest(StrictModel):
    event_id: str = Field(min_length=1, max_length=36)
    code: str = Field(min_length=4, max_length=40)
    dni: str = Field(min_length=6, max_length=20)
    full_name: str = Field(min_length=2, max_length=150)
    email: str = Field(min_length=5, max_length=255)


class GuestListSubmitRequest(StrictModel):
    catalog_item_id: str = Field(min_length=1, max_length=36)
    promoter_id: str | None = Field(default=None, max_length=36)
    dni: str = Field(min_length=6, max_length=20)
    full_name: str = Field(min_length=2, max_length=150)
    email: str = Field(min_length=5, max_length=255)
    note: str = Field(default="", max_length=255)


class GuestListDecisionRequest(StrictModel):
    decision: str = Field(pattern=r"^(APPROVE|REJECT)$")


class GuestListEntryResponse(BaseModel):
    id: str
    event_id: str
    catalog_item_id: str
    display_name: str
    dni_last4: str
    note: str
    status: str
    credential_id: str | None = None
    qr_token: str | None = None
    created_at: datetime


class ComplaintCreateRequest(StrictModel):
    tenant_id: str | None = Field(default=None, max_length=36)
    event_id: str | None = Field(default=None, max_length=36)
    dni: str = Field(min_length=6, max_length=20)
    full_name: str = Field(min_length=2, max_length=150)
    email: str = Field(min_length=5, max_length=255)
    claim_type: str = Field(pattern=r"^(RECLAMO|QUEJA)$")
    detail: str = Field(min_length=10, max_length=2000)
