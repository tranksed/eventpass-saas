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
    banner_image_url: str = Field(default="", max_length=5000000)
    logo_url: str = Field(default="", max_length=5000000)
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
    banner_image_url: str | None = Field(default=None, max_length=5000000)
    logo_url: str | None = Field(default=None, max_length=5000000)
    map_coordinates: str | None = Field(default=None, max_length=255)
    max_purchases_per_dni: int | None = Field(default=None, ge=1, le=10)
    is_active: bool | None = None


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
    artist_name: str = Field(default="", max_length=120)
    interaction_type: str = Field(default="", max_length=40)
    description: str = Field(default="", max_length=255)
    price_cents: int = Field(ge=0)
    stock_total: int = Field(ge=1, le=1_000_000)


class UpdateCatalogItemRequest(StrictModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    item_type: ItemType | None = None
    artist_name: str | None = Field(default=None, max_length=120)
    interaction_type: str | None = Field(default=None, max_length=40)
    description: str | None = Field(default=None, max_length=255)
    price_cents: int | None = Field(default=None, ge=0)
    stock_total: int | None = Field(default=None, ge=0, le=1_000_000)


class CatalogItemResponse(BaseModel):
    id: str
    event_id: str
    code: str
    name: str
    item_type: ItemType
    artist_name: str = ""
    interaction_type: str = ""
    description: str = ""
    price_cents: int
    stock_total: int = 0
    stock_sold: int = 0
    stock_reserved: int = 0
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


class UpdateOrderRequest(StrictModel):
    full_name: str | None = Field(default=None, min_length=2, max_length=150)
    email: str | None = Field(default=None, min_length=5, max_length=255)
    status: str | None = Field(default=None, pattern=r"^(PAID|PENDING|CANCELLED)$")
    payment_method: str | None = Field(default=None, min_length=2, max_length=40)


class PaymentWebhookPayload(StrictModel):
    order_id: str = Field(min_length=1, max_length=36)
    payment_reference: str = Field(min_length=3, max_length=120)
    status: str = Field(pattern=r"^(PAID|FAILED)$")


class CreatePromoterRequest(StrictModel):
    name: str = Field(min_length=2, max_length=120)
    code_prefix: str = Field(min_length=2, max_length=20, pattern=r"^[A-Z0-9_-]+$")
    email: str = Field(min_length=5, max_length=255)


class UpdatePromoterRequest(StrictModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    code_prefix: str | None = Field(default=None, min_length=2, max_length=20, pattern=r"^[A-Z0-9_-]+$")
    email: str | None = Field(default=None, min_length=5, max_length=255)
    is_active: bool | None = None


class PromoterStatsResponse(BaseModel):
    id: str
    name: str
    code_prefix: str
    email: str
    codes_total: int
    codes_redeemed: int
    orders_paid: int
    revenue_cents: int
    is_active: bool = True


class CreateCodeBatchRequest(StrictModel):
    catalog_item_id: str = Field(min_length=1, max_length=36)
    promoter_id: str | None = Field(default=None, max_length=36)
    quantity: int = Field(ge=1, le=500)
    valid_day: str | None = Field(default=None, max_length=40)
    validity_hours: int | None = Field(default=None, ge=1, le=8760)
    expires_at: datetime | None = None


class UpdateCourtesyCodeRequest(StrictModel):
    status: str | None = Field(default=None, pattern=r"^(AVAILABLE|CANCELLED|EXPIRED)$")
    valid_day: str | None = Field(default=None, max_length=40)
    expires_at: datetime | None = None


class CourtesyCodeResponse(BaseModel):
    id: str
    code: str
    catalog_item_id: str
    item_name: str | None = None
    promoter_id: str | None = None
    promoter_name: str | None = None
    valid_day: str | None = None
    expires_at: datetime | None = None
    status: str
    redeemed_at: datetime | None = None


class TenantEmailConfigRequest(StrictModel):
    smtp_enabled: bool = True
    smtp_host: str = Field(min_length=2, max_length=255)
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_user: str = Field(default="", max_length=255)
    smtp_password: str | None = Field(default=None, max_length=255)
    smtp_from_email: str = Field(min_length=5, max_length=255)
    smtp_from_name: str = Field(default="EventPass Tickets", max_length=120)
    smtp_use_tls: bool = True
    smtp_use_ssl: bool = False


class TenantEmailConfigResponse(BaseModel):
    tenant_id: str
    smtp_enabled: bool
    smtp_host: str
    smtp_port: int
    smtp_user: str
    smtp_from_email: str
    smtp_from_name: str
    smtp_use_tls: bool
    smtp_use_ssl: bool
    has_password: bool


class TestEmailRequest(StrictModel):
    recipient_email: str = Field(min_length=5, max_length=255)


class CreatePhysicalBatchRequest(StrictModel):
    catalog_item_id: str = Field(min_length=1, max_length=36)
    batch_name: str = Field(min_length=2, max_length=120)
    quantity: int = Field(ge=1, le=500)
    prefix: str = Field(default="TICK", min_length=1, max_length=20)
    start_sequence: int = Field(default=1, ge=1, le=1000000)
    paper_width: str = Field(default="80mm", pattern=r"^(58mm|80mm)$")


class PhysicalTicketResponse(BaseModel):
    id: str
    sequence_number: int
    ticket_number: str
    credential_id: str
    qr_token: str
    status: str
    item_name: str
    item_code: str
    price_cents: int


class PhysicalBatchResponse(BaseModel):
    id: str
    event_id: str
    catalog_item_id: str
    batch_name: str
    quantity: int
    prefix: str
    start_sequence: int
    end_sequence: int
    paper_width: str
    created_at: datetime


class PhysicalBatchDetailResponse(PhysicalBatchResponse):
    event_name: str
    venue: str
    venue_address: str
    starts_at: datetime
    item_name: str
    price_cents: int
    tickets: list[PhysicalTicketResponse]


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


class UpdatePaymentGatewayConfigRequest(StrictModel):
    # Mercado Pago
    mp_enabled: bool = False
    mp_public_key: str = Field(default="", max_length=255)
    mp_access_token: str = Field(default="", max_length=255)
    mp_webhook_secret: str = Field(default="", max_length=255)
    mp_sandbox: bool = True

    # Izipay
    izipay_enabled: bool = False
    izipay_merchant_id: str = Field(default="", max_length=100)
    izipay_public_key: str = Field(default="", max_length=255)
    izipay_sha256_key: str = Field(default="", max_length=255)
    izipay_sandbox: bool = True

    # Yape
    yape_enabled: bool = True
    yape_provider: str = Field(default="IZIPAY", pattern=r"^(IZIPAY|MERCADOPAGO|DIRECT_QR|DIRECT)$")
    yape_phone_number: str = Field(default="", max_length=30)
    yape_recipient_name: str = Field(default="", max_length=120)


class PaymentGatewayConfigResponse(BaseModel):
    tenant_id: str
    event_id: str | None = None
    mp_enabled: bool
    mp_public_key: str
    mp_has_token: bool
    mp_token_masked: str
    mp_has_webhook_secret: bool
    mp_sandbox: bool
    izipay_enabled: bool
    izipay_merchant_id: str
    izipay_public_key: str
    izipay_has_sha256_key: bool
    izipay_sandbox: bool
    yape_enabled: bool
    yape_provider: str
    yape_phone_number: str
    yape_recipient_name: str
    updated_at: datetime | None = None


class PublicPaymentMethodsResponse(BaseModel):
    mercadopago_enabled: bool
    mp_public_key: str
    mp_sandbox: bool
    izipay_enabled: bool
    izipay_public_key: str
    izipay_merchant_id: str
    izipay_sandbox: bool
    yape_enabled: bool
    yape_provider: str
    yape_phone_number: str
    yape_recipient_name: str
    demo_enabled: bool


class InitiatePaymentRequest(StrictModel):
    payment_method: str = Field(pattern=r"^(MERCADOPAGO|IZIPAY|YAPE|DEMO)$")
    return_url: str | None = None


class InitiatePaymentResponse(BaseModel):
    order_id: str
    event_id: str
    payment_method: str
    status: str
    total_cents: int
    checkout_url: str | None = None
    init_point: str | None = None
    form_token: str | None = None
    yape_qr_data: str | None = None
    yape_phone: str | None = None
    yape_recipient: str | None = None
    reference_code: str | None = None
    credential_id: str | None = None
    qr_token: str | None = None


class YapeConfirmRequest(StrictModel):
    operation_number: str = Field(min_length=4, max_length=40)

