"""FastAPI application for registration-service.

Handles:
- Multi-tenant Events, branding, Peru timezone & DNI limits (1..10).
- Atomic stock reservations, idempotent orders, and HMAC-verified payment webhooks.
- RR.PP. Promoters & Courtesy Code batches (nominative DNI-linked QR redemption).
- Public Guest List with 1-click Admin/Supervisor approval -> QR issuance.
- Background Bulk Excel/CSV imports + real Excel (.xlsx) metrics export.
- Peru Libro de Reclamaciones virtual endpoint.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import secrets
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, Callable

import httpx
import openpyxl
from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    File,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from services.registration_service.config import RegistrationSettings
from services.registration_service.gateways import IzipayGateway, MercadoPagoGateway, YapeGateway
from services.registration_service.models import (
    BulkDispatchJob,
    CatalogItem,
    ComplaintRecord,
    CourtesyCode,
    Event,
    GuestListEntry,
    Order,
    OrderItem,
    OutboxEvent,
    Participant,
    PaymentGatewayConfig,
    PhysicalTicket,
    PhysicalTicketBatch,
    Promoter,
    TenantEmailConfig,
)
from services.registration_service.schemas import (
    CatalogItemResponse,
    ComplaintCreateRequest,
    CourtesyCodeResponse,
    CreateCatalogItemRequest,
    CreateCodeBatchRequest,
    CreateEventRequest,
    CreateOrderRequest,
    CreatePhysicalBatchRequest,
    CreatePromoterRequest,
    EventResponse,
    GuestListDecisionRequest,
    GuestListEntryResponse,
    GuestListSubmitRequest,
    InitiatePaymentRequest,
    InitiatePaymentResponse,
    ItemType,
    OrderResponse,
    PaymentGatewayConfigResponse,
    PaymentWebhookPayload,
    PhysicalBatchDetailResponse,
    PhysicalBatchResponse,
    PhysicalTicketResponse,
    PromoterStatsResponse,
    PublicPaymentMethodsResponse,
    RedeemCodeRequest,
    TenantEmailConfigRequest,
    TenantEmailConfigResponse,
    TestEmailRequest,
    UpdateCatalogItemRequest,
    UpdateCourtesyCodeRequest,
    UpdateEventDetailsRequest,
    UpdateEventLimitRequest,
    UpdateOrderRequest,
    UpdatePaymentGatewayConfigRequest,
    UpdatePromoterRequest,
    YapeConfirmRequest,
)
from shared_kernel.audit_client import AuditClient
from shared_kernel.crypto import (
    PIIEncryptor,
    load_ed25519_public_key,
    mask_dni,
    normalize_dni,
    verify_webhook_signature,
)
from shared_kernel.database import Base, create_service_db, get_db_session, init_db_schema
from shared_kernel.email_service import (
    generate_qr_with_logo,
    render_ticket_email_html,
    send_email_async,
)
from shared_kernel.security import (
    CurrentActor,
    Role,
    SecurityHeadersMiddleware,
    SlidingWindowRateLimiterMiddleware,
    make_role_dependency,
)


def _as_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _event_to_response(e: Event) -> EventResponse:
    return EventResponse(
        id=e.id,
        tenant_id=e.tenant_id,
        name=e.name,
        slug=e.slug,
        venue=e.venue,
        venue_address=getattr(e, "venue_address", "") or "",
        description=e.description,
        brand_color=e.brand_color,
        timezone_name=e.timezone_name,
        banner_image_url=getattr(e, "banner_image_url", "") or "",
        logo_url=getattr(e, "logo_url", "") or "",
        map_coordinates=getattr(e, "map_coordinates", "") or "",
        starts_at=e.starts_at,
        ends_at=e.ends_at,
        max_purchases_per_dni=e.max_purchases_per_dni,
        is_active=e.is_active,
    )


def _item_to_response(i: CatalogItem) -> CatalogItemResponse:
    return CatalogItemResponse(
        id=i.id,
        event_id=i.event_id,
        code=i.code,
        name=i.name,
        item_type=ItemType(i.item_type),
        artist_name=getattr(i, "artist_name", "") or "",
        interaction_type=getattr(i, "interaction_type", "") or "",
        description=getattr(i, "description", "") or "",
        price_cents=i.price_cents,
        stock_total=i.stock_total,
        stock_sold=i.stock_sold,
        stock_reserved=i.stock_reserved,
        stock_available=max(0, i.stock_total - i.stock_reserved - i.stock_sold),
    )


async def _ensure_schema_columns(conn) -> None:
    """Safely add newly introduced columns on existing dev SQLite/Postgres databases."""
    is_pg = conn.dialect.name == "postgresql"
    alter_columns = [
        ("events", "venue", "VARCHAR(180) NOT NULL DEFAULT 'Centro de Convenciones, Lima'"),
        ("events", "venue_address", "VARCHAR(255) NOT NULL DEFAULT ''"),
        ("events", "description", "TEXT NOT NULL DEFAULT ''"),
        ("events", "brand_color", "VARCHAR(20) NOT NULL DEFAULT '#8b5cf6'"),
        ("events", "timezone_name", "VARCHAR(60) NOT NULL DEFAULT 'America/Lima'"),
        ("events", "banner_image_url", "TEXT NOT NULL DEFAULT ''"),
        ("events", "logo_url", "TEXT NOT NULL DEFAULT ''"),
        ("events", "map_coordinates", "VARCHAR(255) NOT NULL DEFAULT ''"),
        ("orders", "source", "VARCHAR(30) NOT NULL DEFAULT 'ONLINE'"),
        ("orders", "promoter_id", "VARCHAR(36)"),
        ("orders", "payment_method", "VARCHAR(40) NOT NULL DEFAULT 'MERCADOPAGO'"),
        ("orders", "checkout_url", "TEXT"),
        ("orders", "gateway_response_json", "TEXT"),
        ("catalog_items", "artist_name", "VARCHAR(120) NOT NULL DEFAULT ''"),
        ("catalog_items", "interaction_type", "VARCHAR(40) NOT NULL DEFAULT ''"),
        ("catalog_items", "description", "VARCHAR(255) NOT NULL DEFAULT ''"),
        ("courtesy_codes", "expires_at", "TIMESTAMP WITH TIME ZONE" if is_pg else "DATETIME"),
        ("courtesy_codes", "valid_day", "VARCHAR(40) NOT NULL DEFAULT ''"),
        ("promoters", "is_active", "BOOLEAN NOT NULL DEFAULT TRUE" if is_pg else "BOOLEAN NOT NULL DEFAULT 1"),
    ]
    for table, col, col_def in alter_columns:
        try:
            if is_pg:
                await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col} {col_def}"))
            else:
                async with conn.begin_nested():
                    await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {col_def}"))
        except Exception:
            pass


def create_registration_app(
    settings: RegistrationSettings | None = None,
    *,
    accreditation_client_factory: Callable[[], httpx.AsyncClient] | None = None,
    audit_client: AuditClient | None = None,
) -> FastAPI:
    """Create the isolated registration-service FastAPI application."""
    cfg = settings or RegistrationSettings()
    engine, session_factory = create_service_db(cfg.database_url)
    jwt_pub_key = load_ed25519_public_key(cfg.keys_dir, "jwt")
    pii_crypto = PIIEncryptor(cfg.pii_master_key_b64, cfg.dni_blind_index_pepper)
    audit = audit_client or AuditClient(cfg.audit_service_url, cfg.internal_service_token)

    dni_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def get_db():
        async for sess in get_db_session(session_factory):
            yield sess

    require_admin = make_role_dependency(lambda: jwt_pub_key, Role.ADMIN)
    require_admin_or_supervisor = make_role_dependency(lambda: jwt_pub_key, Role.ADMIN, Role.SUPERVISOR)
    require_superadmin = make_role_dependency(lambda: jwt_pub_key, Role.SUPERADMIN)
    require_admin_or_superadmin = make_role_dependency(lambda: jwt_pub_key, Role.ADMIN, Role.SUPERADMIN)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await init_db_schema(engine, Base.metadata, post_init=_ensure_schema_columns)
        yield
        await engine.dispose()

    app = FastAPI(title="EventPass Registration Service", version="2.0.0", lifespan=lifespan)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        SlidingWindowRateLimiterMiddleware,
        max_requests=cfg.rate_limit_requests,
        window_seconds=cfg.rate_limit_window_seconds,
    )

    async def _issue_participant_qr(
        event: Event,
        display_name: str,
        dni_last4: str,
        holder_ref_id: str,
        order_id: str | None,
        entitlements: dict[str, int],
    ) -> tuple[str, str]:
        payload = {
            "tenant_id": event.tenant_id,
            "event_id": event.id,
            "order_id": order_id,
            "holder_type": "PARTICIPANT",
            "holder_ref_id": holder_ref_id,
            "display_name": display_name,
            "dni_last4": dni_last4,
            "entitlements": entitlements,
            "expires_at": _as_utc(event.ends_at).isoformat(),
        }
        headers = {"X-Internal-Service-Token": cfg.internal_service_token}
        if accreditation_client_factory is not None:
            async with accreditation_client_factory() as client:
                resp = await client.post("/internal/accreditation/credentials/issue", json=payload, headers=headers)
        else:
            async with httpx.AsyncClient(base_url=cfg.accreditation_service_url, timeout=5.0) as client:
                resp = await client.post("/internal/accreditation/credentials/issue", json=payload, headers=headers)
        if resp.status_code != status.HTTP_201_CREATED:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Accreditation service failed to issue QR: {resp.text}",
            )
        data = resp.json()
        return data["credential_id"], data["qr_token"]

    async def _upsert_participant(
        db: AsyncSession,
        *,
        event: Event,
        dni_idx: str,
        normalized_dni: str,
        dni_last4: str,
        full_name: str,
        email: str,
    ) -> Participant:
        participant = await db.scalar(
            select(Participant).where(Participant.event_id == event.id, Participant.dni_blind_index == dni_idx)
        )
        if participant is None:
            participant = Participant(
                tenant_id=event.tenant_id,
                event_id=event.id,
                dni_blind_index=dni_idx,
                dni_encrypted=pii_crypto.encrypt(normalized_dni, aad=event.id),
                dni_last4=dni_last4,
                full_name_encrypted=pii_crypto.encrypt(full_name, aad=event.id),
                email_encrypted=pii_crypto.encrypt(email.lower(), aad=event.id),
            )
            db.add(participant)
            await db.flush()
        return participant

    async def _issue_complimentary_pass(
        db: AsyncSession,
        *,
        event: Event,
        catalog_item: CatalogItem,
        raw_dni: str,
        full_name: str,
        email: str,
        source: str,
        promoter_id: str | None = None,
        enforce_dni_limit: bool = True,
    ) -> tuple[Order, str, str]:
        """Shared helper to atomically reserve 1 unit and issue a nominative QR (codes, guestlist, bulk)."""
        normalized_dni = normalize_dni(raw_dni)
        dni_last4 = mask_dni(normalized_dni)
        dni_idx = pii_crypto.blind_index_dni(event.tenant_id, event.id, normalized_dni)
        now = datetime.now(timezone.utc)

        async with dni_locks[f"{event.id}:{dni_idx}"]:
            if enforce_dni_limit:
                bought = await db.scalar(
                    select(func.coalesce(func.sum(OrderItem.quantity), 0))
                    .join(Order, OrderItem.order_id == Order.id)
                    .where(
                        Order.event_id == event.id,
                        Order.dni_blind_index == dni_idx,
                        OrderItem.catalog_item_id == catalog_item.id,
                        (Order.status == "PAID") | ((Order.status == "PENDING") & (Order.expires_at > now)),
                    )
                )
                if int(bought or 0) + 1 > event.max_purchases_per_dni:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=f"DNI limit exceeded ({event.max_purchases_per_dni} max per DNI).",
                    )

            res = await db.execute(
                update(CatalogItem)
                .where(
                    CatalogItem.id == catalog_item.id,
                    (CatalogItem.stock_total - CatalogItem.stock_reserved - CatalogItem.stock_sold) >= 1,
                )
                .values(stock_sold=CatalogItem.stock_sold + 1)
            )
            if res.rowcount != 1:
                await db.rollback()
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"No stock for {catalog_item.code}.")

            participant = await _upsert_participant(
                db,
                event=event,
                dni_idx=dni_idx,
                normalized_dni=normalized_dni,
                dni_last4=dni_last4,
                full_name=full_name,
                email=email,
            )

            order = Order(
                tenant_id=event.tenant_id,
                event_id=event.id,
                participant_id=participant.id,
                dni_blind_index=dni_idx,
                idempotency_key=f"{source.lower()}-{secrets.token_hex(12)}",
                status="PAID",
                source=source,
                promoter_id=promoter_id,
                total_cents=0,
                payment_method=source,
                payment_reference=f"{source}-{secrets.token_hex(6).upper()}",
                expires_at=now + timedelta(minutes=10),
                paid_at=now,
            )
            db.add(order)
            await db.flush()
            db.add(
                OrderItem(
                    order_id=order.id,
                    catalog_item_id=catalog_item.id,
                    item_code=catalog_item.code,
                    quantity=1,
                    unit_price_cents=0,
                )
            )

            entitlements = {catalog_item.code: 1}
            if catalog_item.item_type == "ENTRY" and catalog_item.code != "ENTRY":
                entitlements["ENTRY"] = 1
            elif catalog_item.interaction_type and catalog_item.code != catalog_item.interaction_type:
                entitlements[catalog_item.interaction_type] = 1

            cred_id, qr_token = await _issue_participant_qr(
                event,
                full_name,
                dni_last4,
                participant.id,
                order.id,
                entitlements,
            )
            order.credential_id = cred_id
            order.qr_token = qr_token
            await db.commit()
            return order, cred_id, qr_token

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": cfg.service_name}

    # ------------------------------------------------------------------
    # Events & Catalog Items
    # ------------------------------------------------------------------
    @app.post("/api/v1/registration/events", response_model=EventResponse, status_code=status.HTTP_201_CREATED)
    async def create_event(
        payload: CreateEventRequest,
        actor: CurrentActor = Depends(require_admin),
        db: AsyncSession = Depends(get_db),
    ) -> EventResponse:
        if payload.ends_at <= payload.starts_at:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="ends_at must be after starts_at.")

        existing = await db.scalar(
            select(Event).where(Event.tenant_id == actor.tenant_id, Event.slug == payload.slug)
        )
        if existing is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Event slug already exists in tenant.")

        event = Event(
            tenant_id=actor.tenant_id,
            name=payload.name,
            slug=payload.slug,
            venue=payload.venue,
            venue_address=payload.venue_address,
            description=payload.description,
            brand_color=payload.brand_color,
            timezone_name=payload.timezone_name,
            banner_image_url=payload.banner_image_url,
            logo_url=payload.logo_url,
            map_coordinates=payload.map_coordinates,
            starts_at=payload.starts_at,
            ends_at=payload.ends_at,
            max_purchases_per_dni=payload.max_purchases_per_dni,
        )
        db.add(event)
        await db.commit()
        await audit.record(
            tenant_id=actor.tenant_id,
            service=cfg.service_name,
            action="EVENT_CREATED",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="event",
            resource_id=event.id,
            metadata={"max_purchases_per_dni": event.max_purchases_per_dni, "venue": event.venue},
        )
        return _event_to_response(event)

    async def _resolve_event(event_id: str, actor: CurrentActor, db: AsyncSession) -> Event:
        if actor.role == Role.SUPERADMIN:
            event = await db.scalar(select(Event).where(Event.id == event_id))
        else:
            event = await db.scalar(select(Event).where(Event.id == event_id, Event.tenant_id == actor.tenant_id))
        if event is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found.")
        return event

    @app.patch("/api/v1/registration/events/{event_id}", response_model=EventResponse)
    async def update_event_details(
        event_id: str,
        payload: UpdateEventDetailsRequest,
        actor: CurrentActor = Depends(require_admin),
        db: AsyncSession = Depends(get_db),
    ) -> EventResponse:
        event = await _resolve_event(event_id, actor, db)

        if payload.name is not None:
            event.name = payload.name
        if payload.venue is not None:
            event.venue = payload.venue
        if payload.venue_address is not None:
            event.venue_address = payload.venue_address
        if payload.description is not None:
            event.description = payload.description
        if payload.brand_color is not None:
            event.brand_color = payload.brand_color
        if payload.banner_image_url is not None:
            event.banner_image_url = payload.banner_image_url
        if payload.logo_url is not None:
            event.logo_url = payload.logo_url
        if payload.map_coordinates is not None:
            event.map_coordinates = payload.map_coordinates
        if payload.max_purchases_per_dni is not None:
            event.max_purchases_per_dni = payload.max_purchases_per_dni
        if payload.is_active is not None:
            event.is_active = payload.is_active

        await db.commit()
        return _event_to_response(event)

    @app.patch("/api/v1/registration/events/{event_id}/dni-limit", response_model=EventResponse)
    async def update_event_dni_limit(
        event_id: str,
        payload: UpdateEventLimitRequest,
        actor: CurrentActor = Depends(require_admin),
        db: AsyncSession = Depends(get_db),
    ) -> EventResponse:
        event = await _resolve_event(event_id, actor, db)
        event.max_purchases_per_dni = payload.max_purchases_per_dni
        await db.commit()
        await audit.record(
            tenant_id=event.tenant_id,
            service=cfg.service_name,
            action="EVENT_DNI_LIMIT_UPDATED",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="event",
            resource_id=event.id,
            metadata={"max_purchases_per_dni": event.max_purchases_per_dni},
        )
        return _event_to_response(event)

    @app.get("/api/v1/registration/events", response_model=list[EventResponse])
    async def list_tenant_events(
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> list[EventResponse]:
        if actor.role == Role.SUPERADMIN:
            events = (await db.scalars(select(Event).order_by(Event.created_at.desc()))).all()
        else:
            events = (
                await db.scalars(select(Event).where(Event.tenant_id == actor.tenant_id).order_by(Event.created_at.desc()))
            ).all()
        return [_event_to_response(e) for e in events]

    @app.get("/api/v1/registration/public/events", response_model=list[EventResponse])
    async def list_public_active_events(db: AsyncSession = Depends(get_db)) -> list[EventResponse]:
        events = (
            await db.scalars(select(Event).where(Event.is_active.is_(True)).order_by(Event.created_at.desc()))
        ).all()
        return [_event_to_response(e) for e in events]

    @app.post(
        "/api/v1/registration/events/{event_id}/items",
        response_model=CatalogItemResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def create_catalog_item(
        event_id: str,
        payload: CreateCatalogItemRequest,
        actor: CurrentActor = Depends(require_admin),
        db: AsyncSession = Depends(get_db),
    ) -> CatalogItemResponse:
        event = await _resolve_event(event_id, actor, db)

        existing = await db.scalar(
            select(CatalogItem).where(CatalogItem.event_id == event_id, CatalogItem.code == payload.code)
        )
        if existing is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Item code already exists in event.")

        item = CatalogItem(
            event_id=event.id,
            tenant_id=event.tenant_id,
            code=payload.code,
            name=payload.name,
            item_type=payload.item_type.value,
            artist_name=payload.artist_name or "",
            interaction_type=payload.interaction_type or "",
            description=payload.description or "",
            price_cents=payload.price_cents,
            stock_total=payload.stock_total,
        )
        db.add(item)
        await db.commit()
        await audit.record(
            tenant_id=actor.tenant_id,
            service=cfg.service_name,
            action="CATALOG_ITEM_CREATED",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="catalog_item",
            resource_id=item.id,
            metadata={"code": item.code, "price_cents": item.price_cents, "stock_total": item.stock_total},
        )
        return _item_to_response(item)

    @app.get("/api/v1/registration/events/{event_id}/items", response_model=list[CatalogItemResponse])
    async def list_public_catalog_items(event_id: str, db: AsyncSession = Depends(get_db)) -> list[CatalogItemResponse]:
        items = (await db.scalars(select(CatalogItem).where(CatalogItem.event_id == event_id))).all()
        return [_item_to_response(i) for i in items]

    @app.patch("/api/v1/registration/events/{event_id}/items/{item_id}", response_model=CatalogItemResponse)
    async def update_catalog_item(
        event_id: str,
        item_id: str,
        payload: UpdateCatalogItemRequest,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> CatalogItemResponse:
        """Update name, item_type, price or stock of an active catalog item."""
        event = await _resolve_event(event_id, actor, db)

        item = await db.scalar(select(CatalogItem).where(CatalogItem.id == item_id, CatalogItem.event_id == event.id))
        if item is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Catalog item not found.")

        if payload.name is not None:
            item.name = payload.name
        if payload.item_type is not None:
            item.item_type = payload.item_type.value
        if payload.artist_name is not None:
            item.artist_name = payload.artist_name
        if payload.interaction_type is not None:
            item.interaction_type = payload.interaction_type
        if payload.description is not None:
            item.description = payload.description
        if payload.price_cents is not None:
            item.price_cents = payload.price_cents
        if payload.stock_total is not None:
            committed_stock = item.stock_sold + item.stock_reserved
            if payload.stock_total < committed_stock:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"No puedes reducir el stock total a {payload.stock_total} porque ya existen {item.stock_sold} vendidos y {item.stock_reserved} reservados (mínimo permitido: {committed_stock}).",
                )
            item.stock_total = payload.stock_total

        await db.commit()
        await audit.record(
            tenant_id=event.tenant_id,
            service=cfg.service_name,
            action="CATALOG_ITEM_UPDATED",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="catalog_item",
            resource_id=item.id,
            metadata={"code": item.code, "price_cents": item.price_cents, "stock_total": item.stock_total},
        )
        return _item_to_response(item)

    @app.delete("/api/v1/registration/events/{event_id}/items/{item_id}")
    async def delete_catalog_item(
        event_id: str,
        item_id: str,
        actor: CurrentActor = Depends(require_admin),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, Any]:
        """Delete an unused catalog item with 0 sold and 0 reserved (Admin only)."""
        event = await _resolve_event(event_id, actor, db)
        item = await db.scalar(select(CatalogItem).where(CatalogItem.id == item_id, CatalogItem.event_id == event.id))
        if item is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Catalog item not found.")

        item = await db.scalar(select(CatalogItem).where(CatalogItem.id == item_id, CatalogItem.event_id == event.id))
        if item is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Catalog item not found.")

        if item.stock_sold > 0 or item.stock_reserved > 0:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"No se puede eliminar '{item.code}' porque ya tiene {item.stock_sold} vendidas o {item.stock_reserved} reservadas. Puedes editar su stock a 0.",
            )

        has_codes = await db.scalar(select(CourtesyCode.id).where(CourtesyCode.catalog_item_id == item.id).limit(1))
        if has_codes:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"No se puede eliminar '{item.code}' porque tiene códigos de cortesía vinculados.",
            )

        await db.delete(item)
        await db.commit()
        await audit.record(
            tenant_id=actor.tenant_id,
            service=cfg.service_name,
            action="CATALOG_ITEM_DELETED",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="catalog_item",
            resource_id=item.id,
            metadata={"code": item.code},
        )
        return {"status": "deleted", "item_id": item_id}

    # ------------------------------------------------------------------
    # Online Checkout & Payment Webhooks
    # ------------------------------------------------------------------
    @app.post(
        "/api/v1/registration/events/{event_id}/orders",
        response_model=OrderResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def create_participant_order(
        event_id: str,
        payload: CreateOrderRequest,
        request: Request,
        idempotency_key: str = Header(..., min_length=8, max_length=128),
        db: AsyncSession = Depends(get_db),
    ) -> OrderResponse:
        event = await db.scalar(select(Event).where(Event.id == event_id, Event.is_active.is_(True)))
        if event is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active event not found.")

        try:
            normalized_dni = normalize_dni(payload.dni)
            dni_last4 = mask_dni(normalized_dni)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

        dni_idx = pii_crypto.blind_index_dni(event.tenant_id, event.id, normalized_dni)
        async with dni_locks[f"{event.id}:{dni_idx}"]:
            existing_order = await db.scalar(
                select(Order).where(Order.event_id == event.id, Order.idempotency_key == idempotency_key)
            )
            if existing_order is not None:
                return OrderResponse(
                    order_id=existing_order.id,
                    event_id=existing_order.event_id,
                    tenant_id=existing_order.tenant_id,
                    status=existing_order.status,
                    total_cents=existing_order.total_cents,
                    dni_last4=dni_last4,
                    expires_at=existing_order.expires_at,
                    checkout_url=f"/checkout/{existing_order.id}",
                    credential_id=existing_order.credential_id,
                    qr_token=existing_order.qr_token,
                )

            now = datetime.now(timezone.utc)
            requested_by_item: dict[str, int] = defaultdict(int)
            for req_item in payload.items:
                requested_by_item[req_item.item_id] += req_item.quantity

            existing_qty_rows = (
                await db.execute(
                    select(OrderItem.catalog_item_id, func.coalesce(func.sum(OrderItem.quantity), 0))
                    .join(Order, OrderItem.order_id == Order.id)
                    .where(
                        Order.event_id == event.id,
                        Order.dni_blind_index == dni_idx,
                        (Order.status == "PAID") | ((Order.status == "PENDING") & (Order.expires_at > now)),
                    )
                    .group_by(OrderItem.catalog_item_id)
                )
            ).all()
            already_bought = {row[0]: int(row[1]) for row in existing_qty_rows}

            catalog_map: dict[str, CatalogItem] = {}
            total_cents = 0
            for item_id, req_qty in requested_by_item.items():
                catalog_item = await db.scalar(
                    select(CatalogItem).where(CatalogItem.id == item_id, CatalogItem.event_id == event.id)
                )
                if catalog_item is None:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"Catalog item '{item_id}' not found for event.",
                    )
                if already_bought.get(item_id, 0) + req_qty > event.max_purchases_per_dni:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=(
                            f"DNI limit exceeded for '{catalog_item.code}'. "
                            f"Max allowed per DNI is {event.max_purchases_per_dni}."
                        ),
                    )
                catalog_map[item_id] = catalog_item
                total_cents += catalog_item.price_cents * req_qty

            for item_id, req_qty in requested_by_item.items():
                res = await db.execute(
                    update(CatalogItem)
                    .where(
                        CatalogItem.id == item_id,
                        CatalogItem.event_id == event.id,
                        (CatalogItem.stock_total - CatalogItem.stock_reserved - CatalogItem.stock_sold) >= req_qty,
                    )
                    .values(stock_reserved=CatalogItem.stock_reserved + req_qty)
                )
                if res.rowcount != 1:
                    item_code = catalog_map[item_id].code
                    await db.rollback()
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=f"Insufficient stock for item '{item_code}'.",
                    )

            participant = await _upsert_participant(
                db,
                event=event,
                dni_idx=dni_idx,
                normalized_dni=normalized_dni,
                dni_last4=dni_last4,
                full_name=payload.full_name,
                email=payload.email,
            )

            expires_at = now + timedelta(minutes=cfg.reservation_ttl_minutes)
            order = Order(
                tenant_id=event.tenant_id,
                event_id=event.id,
                participant_id=participant.id,
                dni_blind_index=dni_idx,
                idempotency_key=idempotency_key,
                status="PENDING",
                source="ONLINE",
                promoter_id=payload.promoter_id,
                payment_method=payload.payment_method,
                total_cents=total_cents,
                expires_at=expires_at,
            )
            db.add(order)
            await db.flush()

            order_items_list: list[OrderItem] = []
            for item_id, req_qty in requested_by_item.items():
                ci = catalog_map[item_id]
                oi = OrderItem(
                    order_id=order.id,
                    catalog_item_id=ci.id,
                    item_code=ci.code,
                    quantity=req_qty,
                    unit_price_cents=ci.price_cents,
                )
                db.add(oi)
                order_items_list.append(oi)

            # Generate Gateway Checkout Session
            base_url = str(request.base_url).rstrip("/")
            gw_conf = await _get_gateway_config(db, event.tenant_id, event.id)
            checkout_url = f"/checkout/{order.id}"

            if payload.payment_method == "MERCADOPAGO":
                mp_res = await MercadoPagoGateway.create_preference(
                    order, event, order_items_list, payload.full_name, payload.email, gw_conf, base_url
                )
                checkout_url = mp_res.get("checkout_url") or checkout_url
                order.gateway_response_json = json.dumps(mp_res)
            elif payload.payment_method == "IZIPAY":
                iz_res = await IzipayGateway.create_payment_session(
                    order, event, order_items_list, payload.full_name, payload.email, dni_last4, gw_conf, base_url
                )
                checkout_url = iz_res.get("checkout_url") or checkout_url
                order.gateway_response_json = json.dumps(iz_res)
            elif payload.payment_method == "YAPE":
                yape_info = YapeGateway.generate_yape_details(order, event, gw_conf)
                checkout_url = f"/checkout/yape?order_id={order.id}"
                order.gateway_response_json = json.dumps(yape_info)
            else:
                checkout_url = f"/checkout/demo?order_id={order.id}"

            order.checkout_url = checkout_url
            await db.commit()
            return OrderResponse(
                order_id=order.id,
                event_id=order.event_id,
                tenant_id=order.tenant_id,
                status=order.status,
                total_cents=order.total_cents,
                dni_last4=participant.dni_last4,
                expires_at=order.expires_at,
                checkout_url=order.checkout_url,
            )

    async def _complete_paid_order(
        db: AsyncSession,
        order: Order,
        payment_reference: str,
        payment_method: str | None = None,
    ) -> dict[str, str | None]:
        """Atomically transition an order to PAID, shift inventory, and issue signed QR ticket."""
        if order.status == "PAID":
            return {
                "order_id": order.id,
                "status": order.status,
                "credential_id": order.credential_id,
                "qr_token": order.qr_token,
            }

        order_items = (await db.scalars(select(OrderItem).where(OrderItem.order_id == order.id))).all()
        for oi in order_items:
            await db.execute(
                update(CatalogItem)
                .where(CatalogItem.id == oi.catalog_item_id)
                .values(
                    stock_reserved=CatalogItem.stock_reserved - oi.quantity,
                    stock_sold=CatalogItem.stock_sold + oi.quantity,
                )
            )

        event = await db.scalar(select(Event).where(Event.id == order.event_id))
        participant = await db.scalar(select(Participant).where(Participant.id == order.participant_id))
        assert event is not None and participant is not None

        catalogs = (await db.scalars(select(CatalogItem).where(CatalogItem.event_id == event.id))).all()
        cat_by_code = {c.code: c for c in catalogs}

        entitlements: dict[str, int] = defaultdict(int)
        for oi in order_items:
            entitlements[oi.item_code] += oi.quantity
            it = cat_by_code.get(oi.item_code)
            if it and it.item_type == "ENTRY" and oi.item_code != "ENTRY":
                entitlements["ENTRY"] += oi.quantity
            elif it and it.interaction_type and oi.item_code != it.interaction_type:
                entitlements[it.interaction_type] += oi.quantity

        display_name = pii_crypto.decrypt(participant.full_name_encrypted, aad=event.id)
        credential_id, qr_token = await _issue_participant_qr(
            event, display_name, participant.dni_last4, participant.id, order.id, dict(entitlements)
        )

        order.status = "PAID"
        order.payment_reference = payment_reference
        if payment_method:
            order.payment_method = payment_method
        order.paid_at = datetime.now(timezone.utc)
        order.credential_id = credential_id
        order.qr_token = qr_token

        db.add(
            OutboxEvent(
                tenant_id=order.tenant_id,
                event_type="OrderPaid",
                payload_json=json.dumps(
                    {
                        "order_id": order.id,
                        "event_id": order.event_id,
                        "credential_id": credential_id,
                        "entitlements": dict(entitlements),
                    }
                ),
                published=True,
            )
        )
        await db.commit()
        await audit.record(
            tenant_id=order.tenant_id,
            service=cfg.service_name,
            action="ORDER_PAID_QR_ISSUED",
            actor_id=participant.id,
            actor_role="PARTICIPANT",
            resource_type="order",
            resource_id=order.id,
            metadata={"credential_id": credential_id, "entitlements": dict(entitlements)},
        )

        # Auto-dispatch official tickets email with styled QR
        try:
            buyer_email = pii_crypto.decrypt(participant.email_encrypted, aad=event.id)
            buyer_name = display_name
            items_str = ", ".join(f"{oi.quantity}x {oi.item_code}" for oi in order_items) or "Entrada"
            soles_str = f"{(order.total_cents / 100):.2f}"
            starts_str = event.starts_at.strftime("%d/%m/%Y %H:%M") if event.starts_at else ""
            qr_bytes = generate_qr_with_logo(qr_token, brand_color=event.brand_color or "#8b5cf6")
            html_content = render_ticket_email_html(
                event_name=event.name,
                buyer_name=buyer_name,
                dni_last4=participant.dni_last4,
                order_id=order.id,
                items_summary=items_str,
                total_soles=soles_str,
                venue=event.venue,
                venue_address=event.venue_address,
                starts_at_str=starts_str,
                brand_color=event.brand_color or "#8b5cf6",
            )
            subj = f"🎟️ Tus Entradas — {event.name} [Orden {order.id[:8]}]"
            mail_cfg = await _get_tenant_email_settings(db, event.tenant_id)
            asyncio.create_task(send_email_async(mail_cfg, buyer_email, subj, html_content, qr_bytes))
        except Exception as exc:
            logger.warning("Could not auto-dispatch ticket email for order %s: %s", order.id, exc)

        return {
            "order_id": order.id,
            "status": order.status,
            "credential_id": credential_id,
            "qr_token": qr_token,
        }

    async def _get_tenant_email_settings(db: AsyncSession, tenant_id: str):
        cfg_row = await db.scalar(select(TenantEmailConfig).where(TenantEmailConfig.tenant_id == tenant_id))
        if cfg_row and cfg_row.smtp_enabled and cfg_row.smtp_host:
            password = ""
            if cfg_row.smtp_password_encrypted:
                try:
                    password = pii_crypto.decrypt(cfg_row.smtp_password_encrypted, aad="smtp")
                except Exception:
                    password = ""
            return SimpleNamespace(
                smtp_host=cfg_row.smtp_host,
                smtp_port=cfg_row.smtp_port,
                smtp_user=cfg_row.smtp_user,
                smtp_password=password,
                smtp_from_email=cfg_row.smtp_from_email,
                smtp_from_name=cfg_row.smtp_from_name,
                smtp_use_tls=cfg_row.smtp_use_tls,
                smtp_use_ssl=cfg_row.smtp_use_ssl,
                data_dir=cfg.data_dir,
            )
        return cfg

    async def _get_gateway_config(
        db: AsyncSession, tenant_id: str, event_id: str | None = None
    ) -> PaymentGatewayConfig:
        stmt = select(PaymentGatewayConfig).where(PaymentGatewayConfig.tenant_id == tenant_id)
        if event_id:
            stmt = stmt.where((PaymentGatewayConfig.event_id == event_id) | (PaymentGatewayConfig.event_id.is_(None)))
            stmt = stmt.order_by(PaymentGatewayConfig.event_id.desc())
        else:
            stmt = stmt.where(PaymentGatewayConfig.event_id.is_(None))
        conf = await db.scalar(stmt)
        if conf is None:
            conf = PaymentGatewayConfig(
                tenant_id=tenant_id,
                event_id=event_id,
                mp_enabled=False,
                mp_public_key="",
                mp_access_token="",
                mp_webhook_secret="",
                mp_sandbox=True,
                izipay_enabled=False,
                izipay_merchant_id="",
                izipay_public_key="",
                izipay_sha256_key="",
                izipay_sandbox=True,
                yape_enabled=True,
                yape_provider="IZIPAY",
                yape_phone_number="",
                yape_recipient_name="",
            )
            db.add(conf)
            await db.flush()
        return conf

    def _mask_secret(val: str) -> str:
        if not val:
            return ""
        if len(val) <= 8:
            return "***"
        return f"{val[:4]}...{val[-4:]}"

    def _config_to_response(conf: PaymentGatewayConfig) -> PaymentGatewayConfigResponse:
        return PaymentGatewayConfigResponse(
            tenant_id=conf.tenant_id,
            event_id=conf.event_id,
            mp_enabled=conf.mp_enabled,
            mp_public_key=conf.mp_public_key,
            mp_has_token=bool(conf.mp_access_token),
            mp_token_masked=_mask_secret(conf.mp_access_token),
            mp_has_webhook_secret=bool(conf.mp_webhook_secret),
            mp_sandbox=conf.mp_sandbox,
            izipay_enabled=conf.izipay_enabled,
            izipay_merchant_id=conf.izipay_merchant_id,
            izipay_public_key=conf.izipay_public_key,
            izipay_has_sha256_key=bool(conf.izipay_sha256_key),
            izipay_sandbox=conf.izipay_sandbox,
            yape_enabled=conf.yape_enabled,
            yape_provider=conf.yape_provider,
            yape_phone_number=conf.yape_phone_number,
            yape_recipient_name=conf.yape_recipient_name,
            updated_at=conf.updated_at,
        )

    # -------------------------------------------------------------------------
    # Payment Gateway Configuration Endpoints (Admin / SuperAdmin)
    # -------------------------------------------------------------------------
    @app.get("/api/v1/registration/events/{event_id}/payment-config", response_model=PaymentGatewayConfigResponse)
    async def get_payment_gateway_config(
        event_id: str,
        actor: CurrentActor = Depends(require_admin_or_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> PaymentGatewayConfigResponse:
        event = await db.scalar(select(Event).where(Event.id == event_id))
        if event is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found.")
        if actor.role != Role.SUPERADMIN and event.tenant_id != actor.tenant_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access forbidden.")

        conf = await _get_gateway_config(db, event.tenant_id, event.id)
        return _config_to_response(conf)

    @app.put("/api/v1/registration/events/{event_id}/payment-config", response_model=PaymentGatewayConfigResponse)
    async def update_payment_gateway_config(
        event_id: str,
        payload: UpdatePaymentGatewayConfigRequest,
        actor: CurrentActor = Depends(require_admin_or_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> PaymentGatewayConfigResponse:
        event = await db.scalar(select(Event).where(Event.id == event_id))
        if event is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found.")
        if actor.role != Role.SUPERADMIN and event.tenant_id != actor.tenant_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access forbidden.")

        conf = await _get_gateway_config(db, event.tenant_id, event.id)

        # Update Mercado Pago fields
        conf.mp_enabled = payload.mp_enabled
        conf.mp_public_key = payload.mp_public_key.strip()
        if payload.mp_access_token and not payload.mp_access_token.startswith("***"):
            conf.mp_access_token = payload.mp_access_token.strip()
        if payload.mp_webhook_secret and not payload.mp_webhook_secret.startswith("***"):
            conf.mp_webhook_secret = payload.mp_webhook_secret.strip()
        conf.mp_sandbox = payload.mp_sandbox

        # Update Izipay fields
        conf.izipay_enabled = payload.izipay_enabled
        conf.izipay_merchant_id = payload.izipay_merchant_id.strip()
        conf.izipay_public_key = payload.izipay_public_key.strip()
        if payload.izipay_sha256_key and not payload.izipay_sha256_key.startswith("***"):
            conf.izipay_sha256_key = payload.izipay_sha256_key.strip()
        conf.izipay_sandbox = payload.izipay_sandbox

        # Update Yape fields
        conf.yape_enabled = payload.yape_enabled
        conf.yape_provider = payload.yape_provider
        conf.yape_phone_number = payload.yape_phone_number.strip()
        conf.yape_recipient_name = payload.yape_recipient_name.strip()
        conf.updated_at = datetime.now(timezone.utc)

        await db.commit()
        await audit.record(
            tenant_id=event.tenant_id,
            service=cfg.service_name,
            action="PAYMENT_GATEWAY_CONFIG_UPDATED",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="payment_gateway_config",
            resource_id=conf.id,
            metadata={"mp_enabled": conf.mp_enabled, "izipay_enabled": conf.izipay_enabled, "yape_enabled": conf.yape_enabled},
        )
        return _config_to_response(conf)

    @app.get("/api/v1/registration/events/{event_id}/public-payment-methods", response_model=PublicPaymentMethodsResponse)
    async def get_public_payment_methods(
        event_id: str,
        db: AsyncSession = Depends(get_db),
    ) -> PublicPaymentMethodsResponse:
        """Public endpoint allowing the checkout page to discover available gateways."""
        event = await db.scalar(select(Event).where(Event.id == event_id))
        if event is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found.")

        conf = await _get_gateway_config(db, event.tenant_id, event.id)
        return PublicPaymentMethodsResponse(
            mercadopago_enabled=conf.mp_enabled,
            mp_public_key=conf.mp_public_key,
            mp_sandbox=conf.mp_sandbox,
            izipay_enabled=conf.izipay_enabled,
            izipay_public_key=conf.izipay_public_key,
            izipay_merchant_id=conf.izipay_merchant_id,
            izipay_sandbox=conf.izipay_sandbox,
            yape_enabled=conf.yape_enabled,
            yape_provider=conf.yape_provider,
            yape_phone_number=conf.yape_phone_number,
            yape_recipient_name=conf.yape_recipient_name or event.name,
            demo_enabled=True,
        )

    # -------------------------------------------------------------------------
    # Initiate Payment & Yape Confirmation Endpoints
    # -------------------------------------------------------------------------
    @app.post("/api/v1/registration/orders/{order_id}/initiate-payment", response_model=InitiatePaymentResponse)
    async def initiate_order_payment(
        order_id: str,
        payload: InitiatePaymentRequest,
        request: Request,
        db: AsyncSession = Depends(get_db),
    ) -> InitiatePaymentResponse:
        order = await db.scalar(select(Order).where(Order.id == order_id))
        if order is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found.")

        if order.status == "PAID":
            return InitiatePaymentResponse(
                order_id=order.id,
                event_id=order.event_id,
                payment_method=order.payment_method,
                status=order.status,
                total_cents=order.total_cents,
                credential_id=order.credential_id,
                qr_token=order.qr_token,
            )

        event = await db.scalar(select(Event).where(Event.id == order.event_id))
        assert event is not None
        participant = await db.scalar(select(Participant).where(Participant.id == order.participant_id))
        assert participant is not None
        order_items = (await db.scalars(select(OrderItem).where(OrderItem.order_id == order.id))).all()

        base_url = str(request.base_url).rstrip("/")
        conf = await _get_gateway_config(db, event.tenant_id, event.id)
        full_name = pii_crypto.decrypt(participant.full_name_encrypted, aad=event.id)
        email = pii_crypto.decrypt(participant.email_encrypted, aad=event.id)

        order.payment_method = payload.payment_method

        if payload.payment_method == "MERCADOPAGO":
            mp_res = await MercadoPagoGateway.create_preference(
                order, event, list(order_items), full_name, email, conf, base_url
            )
            checkout_url = mp_res.get("checkout_url")
            order.checkout_url = checkout_url
            order.gateway_response_json = json.dumps(mp_res)
            await db.commit()
            return InitiatePaymentResponse(
                order_id=order.id,
                event_id=order.event_id,
                payment_method=payload.payment_method,
                status=order.status,
                total_cents=order.total_cents,
                checkout_url=checkout_url,
                init_point=mp_res.get("init_point"),
            )

        if payload.payment_method == "IZIPAY":
            iz_res = await IzipayGateway.create_payment_session(
                order, event, list(order_items), full_name, email, participant.dni_last4, conf, base_url
            )
            checkout_url = iz_res.get("checkout_url")
            order.checkout_url = checkout_url
            order.gateway_response_json = json.dumps(iz_res)
            await db.commit()
            return InitiatePaymentResponse(
                order_id=order.id,
                event_id=order.event_id,
                payment_method=payload.payment_method,
                status=order.status,
                total_cents=order.total_cents,
                checkout_url=checkout_url,
                form_token=iz_res.get("form_token"),
            )

        if payload.payment_method == "YAPE":
            yape_info = YapeGateway.generate_yape_details(order, event, conf)
            order.gateway_response_json = json.dumps(yape_info)
            await db.commit()
            return InitiatePaymentResponse(
                order_id=order.id,
                event_id=order.event_id,
                payment_method=payload.payment_method,
                status=order.status,
                total_cents=order.total_cents,
                yape_qr_data=yape_info["yape_qr_data"],
                yape_phone=yape_info["yape_phone"],
                yape_recipient=yape_info["yape_recipient"],
                reference_code=yape_info["reference_code"],
            )

        # DEMO Mode: instantly approve
        paid_res = await _complete_paid_order(db, order, f"DEMO-{order.id[:8].upper()}", "DEMO")
        return InitiatePaymentResponse(
            order_id=order.id,
            event_id=order.event_id,
            payment_method="DEMO",
            status="PAID",
            total_cents=order.total_cents,
            credential_id=paid_res.get("credential_id"),
            qr_token=paid_res.get("qr_token"),
        )

    @app.post("/api/v1/registration/orders/{order_id}/confirm-yape")
    async def confirm_yape_payment(
        order_id: str,
        payload: YapeConfirmRequest,
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, Any]:
        """Confirm a Yape transaction by submitting the operation number."""
        order = await db.scalar(select(Order).where(Order.id == order_id))
        if order is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found.")

        op_num = payload.operation_number.strip().upper()
        res = await _complete_paid_order(db, order, f"YAPE-OP-{op_num}", "YAPE")
        return {
            "ok": True,
            "order_id": order.id,
            "status": "PAID",
            "operation_number": op_num,
            "credential_id": res.get("credential_id"),
            "qr_token": res.get("qr_token"),
        }

    # -------------------------------------------------------------------------
    # Webhooks: Mercado Pago & Izipay
    # -------------------------------------------------------------------------
    @app.post("/api/v1/registration/webhooks/mercadopago")
    async def handle_mercadopago_webhook(
        request: Request,
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, Any]:
        """Handle Mercado Pago Webhook / IPN notifications."""
        body_bytes = await request.body()
        try:
            body = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except Exception:
            body = {}

        action = body.get("action") or body.get("type")
        data = body.get("data") or {}
        payment_id = str(data.get("id") or body.get("id") or "")

        # Mercado Pago sends payment notification
        if payment_id:
            # Look up order if external_reference is in notification
            ext_ref = body.get("external_reference") or data.get("external_reference")
            if ext_ref:
                order = await db.scalar(select(Order).where(Order.id == ext_ref))
                if order and order.status != "PAID":
                    await _complete_paid_order(db, order, f"MP-{payment_id}", "MERCADOPAGO")
                    return {"ok": True, "status": "processed", "order_id": order.id}

        return {"ok": True, "status": "received"}

    @app.post("/api/v1/registration/webhooks/izipay")
    async def handle_izipay_webhook(
        request: Request,
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, Any]:
        """Handle Izipay IPN notifications."""
        body_bytes = await request.body()
        try:
            body = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except Exception:
            body = {}

        kr_answer = body.get("kr-answer", {})
        order_details = kr_answer.get("orderDetails", {})
        order_id = order_details.get("orderId")
        order_status = kr_answer.get("orderStatus")

        if order_id and order_status == "PAID":
            order = await db.scalar(select(Order).where(Order.id == order_id))
            if order and order.status != "PAID":
                trans = kr_answer.get("transactions", [{}])[0]
                tx_uuid = trans.get("uuid") or f"IZI-{int(datetime.now(timezone.utc).timestamp())}"
                await _complete_paid_order(db, order, f"IZIPAY-{tx_uuid}", "IZIPAY")
                return {"ok": True, "status": "processed", "order_id": order.id}

        return {"ok": True, "status": "received"}

    @app.post("/api/v1/registration/webhooks/payment")
    async def handle_payment_webhook(
        request: Request,
        x_webhook_signature: str | None = Header(default=None),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, str | None]:
        raw_body = await request.body()
        if not x_webhook_signature or not verify_webhook_signature(
            raw_body, x_webhook_signature, cfg.payment_webhook_secret
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid payment webhook HMAC signature.",
            )

        payload = PaymentWebhookPayload.model_validate_json(raw_body)
        order = await db.scalar(select(Order).where(Order.id == payload.order_id))
        if order is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found.")

        if order.status == "PAID":
            return {
                "order_id": order.id,
                "status": order.status,
                "credential_id": order.credential_id,
                "qr_token": order.qr_token,
            }

        order_items = (await db.scalars(select(OrderItem).where(OrderItem.order_id == order.id))).all()
        if payload.status == "FAILED":
            if order.status == "PENDING":
                order.status = "FAILED"
                for oi in order_items:
                    await db.execute(
                        update(CatalogItem)
                        .where(CatalogItem.id == oi.catalog_item_id)
                        .values(stock_reserved=CatalogItem.stock_reserved - oi.quantity)
                    )
                await db.commit()
            return {"order_id": order.id, "status": order.status, "credential_id": None, "qr_token": None}

        return await _complete_paid_order(db, order, payload.payment_reference)

    @app.get("/api/v1/registration/orders/{order_id}", response_model=OrderResponse)
    async def get_order_by_dni(
        order_id: str,
        dni: str = Query(..., min_length=6, max_length=20),
        db: AsyncSession = Depends(get_db),
    ) -> OrderResponse:
        order = await db.scalar(select(Order).where(Order.id == order_id))
        if order is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found.")
        expected_idx = pii_crypto.blind_index_dni(order.tenant_id, order.event_id, dni)
        if expected_idx != order.dni_blind_index:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="DNI mismatch for order.")
        return OrderResponse(
            order_id=order.id,
            event_id=order.event_id,
            tenant_id=order.tenant_id,
            status=order.status,
            total_cents=order.total_cents,
            dni_last4=mask_dni(dni),
            expires_at=order.expires_at,
            checkout_url=f"/checkout/{order.id}",
            credential_id=order.credential_id,
            qr_token=order.qr_token,
        )

    # ------------------------------------------------------------------
    # RR.PP. Promoters & Courtesy Code Batches
    # ------------------------------------------------------------------
    @app.post(
        "/api/v1/registration/events/{event_id}/promoters",
        response_model=PromoterStatsResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def create_promoter(
        event_id: str,
        payload: CreatePromoterRequest,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> PromoterStatsResponse:
        event = await _resolve_event(event_id, actor, db)
        clean_prefix = payload.code_prefix.strip().upper()
        existing = await db.scalar(
            select(Promoter).where(Promoter.event_id == event_id, Promoter.code_prefix == clean_prefix)
        )
        if existing is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Promoter prefix already exists.")

        prom = Promoter(
            tenant_id=event.tenant_id,
            event_id=event.id,
            name=payload.name.strip(),
            code_prefix=clean_prefix,
            email=payload.email.lower().strip(),
            is_active=True,
        )
        db.add(prom)
        await db.commit()
        return PromoterStatsResponse(
            id=prom.id,
            name=prom.name,
            code_prefix=prom.code_prefix,
            email=prom.email,
            codes_total=0,
            codes_redeemed=0,
            orders_paid=0,
            revenue_cents=0,
            is_active=True,
        )

    @app.patch("/api/v1/registration/promoters/{promoter_id}", response_model=PromoterStatsResponse)
    async def update_promoter(
        promoter_id: str,
        payload: UpdatePromoterRequest,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> PromoterStatsResponse:
        prom = await db.scalar(
            select(Promoter).where(Promoter.id == promoter_id, Promoter.tenant_id == actor.tenant_id)
        )
        if prom is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Promoter not found.")
        if payload.name is not None and payload.name.strip():
            prom.name = payload.name.strip()
        if payload.email is not None and payload.email.strip():
            prom.email = payload.email.lower().strip()
        if payload.code_prefix is not None and payload.code_prefix.strip():
            clean_prefix = payload.code_prefix.strip().upper()
            if clean_prefix != prom.code_prefix:
                existing = await db.scalar(
                    select(Promoter).where(
                        Promoter.event_id == prom.event_id,
                        Promoter.code_prefix == clean_prefix,
                        Promoter.id != prom.id,
                    )
                )
                if existing is not None:
                    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Prefix already in use.")
                prom.code_prefix = clean_prefix
        if payload.is_active is not None:
            prom.is_active = payload.is_active
        await db.commit()

        codes_total = await db.scalar(select(func.count(CourtesyCode.id)).where(CourtesyCode.promoter_id == prom.id))
        codes_redeemed = await db.scalar(
            select(func.count(CourtesyCode.id)).where(
                CourtesyCode.promoter_id == prom.id, CourtesyCode.status == "REDEEMED"
            )
        )
        orders_paid = await db.scalar(
            select(func.count(Order.id)).where(Order.promoter_id == prom.id, Order.status == "PAID")
        )
        rev = await db.scalar(
            select(func.coalesce(func.sum(Order.total_cents), 0)).where(
                Order.promoter_id == prom.id, Order.status == "PAID"
            )
        )
        return PromoterStatsResponse(
            id=prom.id,
            name=prom.name,
            code_prefix=prom.code_prefix,
            email=prom.email,
            codes_total=int(codes_total or 0),
            codes_redeemed=int(codes_redeemed or 0),
            orders_paid=int(orders_paid or 0),
            revenue_cents=int(rev or 0),
            is_active=bool(prom.is_active),
        )

    @app.delete("/api/v1/registration/promoters/{promoter_id}")
    async def delete_promoter(
        promoter_id: str,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, str]:
        prom = await db.scalar(
            select(Promoter).where(Promoter.id == promoter_id, Promoter.tenant_id == actor.tenant_id)
        )
        if prom is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Promoter not found.")
        redeemed = await db.scalar(
            select(func.count(CourtesyCode.id)).where(
                CourtesyCode.promoter_id == prom.id, CourtesyCode.status == "REDEEMED"
            )
        )
        if redeemed and redeemed > 0:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"No se puede eliminar el promotor porque ya tiene {redeemed} código(s) canjeado(s). Puedes desactivarlo.",
            )
        await db.execute(delete(CourtesyCode).where(CourtesyCode.promoter_id == prom.id))
        await db.delete(prom)
        await db.commit()
        return {"status": "deleted", "promoter_id": promoter_id}

    @app.get("/api/v1/registration/events/{event_id}/promoters", response_model=list[PromoterStatsResponse])
    async def list_promoters(
        event_id: str,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> list[PromoterStatsResponse]:
        event = await _resolve_event(event_id, actor, db)
        proms = (
            await db.scalars(
                select(Promoter).where(Promoter.event_id == event.id)
            )
        ).all()
        out: list[PromoterStatsResponse] = []
        for p in proms:
            codes_total = await db.scalar(
                select(func.count(CourtesyCode.id)).where(CourtesyCode.promoter_id == p.id)
            )
            codes_redeemed = await db.scalar(
                select(func.count(CourtesyCode.id)).where(
                    CourtesyCode.promoter_id == p.id, CourtesyCode.status == "REDEEMED"
                )
            )
            orders_paid = await db.scalar(
                select(func.count(Order.id)).where(Order.promoter_id == p.id, Order.status == "PAID")
            )
            rev = await db.scalar(
                select(func.coalesce(func.sum(Order.total_cents), 0)).where(
                    Order.promoter_id == p.id, Order.status == "PAID"
                )
            )
            out.append(
                PromoterStatsResponse(
                    id=p.id,
                    name=p.name,
                    code_prefix=p.code_prefix,
                    email=p.email,
                    codes_total=int(codes_total or 0),
                    codes_redeemed=int(codes_redeemed or 0),
                    orders_paid=int(orders_paid or 0),
                    revenue_cents=int(rev or 0),
                    is_active=bool(p.is_active),
                )
            )
        return out

    @app.post(
        "/api/v1/registration/events/{event_id}/codes/batch",
        response_model=list[CourtesyCodeResponse],
        status_code=status.HTTP_201_CREATED,
    )
    async def create_courtesy_code_batch(
        event_id: str,
        payload: CreateCodeBatchRequest,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> list[CourtesyCodeResponse]:
        event = await _resolve_event(event_id, actor, db)
        item = await db.scalar(
            select(CatalogItem).where(CatalogItem.id == payload.catalog_item_id, CatalogItem.event_id == event_id)
        )
        if item is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Catalog item not found.")

        prefix = "CORT"
        prom_name = ""
        if payload.promoter_id:
            prom = await db.scalar(
                select(Promoter).where(Promoter.id == payload.promoter_id, Promoter.event_id == event_id)
            )
            if prom is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Promoter not found.")
            prefix = prom.code_prefix
            prom_name = prom.name

        now = datetime.now(timezone.utc)
        expires_at = payload.expires_at
        if expires_at is None and payload.validity_hours is not None:
            expires_at = now + timedelta(hours=payload.validity_hours)

        created: list[CourtesyCode] = []
        for _ in range(payload.quantity):
            code_str = f"{prefix}-{secrets.token_hex(3).upper()}"
            c = CourtesyCode(
                tenant_id=actor.tenant_id,
                event_id=event_id,
                catalog_item_id=item.id,
                promoter_id=payload.promoter_id,
                code=code_str,
                valid_day=payload.valid_day or "",
                expires_at=expires_at,
            )
            db.add(c)
            created.append(c)
        await db.commit()
        return [
            CourtesyCodeResponse(
                id=c.id,
                code=c.code,
                catalog_item_id=c.catalog_item_id,
                item_name=item.name,
                promoter_id=c.promoter_id,
                promoter_name=prom_name or None,
                valid_day=c.valid_day or None,
                expires_at=c.expires_at,
                status=c.status,
                redeemed_at=c.redeemed_at,
            )
            for c in created
        ]

    @app.get("/api/v1/registration/events/{event_id}/codes", response_model=list[CourtesyCodeResponse])
    async def list_courtesy_codes(
        event_id: str,
        promoter_id: str | None = Query(None),
        code_status: str | None = Query(None, alias="status"),
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> list[CourtesyCodeResponse]:
        stmt = (
            select(CourtesyCode, CatalogItem.name, Promoter.name)
            .join(CatalogItem, CourtesyCode.catalog_item_id == CatalogItem.id)
            .outerjoin(Promoter, CourtesyCode.promoter_id == Promoter.id)
            .where(CourtesyCode.event_id == event_id, CourtesyCode.tenant_id == actor.tenant_id)
        )
        if promoter_id:
            stmt = stmt.where(CourtesyCode.promoter_id == promoter_id)
        if code_status:
            stmt = stmt.where(CourtesyCode.status == code_status)
        stmt = stmt.order_by(CourtesyCode.created_at.desc()).limit(300)
        rows = (await db.execute(stmt)).all()
        return [
            CourtesyCodeResponse(
                id=c.id,
                code=c.code,
                catalog_item_id=c.catalog_item_id,
                item_name=item_name or "",
                promoter_id=c.promoter_id,
                promoter_name=p_name or None,
                valid_day=c.valid_day or None,
                expires_at=c.expires_at,
                status=c.status,
                redeemed_at=c.redeemed_at,
            )
            for c, item_name, p_name in rows
        ]

    @app.patch("/api/v1/registration/codes/{code_id}", response_model=CourtesyCodeResponse)
    async def update_courtesy_code(
        code_id: str,
        payload: UpdateCourtesyCodeRequest,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> CourtesyCodeResponse:
        c = await db.scalar(
            select(CourtesyCode).where(CourtesyCode.id == code_id, CourtesyCode.tenant_id == actor.tenant_id)
        )
        if c is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Courtesy code not found.")
        if payload.status is not None:
            c.status = payload.status
        if payload.valid_day is not None:
            c.valid_day = payload.valid_day.strip()
        if payload.expires_at is not None:
            c.expires_at = payload.expires_at
        await db.commit()
        item = await db.scalar(select(CatalogItem).where(CatalogItem.id == c.catalog_item_id))
        prom = await db.scalar(select(Promoter).where(Promoter.id == c.promoter_id)) if c.promoter_id else None
        return CourtesyCodeResponse(
            id=c.id,
            code=c.code,
            catalog_item_id=c.catalog_item_id,
            item_name=item.name if item else "",
            promoter_id=c.promoter_id,
            promoter_name=prom.name if prom else None,
            valid_day=c.valid_day or None,
            expires_at=c.expires_at,
            status=c.status,
            redeemed_at=c.redeemed_at,
        )

    @app.delete("/api/v1/registration/codes/{code_id}")
    async def delete_courtesy_code(
        code_id: str,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, str]:
        c = await db.scalar(
            select(CourtesyCode).where(CourtesyCode.id == code_id, CourtesyCode.tenant_id == actor.tenant_id)
        )
        if c is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Courtesy code not found.")
        if c.status == "REDEEMED":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="No se puede eliminar un código ya canjeado; el ticket ya fue emitido.",
            )
        await db.delete(c)
        await db.commit()
        return {"status": "deleted", "code_id": code_id}

    @app.post("/api/v1/registration/public/redeem-code")
    async def redeem_courtesy_code(
        payload: RedeemCodeRequest,
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, Any]:
        """Redeem a unique courtesy / RR.PP. code into a nominative DNI-linked QR pass."""
        event = await db.scalar(select(Event).where(Event.id == payload.event_id, Event.is_active.is_(True)))
        if event is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active event not found.")
        cc = await db.scalar(
            select(CourtesyCode).where(CourtesyCode.event_id == event.id, CourtesyCode.code == payload.code.upper())
        )
        if cc is None or cc.status != "AVAILABLE":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Code invalid or already redeemed.")

        now = datetime.now(timezone.utc)
        if cc.expires_at is not None:
            exp = cc.expires_at if cc.expires_at.tzinfo else cc.expires_at.replace(tzinfo=timezone.utc)
            if exp < now:
                cc.status = "EXPIRED"
                await db.commit()
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="El código de cortesía ha expirado.")

        item = await db.scalar(select(CatalogItem).where(CatalogItem.id == cc.catalog_item_id))
        assert item is not None

        order, cred_id, qr_token = await _issue_complimentary_pass(
            db,
            event=event,
            catalog_item=item,
            raw_dni=payload.dni,
            full_name=payload.full_name,
            email=payload.email,
            source="CODE",
            promoter_id=cc.promoter_id,
            enforce_dni_limit=True,
        )
        cc.status = "REDEEMED"
        cc.redeemed_by_dni_idx = order.dni_blind_index
        cc.order_id = order.id
        cc.credential_id = cred_id
        cc.redeemed_at = now
        await db.commit()
        return {
            "status": "REDEEMED",
            "order_id": order.id,
            "credential_id": cred_id,
            "qr_token": qr_token,
            "item_name": item.name,
            "event_name": event.name,
        }

    # ------------------------------------------------------------------
    # Physical / Thermal Tickets Batches
    # ------------------------------------------------------------------
    @app.post(
        "/api/v1/registration/events/{event_id}/physical-tickets/batches",
        response_model=PhysicalBatchResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def create_physical_ticket_batch(
        event_id: str,
        payload: CreatePhysicalBatchRequest,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> PhysicalBatchResponse:
        event = await _resolve_event(event_id, actor, db)
        item = await db.scalar(
            select(CatalogItem).where(CatalogItem.id == payload.catalog_item_id, CatalogItem.event_id == event_id)
        )
        if item is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Catalog item not found.")

        avail = item.stock_total - item.stock_reserved - item.stock_sold
        if avail < payload.quantity:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Stock disponible insuficiente ({avail} restantes, solicitados {payload.quantity}).",
            )

        item.stock_sold += payload.quantity
        end_seq = payload.start_sequence + payload.quantity - 1
        batch = PhysicalTicketBatch(
            tenant_id=actor.tenant_id,
            event_id=event.id,
            catalog_item_id=item.id,
            batch_name=payload.batch_name.strip(),
            quantity=payload.quantity,
            prefix=payload.prefix.strip().upper(),
            start_sequence=payload.start_sequence,
            end_sequence=end_seq,
            paper_width=payload.paper_width,
        )
        db.add(batch)
        await db.flush()

        batch_entitlements = {item.code: 1}
        if item.item_type == "ENTRY" and item.code != "ENTRY":
            batch_entitlements["ENTRY"] = 1
        elif item.interaction_type and item.code != item.interaction_type:
            batch_entitlements[item.interaction_type] = 1

        for seq in range(payload.start_sequence, end_seq + 1):
            t_num = f"{batch.prefix}-{seq:04d}"
            ticket_id = str(uuid.uuid4())
            cid, qr_tok = await _issue_participant_qr(
                event=event,
                display_name=f"Entrada Física #{t_num}",
                dni_last4="----",
                holder_ref_id=ticket_id,
                order_id=None,
                entitlements=batch_entitlements,
            )
            pt = PhysicalTicket(
                id=ticket_id,
                batch_id=batch.id,
                tenant_id=actor.tenant_id,
                event_id=event.id,
                catalog_item_id=item.id,
                sequence_number=seq,
                ticket_number=t_num,
                credential_id=cid,
                qr_token=qr_tok,
                status="ISSUED",
            )
            db.add(pt)

        await db.commit()
        return PhysicalBatchResponse(
            id=batch.id,
            event_id=batch.event_id,
            catalog_item_id=batch.catalog_item_id,
            batch_name=batch.batch_name,
            quantity=batch.quantity,
            prefix=batch.prefix,
            start_sequence=batch.start_sequence,
            end_sequence=batch.end_sequence,
            paper_width=batch.paper_width,
            created_at=batch.created_at,
        )

    @app.get(
        "/api/v1/registration/events/{event_id}/physical-tickets/batches",
        response_model=list[PhysicalBatchResponse],
    )
    async def list_physical_ticket_batches(
        event_id: str,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> list[PhysicalBatchResponse]:
        event = await _resolve_event(event_id, actor, db)
        batches = (
            await db.scalars(
                select(PhysicalTicketBatch)
                .where(PhysicalTicketBatch.event_id == event.id, PhysicalTicketBatch.tenant_id == actor.tenant_id)
                .order_by(PhysicalTicketBatch.created_at.desc())
            )
        ).all()
        return [
            PhysicalBatchResponse(
                id=b.id,
                event_id=b.event_id,
                catalog_item_id=b.catalog_item_id,
                batch_name=b.batch_name,
                quantity=b.quantity,
                prefix=b.prefix,
                start_sequence=b.start_sequence,
                end_sequence=b.end_sequence,
                paper_width=b.paper_width,
                created_at=b.created_at,
            )
            for b in batches
        ]

    @app.get(
        "/api/v1/registration/physical-tickets/batches/{batch_id}",
        response_model=PhysicalBatchDetailResponse,
    )
    async def get_physical_ticket_batch(
        batch_id: str,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> PhysicalBatchDetailResponse:
        batch = await db.scalar(
            select(PhysicalTicketBatch).where(
                PhysicalTicketBatch.id == batch_id, PhysicalTicketBatch.tenant_id == actor.tenant_id
            )
        )
        if batch is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Batch not found.")
        event = await db.scalar(select(Event).where(Event.id == batch.event_id))
        item = await db.scalar(select(CatalogItem).where(CatalogItem.id == batch.catalog_item_id))
        assert event is not None and item is not None

        tickets = (
            await db.scalars(
                select(PhysicalTicket)
                .where(PhysicalTicket.batch_id == batch.id)
                .order_by(PhysicalTicket.sequence_number.asc())
            )
        ).all()

        t_res = [
            PhysicalTicketResponse(
                id=t.id,
                sequence_number=t.sequence_number,
                ticket_number=t.ticket_number,
                credential_id=t.credential_id,
                qr_token=t.qr_token,
                status=t.status,
                item_name=item.name,
                item_code=item.code,
                price_cents=item.price_cents,
            )
            for t in tickets
        ]

        return PhysicalBatchDetailResponse(
            id=batch.id,
            event_id=batch.event_id,
            catalog_item_id=batch.catalog_item_id,
            batch_name=batch.batch_name,
            quantity=batch.quantity,
            prefix=batch.prefix,
            start_sequence=batch.start_sequence,
            end_sequence=batch.end_sequence,
            paper_width=batch.paper_width,
            created_at=batch.created_at,
            event_name=event.name,
            venue=event.venue,
            venue_address=event.venue_address,
            starts_at=event.starts_at,
            item_name=item.name,
            price_cents=item.price_cents,
            tickets=t_res,
        )

    @app.delete("/api/v1/registration/physical-tickets/batches/{batch_id}")
    async def delete_physical_ticket_batch(
        batch_id: str,
        actor: CurrentActor = Depends(require_admin),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, str]:
        batch = await db.scalar(
            select(PhysicalTicketBatch).where(
                PhysicalTicketBatch.id == batch_id, PhysicalTicketBatch.tenant_id == actor.tenant_id
            )
        )
        if batch is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Batch not found.")

        item = await db.scalar(select(CatalogItem).where(CatalogItem.id == batch.catalog_item_id))
        if item is not None:
            item.stock_sold = max(0, item.stock_sold - batch.quantity)

        await db.execute(delete(PhysicalTicket).where(PhysicalTicket.batch_id == batch.id))
        await db.delete(batch)
        await db.commit()
        return {"status": "deleted", "batch_id": batch_id}

    # ------------------------------------------------------------------
    # SMTP / Custom Email Configuration Per Tenant
    # ------------------------------------------------------------------
    @app.get("/api/v1/registration/email-config", response_model=TenantEmailConfigResponse)
    async def get_email_config(
        actor: CurrentActor = Depends(require_admin_or_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> TenantEmailConfigResponse:
        row = await db.scalar(select(TenantEmailConfig).where(TenantEmailConfig.tenant_id == actor.tenant_id))
        if row is None:
            return TenantEmailConfigResponse(
                tenant_id=actor.tenant_id,
                smtp_enabled=bool(cfg.smtp_host),
                smtp_host=cfg.smtp_host or "",
                smtp_port=cfg.smtp_port or 587,
                smtp_user=cfg.smtp_user or "",
                smtp_from_email=cfg.smtp_from_email or "tickets@eventpass.pe",
                smtp_from_name=cfg.smtp_from_name or "EventPass Tickets",
                smtp_use_tls=cfg.smtp_use_tls,
                smtp_use_ssl=cfg.smtp_use_ssl,
                has_password=bool(cfg.smtp_password),
            )
        return TenantEmailConfigResponse(
            tenant_id=row.tenant_id,
            smtp_enabled=row.smtp_enabled,
            smtp_host=row.smtp_host,
            smtp_port=row.smtp_port,
            smtp_user=row.smtp_user,
            smtp_from_email=row.smtp_from_email,
            smtp_from_name=row.smtp_from_name,
            smtp_use_tls=row.smtp_use_tls,
            smtp_use_ssl=row.smtp_use_ssl,
            has_password=bool(row.smtp_password_encrypted),
        )

    @app.put("/api/v1/registration/email-config", response_model=TenantEmailConfigResponse)
    async def update_email_config(
        payload: TenantEmailConfigRequest,
        actor: CurrentActor = Depends(require_admin_or_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> TenantEmailConfigResponse:
        row = await db.scalar(select(TenantEmailConfig).where(TenantEmailConfig.tenant_id == actor.tenant_id))
        if row is None:
            row = TenantEmailConfig(tenant_id=actor.tenant_id)
            db.add(row)

        row.smtp_enabled = payload.smtp_enabled
        row.smtp_host = payload.smtp_host.strip()
        row.smtp_port = payload.smtp_port
        row.smtp_user = payload.smtp_user.strip()
        row.smtp_from_email = payload.smtp_from_email.strip()
        row.smtp_from_name = payload.smtp_from_name.strip()
        row.smtp_use_tls = payload.smtp_use_tls
        row.smtp_use_ssl = payload.smtp_use_ssl
        if payload.smtp_password is not None and payload.smtp_password != "":
            row.smtp_password_encrypted = pii_crypto.encrypt(payload.smtp_password, aad="smtp")
        await db.commit()
        return TenantEmailConfigResponse(
            tenant_id=row.tenant_id,
            smtp_enabled=row.smtp_enabled,
            smtp_host=row.smtp_host,
            smtp_port=row.smtp_port,
            smtp_user=row.smtp_user,
            smtp_from_email=row.smtp_from_email,
            smtp_from_name=row.smtp_from_name,
            smtp_use_tls=row.smtp_use_tls,
            smtp_use_ssl=row.smtp_use_ssl,
            has_password=bool(row.smtp_password_encrypted),
        )

    @app.post("/api/v1/registration/email-config/test")
    async def test_email_config(
        payload: TestEmailRequest,
        actor: CurrentActor = Depends(require_admin_or_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, Any]:
        mail_settings = await _get_tenant_email_settings(db, actor.tenant_id)
        test_html = """
        <div style="font-family:sans-serif;max-width:500px;margin:auto;padding:24px;border:1px solid #e2e8f0;border-radius:12px;">
            <h2 style="color:#8b5cf6;margin-top:0;">Prueba de Conexión SMTP Exitosa</h2>
            <p>Este es un correo de prueba enviado desde el panel de administración de <strong>EventPass SaaS</strong>.</p>
            <p style="font-size:13px;color:#64748b;">Tu configuración de correo saliente está funcionando correctamente.</p>
        </div>
        """
        res = await send_email_async(
            mail_settings,
            to_email=payload.recipient_email,
            subject="✅ Verificación de Conexión SMTP — EventPass SaaS",
            html_body=test_html,
        )
        return res

    # ------------------------------------------------------------------
    # Guest List (Public Request + 1-Click Approval -> QR)
    # ------------------------------------------------------------------
    @app.post(
        "/api/v1/registration/events/{event_id}/guest-list/request",
        response_model=GuestListEntryResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def request_guest_list(
        event_id: str,
        payload: GuestListSubmitRequest,
        db: AsyncSession = Depends(get_db),
    ) -> GuestListEntryResponse:
        event = await db.scalar(select(Event).where(Event.id == event_id, Event.is_active.is_(True)))
        if event is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active event not found.")
        item = await db.scalar(
            select(CatalogItem).where(CatalogItem.id == payload.catalog_item_id, CatalogItem.event_id == event_id)
        )
        if item is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Catalog item not found.")

        normalized_dni = normalize_dni(payload.dni)
        dni_last4 = mask_dni(normalized_dni)
        dni_idx = pii_crypto.blind_index_dni(event.tenant_id, event.id, normalized_dni)

        entry = GuestListEntry(
            tenant_id=event.tenant_id,
            event_id=event.id,
            catalog_item_id=item.id,
            promoter_id=payload.promoter_id,
            dni_blind_index=dni_idx,
            dni_encrypted=pii_crypto.encrypt(normalized_dni, aad=event.id),
            dni_last4=dni_last4,
            full_name_encrypted=pii_crypto.encrypt(payload.full_name, aad=event.id),
            display_name=payload.full_name,
            email_encrypted=pii_crypto.encrypt(payload.email.lower(), aad=event.id),
            note=payload.note,
        )
        db.add(entry)
        await db.commit()
        return GuestListEntryResponse(
            id=entry.id,
            event_id=entry.event_id,
            catalog_item_id=entry.catalog_item_id,
            display_name=entry.display_name,
            dni_last4=entry.dni_last4,
            note=entry.note,
            status=entry.status,
            credential_id=entry.credential_id,
            qr_token=entry.qr_token,
            created_at=entry.created_at,
        )

    @app.get("/api/v1/registration/events/{event_id}/guest-list", response_model=list[GuestListEntryResponse])
    async def list_guest_list(
        event_id: str,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> list[GuestListEntryResponse]:
        rows = (
            await db.scalars(
                select(GuestListEntry)
                .where(GuestListEntry.event_id == event_id, GuestListEntry.tenant_id == actor.tenant_id)
                .order_by(GuestListEntry.created_at.desc())
            )
        ).all()
        return [
            GuestListEntryResponse(
                id=r.id,
                event_id=r.event_id,
                catalog_item_id=r.catalog_item_id,
                display_name=r.display_name,
                dni_last4=r.dni_last4,
                note=r.note,
                status=r.status,
                credential_id=r.credential_id,
                qr_token=r.qr_token,
                created_at=r.created_at,
            )
            for r in rows
        ]

    @app.post("/api/v1/registration/guest-list/{entry_id}/decision", response_model=GuestListEntryResponse)
    async def decide_guest_list_entry(
        entry_id: str,
        payload: GuestListDecisionRequest,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> GuestListEntryResponse:
        entry = await db.scalar(
            select(GuestListEntry).where(GuestListEntry.id == entry_id, GuestListEntry.tenant_id == actor.tenant_id)
        )
        if entry is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Guest list entry not found.")
        if entry.status != "PENDING":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Entry already {entry.status}.")

        now = datetime.now(timezone.utc)
        if payload.decision == "REJECT":
            entry.status = "REJECTED"
            entry.reviewed_by = actor.user_id
            entry.reviewed_at = now
            await db.commit()
        else:
            event = await db.scalar(select(Event).where(Event.id == entry.event_id))
            item = await db.scalar(select(CatalogItem).where(CatalogItem.id == entry.catalog_item_id))
            assert event is not None and item is not None
            raw_dni = pii_crypto.decrypt(entry.dni_encrypted, aad=event.id)
            full_name = pii_crypto.decrypt(entry.full_name_encrypted, aad=event.id)
            email = pii_crypto.decrypt(entry.email_encrypted, aad=event.id)
            _, cred_id, qr_token = await _issue_complimentary_pass(
                db,
                event=event,
                catalog_item=item,
                raw_dni=raw_dni,
                full_name=full_name,
                email=email,
                source="GUESTLIST",
                promoter_id=entry.promoter_id,
                enforce_dni_limit=False,
            )
            entry.status = "APPROVED"
            entry.credential_id = cred_id
            entry.qr_token = qr_token
            entry.reviewed_by = actor.user_id
            entry.reviewed_at = now
            await db.commit()

        return GuestListEntryResponse(
            id=entry.id,
            event_id=entry.event_id,
            catalog_item_id=entry.catalog_item_id,
            display_name=entry.display_name,
            dni_last4=entry.dni_last4,
            note=entry.note,
            status=entry.status,
            credential_id=entry.credential_id,
            qr_token=entry.qr_token,
            created_at=entry.created_at,
        )

    # ------------------------------------------------------------------
    # Bulk Excel / CSV Imports in Background
    # ------------------------------------------------------------------
    @app.get("/api/v1/registration/bulk-template.xlsx")
    async def download_bulk_template() -> Response:
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Asistentes"
        ws.append(["dni", "full_name", "email", "item_code"])
        ws.append(["71112222", "Ejemplo Asistente 1", "asistente1@example.com", "ENTRY"])
        buf = io.BytesIO()
        wb.save(buf)
        return Response(
            content=buf.getvalue(),
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": 'attachment; filename="plantilla_envio_masivo.xlsx"'},
        )

    async def _run_bulk_job(job_id: str, event_id: str, rows: list[dict[str, str]]) -> None:
        async with session_factory() as db:
            job = await db.scalar(select(BulkDispatchJob).where(BulkDispatchJob.id == job_id))
            event = await db.scalar(select(Event).where(Event.id == event_id))
            if job is None or event is None:
                return
            job.status = "RUNNING"
            await db.commit()

            items = (await db.scalars(select(CatalogItem).where(CatalogItem.event_id == event_id))).all()
            item_by_code = {i.code.upper(): i for i in items}
            report: list[dict[str, Any]] = []

            for idx, r in enumerate(rows, start=1):
                code_key = (r.get("item_code") or "ENTRY").strip().upper()
                item = item_by_code.get(code_key)
                if item is None:
                    job.failed_rows += 1
                    report.append({"row": idx, "status": "FAILED", "reason": f"Unknown item_code '{code_key}'"})
                else:
                    try:
                        _, cred_id, _ = await _issue_complimentary_pass(
                            db,
                            event=event,
                            catalog_item=item,
                            raw_dni=r["dni"],
                            full_name=r["full_name"],
                            email=r["email"],
                            source="BULK",
                            enforce_dni_limit=False,
                        )
                        job.succeeded_rows += 1
                        report.append({"row": idx, "status": "SENT", "credential_id": cred_id})
                    except Exception as exc:
                        job.failed_rows += 1
                        report.append({"row": idx, "status": "FAILED", "reason": str(exc)})
                job.processed_rows += 1

            job.status = "COMPLETED"
            job.report_json = json.dumps(report[:200])
            job.completed_at = datetime.now(timezone.utc)
            await db.commit()

    @app.post("/api/v1/registration/events/{event_id}/bulk-import", status_code=status.HTTP_202_ACCEPTED)
    async def upload_bulk_import(
        event_id: str,
        background_tasks: BackgroundTasks,
        file: UploadFile = File(...),
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, Any]:
        event = await _resolve_event(event_id, actor, db)

        content = await file.read()
        fname = (file.filename or "import.csv").lower()
        parsed_rows: list[dict[str, str]] = []

        if fname.endswith(".xlsx"):
            wb = openpyxl.load_workbook(io.BytesIO(content), read_only=True)
            ws = wb.active
            rows_iter = ws.iter_rows(values_only=True)
            headers = [str(h or "").strip().lower() for h in next(rows_iter, [])]
            for vals in rows_iter:
                if not vals or not any(vals):
                    continue
                row_dict = {headers[i]: str(vals[i] or "").strip() for i in range(min(len(headers), len(vals)))}
                if row_dict.get("dni") and row_dict.get("full_name"):
                    parsed_rows.append(
                        {
                            "dni": row_dict["dni"],
                            "full_name": row_dict["full_name"],
                            "email": row_dict.get("email") or "sin-correo@eventpass.local",
                            "item_code": row_dict.get("item_code") or "ENTRY",
                        }
                    )
        else:
            text_stream = io.StringIO(content.decode("utf-8-sig"))
            reader = csv.DictReader(text_stream)
            for r in reader:
                norm = {k.strip().lower(): (v or "").strip() for k, v in r.items() if k}
                if norm.get("dni") and norm.get("full_name"):
                    parsed_rows.append(
                        {
                            "dni": norm["dni"],
                            "full_name": norm["full_name"],
                            "email": norm.get("email") or "sin-correo@eventpass.local",
                            "item_code": norm.get("item_code") or "ENTRY",
                        }
                    )

        if not parsed_rows:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No valid rows found in file.")

        job = BulkDispatchJob(
            tenant_id=actor.tenant_id,
            event_id=event.id,
            filename=file.filename or "import",
            total_rows=len(parsed_rows),
            status="QUEUED",
            created_by=actor.user_id,
        )
        db.add(job)
        await db.commit()
        background_tasks.add_task(_run_bulk_job, job.id, event.id, parsed_rows)
        return {"job_id": job.id, "total_rows": job.total_rows, "status": job.status}

    @app.get("/api/v1/registration/events/{event_id}/bulk-jobs")
    async def list_bulk_jobs(
        event_id: str,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> list[dict[str, Any]]:
        event = await _resolve_event(event_id, actor, db)
        rows = (
            await db.scalars(
                select(BulkDispatchJob)
                .where(BulkDispatchJob.event_id == event.id)
                .order_by(BulkDispatchJob.created_at.desc())
            )
        ).all()
        return [
            {
                "id": j.id,
                "filename": j.filename,
                "total_rows": j.total_rows,
                "processed_rows": j.processed_rows,
                "succeeded_rows": j.succeeded_rows,
                "failed_rows": j.failed_rows,
                "status": j.status,
                "report": json.loads(j.report_json),
                "created_at": j.created_at.isoformat(),
            }
            for j in rows
        ]

    # ------------------------------------------------------------------
    # Full Analytics Metrics & Excel (.xlsx) Export
    # ------------------------------------------------------------------
    async def _build_event_metrics(db: AsyncSession, event: Event) -> dict[str, Any]:
        orders = (await db.scalars(select(Order).where(Order.event_id == event.id))).all()
        items = (await db.scalars(select(CatalogItem).where(CatalogItem.event_id == event.id))).all()
        codes = (await db.scalars(select(CourtesyCode).where(CourtesyCode.event_id == event.id))).all()
        guests = (await db.scalars(select(GuestListEntry).where(GuestListEntry.event_id == event.id))).all()
        proms = (await db.scalars(select(Promoter).where(Promoter.event_id == event.id))).all()

        paid_orders = [o for o in orders if o.status == "PAID"]
        pending_orders = [o for o in orders if o.status == "PENDING"]
        revenue_cents = sum(o.total_cents for o in paid_orders)

        by_source: dict[str, int] = defaultdict(int)
        by_hour: dict[str, dict[str, int]] = defaultdict(lambda: {"orders": 0, "revenue_cents": 0})
        for o in paid_orders:
            by_source[o.source] += 1
            hour_label = _as_utc(o.paid_at or o.created_at).strftime("%Y-%m-%d %H:00")
            by_hour[hour_label]["orders"] += 1
            by_hour[hour_label]["revenue_cents"] += o.total_cents

        items_breakdown = [
            {
                "code": i.code,
                "name": i.name,
                "item_type": i.item_type,
                "price_cents": i.price_cents,
                "stock_total": i.stock_total,
                "stock_sold": i.stock_sold,
                "stock_reserved": i.stock_reserved,
                "stock_available": max(0, i.stock_total - i.stock_reserved - i.stock_sold),
                "revenue_cents": i.stock_sold * i.price_cents,
            }
            for i in items
        ]

        promoter_stats = []
        for p in proms:
            p_codes = [c for c in codes if c.promoter_id == p.id]
            p_orders = [o for o in paid_orders if o.promoter_id == p.id]
            promoter_stats.append(
                {
                    "id": p.id,
                    "name": p.name,
                    "code_prefix": p.code_prefix,
                    "codes_total": len(p_codes),
                    "codes_redeemed": sum(1 for c in p_codes if c.status == "REDEEMED"),
                    "orders_paid": len(p_orders),
                    "revenue_cents": sum(o.total_cents for o in p_orders),
                }
            )

        return {
            "event_id": event.id,
            "event_name": event.name,
            "total_revenue_cents": revenue_cents,
            "orders_paid": len(paid_orders),
            "orders_pending": len(pending_orders),
            "tickets_sold": sum(i.stock_sold for i in items),
            "tickets_capacity": sum(i.stock_total for i in items),
            "orders_by_source": dict(by_source),
            "sales_timeline": [
                {"hour": k, "orders": v["orders"], "revenue_cents": v["revenue_cents"]}
                for k, v in sorted(by_hour.items())
            ],
            "items": items_breakdown,
            "courtesy_codes": {
                "total": len(codes),
                "redeemed": sum(1 for c in codes if c.status == "REDEEMED"),
                "available": sum(1 for c in codes if c.status == "AVAILABLE"),
            },
            "guest_list": {
                "total": len(guests),
                "pending": sum(1 for g in guests if g.status == "PENDING"),
                "approved": sum(1 for g in guests if g.status == "APPROVED"),
                "rejected": sum(1 for g in guests if g.status == "REJECTED"),
            },
            "promoters": promoter_stats,
        }

    @app.get("/api/v1/registration/events/{event_id}/metrics")
    async def get_event_metrics(
        event_id: str,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, Any]:
        event = await _resolve_event(event_id, actor, db)
        return await _build_event_metrics(db, event)

    @app.get("/api/v1/registration/events/{event_id}/metrics/export.xlsx")
    async def export_event_metrics_excel(
        event_id: str,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> Response:
        event = await _resolve_event(event_id, actor, db)
        m = await _build_event_metrics(db, event)

        wb = openpyxl.Workbook()
        ws_sum = wb.active
        ws_sum.title = "Resumen"
        ws_sum.append(["Métrica", "Valor"])
        ws_sum.append(["Evento", m["event_name"]])
        ws_sum.append(["Ingresos Totales", m["total_revenue_cents"] / 100.0])
        ws_sum.append(["Órdenes Pagadas", m["orders_paid"]])
        ws_sum.append(["Órdenes Pendientes", m["orders_pending"]])
        ws_sum.append(["Unidades Vendidas/Emitidas", m["tickets_sold"]])
        ws_sum.append(["Capacidad Total", m["tickets_capacity"]])
        ws_sum.append(["Cortesías Canjeadas", m["courtesy_codes"]["redeemed"]])
        ws_sum.append(["Guest List Aprobados", m["guest_list"]["approved"]])

        ws_items = wb.create_sheet("Entradas_Interacciones")
        ws_items.append(["Código", "Nombre", "Tipo", "Vendidos", "Disponibles", "Total", "Ingresos"])
        for it in m["items"]:
            ws_items.append(
                [it["code"], it["name"], it["item_type"], it["stock_sold"], it["stock_available"], it["stock_total"], it["revenue_cents"] / 100.0]
            )

        ws_rrpp = wb.create_sheet("Promotores_RRPP")
        ws_rrpp.append(["Promotor", "Prefijo", "Códigos Emitidos", "Códigos Canjeados", "Órdenes", "Ingresos"])
        for p in m["promoters"]:
            ws_rrpp.append(
                [p["name"], p["code_prefix"], p["codes_total"], p["codes_redeemed"], p["orders_paid"], p["revenue_cents"] / 100.0]
            )

        buf = io.BytesIO()
        wb.save(buf)
        return Response(
            content=buf.getvalue(),
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f'attachment; filename="metricas_{event.slug}.xlsx"'},
        )

    # ------------------------------------------------------------------
    # Peru Virtual Libro de Reclamaciones
    # ------------------------------------------------------------------
    @app.post("/api/v1/registration/public/complaints", status_code=status.HTTP_201_CREATED)
    async def submit_complaint(
        payload: ComplaintCreateRequest,
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, str]:
        normalized_dni = normalize_dni(payload.dni)
        dni_l4 = mask_dni(normalized_dni)
        code = f"LR-{datetime.now(timezone.utc).year}-{secrets.token_hex(3).upper()}"
        rec = ComplaintRecord(
            complaint_code=code,
            tenant_id=payload.tenant_id,
            event_id=payload.event_id,
            dni_last4=dni_l4,
            full_name_encrypted=pii_crypto.encrypt(payload.full_name, aad=code),
            email_encrypted=pii_crypto.encrypt(payload.email.lower(), aad=code),
            claim_type=payload.claim_type,
            detail=payload.detail,
        )
        db.add(rec)
        await db.commit()
        return {"complaint_code": code, "status": rec.status}

    @app.get("/api/v1/registration/complaints")
    async def list_complaints(
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> list[dict[str, Any]]:
        rows = (
            await db.scalars(
                select(ComplaintRecord)
                .where((ComplaintRecord.tenant_id == actor.tenant_id) | (ComplaintRecord.tenant_id.is_(None)))
                .order_by(ComplaintRecord.created_at.desc())
                .limit(100)
            )
        ).all()
        return [
            {
                "complaint_code": r.complaint_code,
                "claim_type": r.claim_type,
                "dni_last4": r.dni_last4,
                "detail": r.detail,
                "status": r.status,
                "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ]

    @app.get("/api/v1/registration/superadmin/overview")
    async def superadmin_registration_overview(
        actor: CurrentActor = Depends(require_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, Any]:
        """Cross-tenant event, revenue, and ticket sales summary for platform SuperAdmin."""
        events = (await db.scalars(select(Event).order_by(Event.created_at.desc()))).all()
        catalogs = (await db.scalars(select(CatalogItem))).all()
        paid_orders = (await db.scalars(select(Order).where(Order.status == "PAID"))).all()
        complaints_count = int((await db.scalar(select(func.count(ComplaintRecord.id)))) or 0)

        sold_by_event: dict[str, int] = defaultdict(int)
        cap_by_event: dict[str, int] = defaultdict(int)
        for item in catalogs:
            sold_by_event[item.event_id] += int(item.stock_sold or 0)
            cap_by_event[item.event_id] += int(item.stock_total or 0)

        orders_by_event: dict[str, int] = defaultdict(int)
        rev_by_event: dict[str, int] = defaultdict(int)
        for o in paid_orders:
            orders_by_event[o.event_id] += 1
            rev_by_event[o.event_id] += int(o.total_cents or 0)

        total_revenue_cents = sum(rev_by_event.values())
        total_tickets_sold = sum(sold_by_event.values())
        active_events = sum(1 for e in events if e.is_active)

        return {
            "total_events": len(events),
            "active_events": active_events,
            "total_orders_paid": len(paid_orders),
            "total_revenue_cents": total_revenue_cents,
            "total_tickets_sold": total_tickets_sold,
            "total_complaints": complaints_count,
            "events": [
                {
                    "id": e.id,
                    "tenant_id": e.tenant_id,
                    "name": e.name,
                    "slug": e.slug,
                    "venue": e.venue,
                    "is_active": e.is_active,
                    "max_purchases_per_dni": e.max_purchases_per_dni,
                    "orders_paid": orders_by_event[e.id],
                    "revenue_cents": rev_by_event[e.id],
                    "tickets_sold": sold_by_event[e.id],
                    "tickets_capacity": cap_by_event[e.id],
                    "starts_at": _as_utc(e.starts_at).isoformat(),
                }
                for e in events
            ],
        }

    @app.patch("/api/v1/registration/superadmin/events/{event_id}/status")
    async def superadmin_update_event_status(
        event_id: str,
        payload: dict[str, Any],
        actor: CurrentActor = Depends(require_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> EventResponse:
        """Pause or activate any tenant event from the SuperAdmin console."""
        event = await db.scalar(select(Event).where(Event.id == event_id))
        if event is None:
            raise HTTPException(status_code=404, detail="Evento no encontrado")
        if "is_active" not in payload or not isinstance(payload["is_active"], bool):
            raise HTTPException(status_code=422, detail="Campo booleano 'is_active' requerido")
        event.is_active = payload["is_active"]
        await db.commit()
        await db.refresh(event)
        await audit.record(
            tenant_id=event.tenant_id,
            service=cfg.service_name,
            action="SUPERADMIN_EVENT_STATUS_UPDATED",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="event",
            resource_id=event.id,
            metadata={"is_active": event.is_active},
        )
        return _event_to_response(event)

    async def _delete_event_cascade(db: AsyncSession, event_id: str) -> None:
        """Delete an event and all dependent records in safe FK order (OrderItem has RESTRICT)."""
        order_ids_sq = select(Order.id).where(Order.event_id == event_id)
        await db.execute(delete(OrderItem).where(OrderItem.order_id.in_(order_ids_sq)))
        await db.execute(delete(Order).where(Order.event_id == event_id))
        await db.execute(delete(CourtesyCode).where(CourtesyCode.event_id == event_id))
        await db.execute(delete(GuestListEntry).where(GuestListEntry.event_id == event_id))
        await db.execute(delete(BulkDispatchJob).where(BulkDispatchJob.event_id == event_id))
        await db.execute(delete(Promoter).where(Promoter.event_id == event_id))
        await db.execute(delete(Participant).where(Participant.event_id == event_id))
        await db.execute(delete(CatalogItem).where(CatalogItem.event_id == event_id))
        await db.execute(delete(ComplaintRecord).where(ComplaintRecord.event_id == event_id))
        await db.execute(delete(Event).where(Event.id == event_id))

    @app.get("/api/v1/registration/events/{event_id}/orders")
    async def list_event_orders(
        event_id: str,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> list[dict[str, Any]]:
        """List registered purchases/orders for an event (Admin/Supervisor)."""
        event = await _resolve_event(event_id, actor, db)
        orders = (
            await db.scalars(select(Order).where(Order.event_id == event.id).order_by(Order.created_at.desc()).limit(200))
        ).all()
        if not orders:
            return []
        part_ids = list({o.participant_id for o in orders})
        parts = (await db.scalars(select(Participant).where(Participant.id.in_(part_ids)))).all()
        part_map = {p.id: p for p in parts}
        order_ids = [o.id for o in orders]
        oitems = (await db.scalars(select(OrderItem).where(OrderItem.order_id.in_(order_ids)))).all()
        items_by_order: dict[str, list[str]] = defaultdict(list)
        for oi in oitems:
            items_by_order[oi.order_id].append(f"{oi.quantity}x {oi.item_code}")

        result: list[dict[str, Any]] = []
        for o in orders:
            p = part_map.get(o.participant_id)
            full_name = pii_crypto.decrypt(p.full_name_encrypted, aad=event.id) if p else "-"
            email = pii_crypto.decrypt(p.email_encrypted, aad=event.id) if p else "-"
            result.append(
                {
                    "order_id": o.id,
                    "full_name": full_name,
                    "email": email,
                    "dni_last4": p.dni_last4 if p else "----",
                    "items_summary": ", ".join(items_by_order.get(o.id, [])) or "-",
                    "total_cents": o.total_cents,
                    "payment_method": o.payment_method,
                    "source": o.source,
                    "status": o.status,
                    "created_at": _as_utc(o.created_at).isoformat(),
                    "paid_at": _as_utc(o.paid_at).isoformat() if o.paid_at else None,
                }
            )
        return result

    @app.patch("/api/v1/registration/orders/{order_id}")
    async def update_order(
        order_id: str,
        payload: UpdateOrderRequest,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, Any]:
        """Update buyer contact information, payment method, or payment status of an order."""
        order = await db.scalar(select(Order).where(Order.id == order_id))
        if not order:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Orden no encontrada")
        if actor.role != Role.SUPERADMIN and order.tenant_id != actor.tenant_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No autorizado para esta orden")

        event = await db.scalar(select(Event).where(Event.id == order.event_id))
        participant = await db.scalar(select(Participant).where(Participant.id == order.participant_id))
        if not event or not participant:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evento o participante no encontrado")

        if payload.full_name is not None and payload.full_name.strip():
            participant.full_name_encrypted = pii_crypto.encrypt(payload.full_name.strip(), aad=event.id)
        if payload.email is not None and payload.email.strip():
            participant.email_encrypted = pii_crypto.encrypt(payload.email.strip().lower(), aad=event.id)

        if payload.payment_method is not None and payload.payment_method.strip():
            order.payment_method = payload.payment_method.strip().upper()

        if payload.status is not None and payload.status.upper() != order.status:
            old_status = order.status
            new_status = payload.status.upper()
            oitems = (await db.scalars(select(OrderItem).where(OrderItem.order_id == order.id))).all()

            if old_status == "PENDING" and new_status == "PAID":
                for oi in oitems:
                    ci = await db.scalar(select(CatalogItem).where(CatalogItem.id == oi.catalog_item_id))
                    if ci:
                        ci.stock_reserved = max(0, ci.stock_reserved - oi.quantity)
                        ci.stock_sold += oi.quantity
                order.status = "PAID"
                order.paid_at = datetime.now(timezone.utc)
                if not order.credential_id:
                    entitlements = {oi.item_code: oi.quantity for oi in oitems}
                    for oi in oitems:
                        ci = await db.scalar(select(CatalogItem).where(CatalogItem.id == oi.catalog_item_id))
                        if ci and ci.item_type == "ENTRY" and oi.item_code != "ENTRY":
                            entitlements["ENTRY"] = entitlements.get("ENTRY", 0) + oi.quantity
                        elif ci and ci.interaction_type and oi.item_code != ci.interaction_type:
                            entitlements[ci.interaction_type] = entitlements.get(ci.interaction_type, 0) + oi.quantity
                    disp_name = pii_crypto.decrypt(participant.full_name_encrypted, aad=event.id)
                    cid, qr_tok = await _issue_participant_qr(
                        event, disp_name, participant.dni_last4, participant.id, order.id, entitlements
                    )
                    order.credential_id = cid
                    order.qr_token = qr_tok
            elif old_status == "PAID" and new_status in ("CANCELLED", "PENDING"):
                for oi in oitems:
                    ci = await db.scalar(select(CatalogItem).where(CatalogItem.id == oi.catalog_item_id))
                    if ci:
                        ci.stock_sold = max(0, ci.stock_sold - oi.quantity)
                        if new_status == "PENDING":
                            ci.stock_reserved += oi.quantity
                order.status = new_status
            elif old_status == "PENDING" and new_status == "CANCELLED":
                for oi in oitems:
                    ci = await db.scalar(select(CatalogItem).where(CatalogItem.id == oi.catalog_item_id))
                    if ci:
                        ci.stock_reserved = max(0, ci.stock_reserved - oi.quantity)
                order.status = "CANCELLED"

        await db.commit()
        return {"status": "ok", "order_id": order.id, "order_status": order.status}

    @app.delete("/api/v1/registration/orders/{order_id}")
    async def delete_order(
        order_id: str,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, str]:
        """Permanently delete a purchase order, restore catalog item stock, and revoke QR credential."""
        order = await db.scalar(select(Order).where(Order.id == order_id))
        if not order:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Orden no encontrada")
        if actor.role != Role.SUPERADMIN and order.tenant_id != actor.tenant_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No autorizado para esta orden")

        # Restore catalog item stock
        oitems = (await db.scalars(select(OrderItem).where(OrderItem.order_id == order.id))).all()
        for oi in oitems:
            citem = await db.scalar(select(CatalogItem).where(CatalogItem.id == oi.catalog_item_id))
            if citem:
                if order.status == "PAID":
                    citem.stock_sold = max(0, citem.stock_sold - oi.quantity)
                elif order.status == "PENDING":
                    citem.stock_reserved = max(0, citem.stock_reserved - oi.quantity)

        # Reset courtesy codes redeemed for this order
        courtesies = (await db.scalars(select(CourtesyCode).where(CourtesyCode.order_id == order.id))).all()
        for cc in courtesies:
            cc.status = "AVAILABLE"
            cc.redeemed_by_dni_idx = None
            cc.order_id = None
            cc.credential_id = None
            cc.redeemed_at = None

        # Revoke credential in accreditation service if present
        if order.credential_id:
            try:
                headers = {
                    "X-Internal-Service-Token": cfg.internal_service_token,
                    "Authorization": f"Bearer {cfg.internal_service_token}",
                }
                if accreditation_client_factory is not None:
                    async with accreditation_client_factory() as acc_cli:
                        await acc_cli.post(f"/api/v1/accreditation/credentials/{order.credential_id}/revoke", headers=headers, timeout=5.0)
                else:
                    async with httpx.AsyncClient(base_url=cfg.accreditation_service_url, timeout=5.0) as acc_cli:
                        await acc_cli.post(f"/api/v1/accreditation/credentials/{order.credential_id}/revoke", headers=headers)
            except Exception:
                pass

        part_id = order.participant_id
        event_id = order.event_id

        # Remove order items & order
        await db.execute(delete(OrderItem).where(OrderItem.order_id == order.id))
        await db.execute(delete(Order).where(Order.id == order.id))

        # Clean up participant if they have no remaining orders (allows testing with same DNI again)
        remaining_count = await db.scalar(
            select(func.count(Order.id)).where(Order.participant_id == part_id, Order.event_id == event_id)
        )
        if not remaining_count:
            await db.execute(delete(Participant).where(Participant.id == part_id))

        await db.commit()

        await audit.record(
            tenant_id=order.tenant_id,
            service=cfg.service_name,
            action="ORDER_DELETED",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="order",
            resource_id=order.id,
            metadata={"event_id": event_id, "restored_items": len(oitems)},
        )
        return {"status": "deleted", "order_id": order_id}

    @app.post("/api/v1/registration/orders/{order_id}/send-email")
    async def send_order_email(
        order_id: str,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, Any]:
        """Send or resend official purchase tickets with embedded branded QR code to the buyer email."""
        order = await db.scalar(select(Order).where(Order.id == order_id))
        if not order:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Orden no encontrada")
        if actor.role != Role.SUPERADMIN and order.tenant_id != actor.tenant_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No autorizado")

        event = await db.scalar(select(Event).where(Event.id == order.event_id))
        participant = await db.scalar(select(Participant).where(Participant.id == order.participant_id))
        if not event or not participant:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Datos de orden incompletos")

        order_items = (await db.scalars(select(OrderItem).where(OrderItem.order_id == order.id))).all()

        if not order.qr_token:
            entitlements = {oi.item_code: oi.quantity for oi in order_items}
            for oi in order_items:
                ci = await db.scalar(select(CatalogItem).where(CatalogItem.id == oi.catalog_item_id))
                if ci and ci.item_type == "ENTRY" and oi.item_code != "ENTRY":
                    entitlements["ENTRY"] = entitlements.get("ENTRY", 0) + oi.quantity
                elif ci and ci.interaction_type and oi.item_code != ci.interaction_type:
                    entitlements[ci.interaction_type] = entitlements.get(ci.interaction_type, 0) + oi.quantity
            display_name = pii_crypto.decrypt(participant.full_name_encrypted, aad=event.id)
            cid, qr_tok = await _issue_participant_qr(
                event, display_name, participant.dni_last4, participant.id, order.id, entitlements
            )
            order.credential_id = cid
            order.qr_token = qr_tok
            await db.commit()

        buyer_email = pii_crypto.decrypt(participant.email_encrypted, aad=event.id)
        buyer_name = pii_crypto.decrypt(participant.full_name_encrypted, aad=event.id)
        items_summary = ", ".join(f"{oi.quantity}x {oi.item_code}" for oi in order_items) or "Entrada General"
        total_soles = f"{(order.total_cents / 100):.2f}"
        starts_at_str = event.starts_at.strftime("%d/%m/%Y %H:%M") if event.starts_at else ""

        qr_bytes = generate_qr_with_logo(order.qr_token or "", brand_color=event.brand_color or "#8b5cf6")
        html = render_ticket_email_html(
            event_name=event.name,
            buyer_name=buyer_name,
            dni_last4=participant.dni_last4,
            order_id=order.id,
            items_summary=items_summary,
            total_soles=total_soles,
            venue=event.venue,
            venue_address=event.venue_address,
            starts_at_str=starts_at_str,
            brand_color=event.brand_color or "#8b5cf6",
        )
        subject = f"🎟️ Tus Entradas Oficiales — {event.name} [Orden {order.id[:8]}]"
        mail_cfg = await _get_tenant_email_settings(db, event.tenant_id)
        delivery_res = await send_email_async(mail_cfg, buyer_email, subject, html, qr_bytes)
        return {
            "status": "ok",
            "recipient": buyer_email,
            "delivery": delivery_res,
        }

    @app.delete("/api/v1/registration/events/{event_id}")
    async def delete_tenant_event(
        event_id: str,
        actor: CurrentActor = Depends(require_admin),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, str]:
        event = await _resolve_event(event_id, actor, db)
        await _delete_event_cascade(db, event.id)
        await db.commit()
        await audit.record(
            tenant_id=event.tenant_id,
            service=cfg.service_name,
            action="EVENT_DELETED",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="event",
            resource_id=event_id,
            metadata={"slug": event.slug},
        )
        return {"deleted": event_id}

    @app.delete("/api/v1/registration/superadmin/events/{event_id}")
    async def superadmin_delete_event(
        event_id: str,
        actor: CurrentActor = Depends(require_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, str]:
        event = await db.scalar(select(Event).where(Event.id == event_id))
        if event is None:
            raise HTTPException(status_code=404, detail="Evento no encontrado")
        tid = event.tenant_id
        slug = event.slug
        await _delete_event_cascade(db, event.id)
        await db.commit()
        await audit.record(
            tenant_id=tid,
            service=cfg.service_name,
            action="SUPERADMIN_EVENT_DELETED",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="event",
            resource_id=event_id,
            metadata={"slug": slug},
        )
        return {"deleted": event_id}

    @app.delete("/api/v1/registration/superadmin/tenants/{tenant_id}/events")
    async def superadmin_delete_tenant_events(
        tenant_id: str,
        actor: CurrentActor = Depends(require_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, int]:
        events = (await db.scalars(select(Event).where(Event.tenant_id == tenant_id))).all()
        for ev in events:
            await _delete_event_cascade(db, ev.id)
        await db.commit()
        return {"deleted_events": len(events)}

    return app


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(create_registration_app(), host="0.0.0.0", port=8002)
