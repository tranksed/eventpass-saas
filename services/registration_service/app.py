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
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
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
    Promoter,
)
from services.registration_service.schemas import (
    CatalogItemResponse,
    ComplaintCreateRequest,
    CourtesyCodeResponse,
    CreateCatalogItemRequest,
    CreateCodeBatchRequest,
    CreateEventRequest,
    CreateOrderRequest,
    CreatePromoterRequest,
    EventResponse,
    GuestListDecisionRequest,
    GuestListEntryResponse,
    GuestListSubmitRequest,
    ItemType,
    OrderResponse,
    PaymentWebhookPayload,
    PromoterStatsResponse,
    RedeemCodeRequest,
    UpdateEventLimitRequest,
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
        description=e.description,
        brand_color=e.brand_color,
        timezone_name=e.timezone_name,
        starts_at=e.starts_at,
        ends_at=e.ends_at,
        max_purchases_per_dni=e.max_purchases_per_dni,
        is_active=e.is_active,
    )


async def _ensure_schema_columns(conn) -> None:
    """Safely add newly introduced columns on existing dev SQLite/Postgres databases using SAVEPOINTs."""
    alter_statements = [
        "ALTER TABLE events ADD COLUMN venue VARCHAR(180) NOT NULL DEFAULT 'Centro de Convenciones, Lima'",
        "ALTER TABLE events ADD COLUMN description TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE events ADD COLUMN brand_color VARCHAR(20) NOT NULL DEFAULT '#8b5cf6'",
        "ALTER TABLE events ADD COLUMN timezone_name VARCHAR(60) NOT NULL DEFAULT 'America/Lima'",
        "ALTER TABLE orders ADD COLUMN source VARCHAR(30) NOT NULL DEFAULT 'ONLINE'",
        "ALTER TABLE orders ADD COLUMN promoter_id VARCHAR(36)",
        "ALTER TABLE orders ADD COLUMN payment_method VARCHAR(40) NOT NULL DEFAULT 'MERCADOPAGO'",
    ]
    for stmt in alter_statements:
        try:
            async with conn.begin_nested():
                await conn.execute(text(stmt))
        except Exception:
            # Column already exists; nested savepoint rollback preserves outer PostgreSQL transaction
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

            cred_id, qr_token = await _issue_participant_qr(
                event,
                full_name,
                dni_last4,
                participant.id,
                order.id,
                {catalog_item.code: 1},
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
            description=payload.description,
            brand_color=payload.brand_color,
            timezone_name=payload.timezone_name,
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

    @app.patch("/api/v1/registration/events/{event_id}/dni-limit", response_model=EventResponse)
    async def update_event_dni_limit(
        event_id: str,
        payload: UpdateEventLimitRequest,
        actor: CurrentActor = Depends(require_admin),
        db: AsyncSession = Depends(get_db),
    ) -> EventResponse:
        event = await db.scalar(select(Event).where(Event.id == event_id, Event.tenant_id == actor.tenant_id))
        if event is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found.")
        event.max_purchases_per_dni = payload.max_purchases_per_dni
        await db.commit()
        await audit.record(
            tenant_id=actor.tenant_id,
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
        event = await db.scalar(select(Event).where(Event.id == event_id, Event.tenant_id == actor.tenant_id))
        if event is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found.")

        existing = await db.scalar(
            select(CatalogItem).where(CatalogItem.event_id == event_id, CatalogItem.code == payload.code)
        )
        if existing is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Item code already exists in event.")

        item = CatalogItem(
            event_id=event.id,
            tenant_id=actor.tenant_id,
            code=payload.code,
            name=payload.name,
            item_type=payload.item_type.value,
            price_cents=payload.price_cents,
            stock_total=payload.stock_total,
        )
        db.add(item)
        await db.commit()
        return CatalogItemResponse(
            id=item.id,
            event_id=item.event_id,
            code=item.code,
            name=item.name,
            item_type=ItemType(item.item_type),
            price_cents=item.price_cents,
            stock_available=item.stock_total - item.stock_reserved - item.stock_sold,
        )

    @app.get("/api/v1/registration/events/{event_id}/items", response_model=list[CatalogItemResponse])
    async def list_public_catalog_items(event_id: str, db: AsyncSession = Depends(get_db)) -> list[CatalogItemResponse]:
        items = (await db.scalars(select(CatalogItem).where(CatalogItem.event_id == event_id))).all()
        return [
            CatalogItemResponse(
                id=i.id,
                event_id=i.event_id,
                code=i.code,
                name=i.name,
                item_type=ItemType(i.item_type),
                price_cents=i.price_cents,
                stock_available=max(0, i.stock_total - i.stock_reserved - i.stock_sold),
            )
            for i in items
        ]

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

            for item_id, req_qty in requested_by_item.items():
                ci = catalog_map[item_id]
                db.add(
                    OrderItem(
                        order_id=order.id,
                        catalog_item_id=ci.id,
                        item_code=ci.code,
                        quantity=req_qty,
                        unit_price_cents=ci.price_cents,
                    )
                )

            await db.commit()
            return OrderResponse(
                order_id=order.id,
                event_id=order.event_id,
                tenant_id=order.tenant_id,
                status=order.status,
                total_cents=order.total_cents,
                dni_last4=participant.dni_last4,
                expires_at=order.expires_at,
                checkout_url=f"/checkout/{order.id}",
            )

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

        entitlements: dict[str, int] = defaultdict(int)
        for oi in order_items:
            entitlements[oi.item_code] += oi.quantity

        display_name = pii_crypto.decrypt(participant.full_name_encrypted, aad=event.id)
        credential_id, qr_token = await _issue_participant_qr(
            event, display_name, participant.dni_last4, participant.id, order.id, dict(entitlements)
        )

        order.status = "PAID"
        order.payment_reference = payload.payment_reference
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
        return {
            "order_id": order.id,
            "status": order.status,
            "credential_id": credential_id,
            "qr_token": qr_token,
        }

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
        event = await db.scalar(select(Event).where(Event.id == event_id, Event.tenant_id == actor.tenant_id))
        if event is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found.")
        existing = await db.scalar(
            select(Promoter).where(Promoter.event_id == event_id, Promoter.code_prefix == payload.code_prefix)
        )
        if existing is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Promoter prefix already exists.")

        prom = Promoter(
            tenant_id=actor.tenant_id,
            event_id=event_id,
            name=payload.name,
            code_prefix=payload.code_prefix,
            email=payload.email.lower(),
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
        )

    @app.get("/api/v1/registration/events/{event_id}/promoters", response_model=list[PromoterStatsResponse])
    async def list_promoters(
        event_id: str,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> list[PromoterStatsResponse]:
        proms = (
            await db.scalars(
                select(Promoter).where(Promoter.event_id == event_id, Promoter.tenant_id == actor.tenant_id)
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
        event = await db.scalar(select(Event).where(Event.id == event_id, Event.tenant_id == actor.tenant_id))
        if event is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found.")
        item = await db.scalar(
            select(CatalogItem).where(CatalogItem.id == payload.catalog_item_id, CatalogItem.event_id == event_id)
        )
        if item is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Catalog item not found.")

        prefix = "CORT"
        if payload.promoter_id:
            prom = await db.scalar(
                select(Promoter).where(Promoter.id == payload.promoter_id, Promoter.event_id == event_id)
            )
            if prom is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Promoter not found.")
            prefix = prom.code_prefix

        created: list[CourtesyCode] = []
        for _ in range(payload.quantity):
            code_str = f"{prefix}-{secrets.token_hex(3).upper()}"
            c = CourtesyCode(
                tenant_id=actor.tenant_id,
                event_id=event_id,
                catalog_item_id=item.id,
                promoter_id=payload.promoter_id,
                code=code_str,
            )
            db.add(c)
            created.append(c)
        await db.commit()
        return [
            CourtesyCodeResponse(
                id=c.id,
                code=c.code,
                catalog_item_id=c.catalog_item_id,
                promoter_id=c.promoter_id,
                status=c.status,
                redeemed_at=c.redeemed_at,
            )
            for c in created
        ]

    @app.get("/api/v1/registration/events/{event_id}/codes", response_model=list[CourtesyCodeResponse])
    async def list_courtesy_codes(
        event_id: str,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> list[CourtesyCodeResponse]:
        rows = (
            await db.scalars(
                select(CourtesyCode)
                .where(CourtesyCode.event_id == event_id, CourtesyCode.tenant_id == actor.tenant_id)
                .order_by(CourtesyCode.created_at.desc())
                .limit(200)
            )
        ).all()
        return [
            CourtesyCodeResponse(
                id=c.id,
                code=c.code,
                catalog_item_id=c.catalog_item_id,
                promoter_id=c.promoter_id,
                status=c.status,
                redeemed_at=c.redeemed_at,
            )
            for c in rows
        ]

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
        cc.redeemed_at = datetime.now(timezone.utc)
        await db.commit()
        return {
            "status": "REDEEMED",
            "order_id": order.id,
            "credential_id": cred_id,
            "qr_token": qr_token,
            "item_code": item.code,
        }

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
        event = await db.scalar(select(Event).where(Event.id == event_id, Event.tenant_id == actor.tenant_id))
        if event is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found.")

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
        rows = (
            await db.scalars(
                select(BulkDispatchJob)
                .where(BulkDispatchJob.event_id == event_id, BulkDispatchJob.tenant_id == actor.tenant_id)
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
        event = await db.scalar(select(Event).where(Event.id == event_id, Event.tenant_id == actor.tenant_id))
        if event is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found.")
        return await _build_event_metrics(db, event)

    @app.get("/api/v1/registration/events/{event_id}/metrics/export.xlsx")
    async def export_event_metrics_excel(
        event_id: str,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> Response:
        event = await db.scalar(select(Event).where(Event.id == event_id, Event.tenant_id == actor.tenant_id))
        if event is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found.")
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
        await db.execute(delete(Event).where(Event.id == event_id))

    @app.get("/api/v1/registration/events/{event_id}/orders")
    async def list_event_orders(
        event_id: str,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> list[dict[str, Any]]:
        """List registered purchases/orders for an event (Admin/Supervisor)."""
        event = await db.scalar(select(Event).where(Event.id == event_id, Event.tenant_id == actor.tenant_id))
        if event is None:
            raise HTTPException(status_code=404, detail="Event not found.")
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

    @app.delete("/api/v1/registration/events/{event_id}")
    async def delete_tenant_event(
        event_id: str,
        actor: CurrentActor = Depends(require_admin),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, str]:
        event = await db.scalar(select(Event).where(Event.id == event_id, Event.tenant_id == actor.tenant_id))
        if event is None:
            raise HTTPException(status_code=404, detail="Event not found.")
        await _delete_event_cascade(db, event.id)
        await db.commit()
        await audit.record(
            tenant_id=actor.tenant_id,
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
