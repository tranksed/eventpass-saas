"""FastAPI application for registration-service (Events, DNI Quota, Orders, Payment Webhooks)."""

from __future__ import annotations

import asyncio
import json
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Callable

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from services.registration_service.config import RegistrationSettings
from services.registration_service.models import (
    CatalogItem,
    Event,
    Order,
    OrderItem,
    OutboxEvent,
    Participant,
)
from services.registration_service.schemas import (
    CatalogItemResponse,
    CreateCatalogItemRequest,
    CreateEventRequest,
    CreateOrderRequest,
    EventResponse,
    ItemType,
    OrderResponse,
    PaymentWebhookPayload,
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
from shared_kernel.database import Base, create_service_db, get_db_session
from shared_kernel.security import (
    CurrentActor,
    Role,
    SecurityHeadersMiddleware,
    SlidingWindowRateLimiterMiddleware,
    make_role_dependency,
)


def _as_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


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

    # Per-(event_id, dni_blind_index) mutex to serialize concurrent requests for the same DNI
    dni_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def get_db():
        async for sess in get_db_session(session_factory):
            yield sess

    require_admin = make_role_dependency(lambda: jwt_pub_key, Role.ADMIN)
    require_admin_or_supervisor = make_role_dependency(lambda: jwt_pub_key, Role.ADMIN, Role.SUPERVISOR)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        yield
        await engine.dispose()

    app = FastAPI(title="EventPass Registration Service", version="1.0.0", lifespan=lifespan)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        SlidingWindowRateLimiterMiddleware,
        max_requests=cfg.rate_limit_requests,
        window_seconds=cfg.rate_limit_window_seconds,
    )

    async def _issue_participant_qr(
        event: Event,
        participant: Participant,
        order: Order,
        entitlements: dict[str, int],
    ) -> tuple[str, str]:
        payload = {
            "tenant_id": event.tenant_id,
            "event_id": event.id,
            "order_id": order.id,
            "holder_type": "PARTICIPANT",
            "holder_ref_id": participant.id,
            "display_name": pii_crypto.decrypt(participant.full_name_encrypted, aad=event.id),
            "dni_last4": participant.dni_last4,
            "entitlements": entitlements,
            "expires_at": _as_utc(event.ends_at).isoformat(),
        }
        headers = {"X-Internal-Service-Token": cfg.internal_service_token}
        if accreditation_client_factory is not None:
            async with accreditation_client_factory() as client:
                resp = await client.post(
                    "/internal/accreditation/credentials/issue",
                    json=payload,
                    headers=headers,
                )
        else:
            async with httpx.AsyncClient(base_url=cfg.accreditation_service_url, timeout=5.0) as client:
                resp = await client.post(
                    "/internal/accreditation/credentials/issue",
                    json=payload,
                    headers=headers,
                )
        if resp.status_code != status.HTTP_201_CREATED:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Accreditation service failed to issue QR: {resp.text}",
            )
        data = resp.json()
        return data["credential_id"], data["qr_token"]

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": cfg.service_name}

    @app.post(
        "/api/v1/registration/events",
        response_model=EventResponse,
        status_code=status.HTTP_201_CREATED,
    )
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
            metadata={"max_purchases_per_dni": event.max_purchases_per_dni},
        )
        return EventResponse(
            id=event.id,
            tenant_id=event.tenant_id,
            name=event.name,
            slug=event.slug,
            starts_at=event.starts_at,
            ends_at=event.ends_at,
            max_purchases_per_dni=event.max_purchases_per_dni,
            is_active=event.is_active,
        )

    @app.patch("/api/v1/registration/events/{event_id}/dni-limit", response_model=EventResponse)
    async def update_event_dni_limit(
        event_id: str,
        payload: UpdateEventLimitRequest,
        actor: CurrentActor = Depends(require_admin),
        db: AsyncSession = Depends(get_db),
    ) -> EventResponse:
        event = await db.scalar(
            select(Event).where(Event.id == event_id, Event.tenant_id == actor.tenant_id)
        )
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
        return EventResponse(
            id=event.id,
            tenant_id=event.tenant_id,
            name=event.name,
            slug=event.slug,
            starts_at=event.starts_at,
            ends_at=event.ends_at,
            max_purchases_per_dni=event.max_purchases_per_dni,
            is_active=event.is_active,
        )

    @app.get("/api/v1/registration/events", response_model=list[EventResponse])
    async def list_tenant_events(
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> list[EventResponse]:
        events = (
            await db.scalars(
                select(Event).where(Event.tenant_id == actor.tenant_id).order_by(Event.created_at.desc())
            )
        ).all()
        return [
            EventResponse(
                id=e.id,
                tenant_id=e.tenant_id,
                name=e.name,
                slug=e.slug,
                starts_at=e.starts_at,
                ends_at=e.ends_at,
                max_purchases_per_dni=e.max_purchases_per_dni,
                is_active=e.is_active,
            )
            for e in events
        ]

    @app.get("/api/v1/registration/public/events", response_model=list[EventResponse])
    async def list_public_active_events(
        db: AsyncSession = Depends(get_db),
    ) -> list[EventResponse]:
        """Public listing of active events for buyer registration."""
        events = (
            await db.scalars(
                select(Event).where(Event.is_active.is_(True)).order_by(Event.created_at.desc())
            )
        ).all()
        return [
            EventResponse(
                id=e.id,
                tenant_id=e.tenant_id,
                name=e.name,
                slug=e.slug,
                starts_at=e.starts_at,
                ends_at=e.ends_at,
                max_purchases_per_dni=e.max_purchases_per_dni,
                is_active=e.is_active,
            )
            for e in events
        ]

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
        event = await db.scalar(
            select(Event).where(Event.id == event_id, Event.tenant_id == actor.tenant_id)
        )
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
    async def list_public_catalog_items(
        event_id: str,
        db: AsyncSession = Depends(get_db),
    ) -> list[CatalogItemResponse]:
        items = (
            await db.scalars(select(CatalogItem).where(CatalogItem.event_id == event_id))
        ).all()
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
        """Public pre-registration + purchase reservation enforcing DNI limit (1..10) and atomic stock."""
        event = await db.scalar(select(Event).where(Event.id == event_id, Event.is_active.is_(True)))
        if event is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active event not found.")

        try:
            normalized_dni = normalize_dni(payload.dni)
            dni_last4 = mask_dni(normalized_dni)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

        dni_idx = pii_crypto.blind_index_dni(event.tenant_id, event.id, normalized_dni)
        lock = dni_locks[f"{event.id}:{dni_idx}"]

        async with lock:
            # 1. Idempotency check
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

            # 2. Aggregate requested quantities per catalog item
            requested_by_item: dict[str, int] = defaultdict(int)
            for req_item in payload.items:
                requested_by_item[req_item.item_id] += req_item.quantity

            # 3. Check existing active/paid purchases for this DNI on this event
            existing_qty_rows = (
                await db.execute(
                    select(OrderItem.catalog_item_id, func.coalesce(func.sum(OrderItem.quantity), 0))
                    .join(Order, OrderItem.order_id == Order.id)
                    .where(
                        Order.event_id == event.id,
                        Order.dni_blind_index == dni_idx,
                        (Order.status == "PAID")
                        | ((Order.status == "PENDING") & (Order.expires_at > now)),
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

            # 4. Atomic stock reservation per item (prevents overselling under burst concurrency)
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

            # 5. Upsert encrypted participant record
            participant = await db.scalar(
                select(Participant).where(
                    Participant.event_id == event.id,
                    Participant.dni_blind_index == dni_idx,
                )
            )
            if participant is None:
                participant = Participant(
                    tenant_id=event.tenant_id,
                    event_id=event.id,
                    dni_blind_index=dni_idx,
                    dni_encrypted=pii_crypto.encrypt(normalized_dni, aad=event.id),
                    dni_last4=dni_last4,
                    full_name_encrypted=pii_crypto.encrypt(payload.full_name, aad=event.id),
                    email_encrypted=pii_crypto.encrypt(payload.email.lower(), aad=event.id),
                )
                db.add(participant)
                await db.flush()

            expires_at = now + timedelta(minutes=cfg.reservation_ttl_minutes)
            order = Order(
                tenant_id=event.tenant_id,
                event_id=event.id,
                participant_id=participant.id,
                dni_blind_index=dni_idx,
                idempotency_key=idempotency_key,
                status="PENDING",
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
        """Verify HMAC-SHA256 gateway webhook, finalize order, and trigger signed QR issuance."""
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

        # Idempotent replay handling
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

        # Convert stock_reserved -> stock_sold
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

        credential_id, qr_token = await _issue_participant_qr(
            event, participant, order, dict(entitlements)
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
        """Anti-IDOR order lookup requiring matching participant DNI."""
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

    return app


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(create_registration_app(), host="0.0.0.0", port=8002)
