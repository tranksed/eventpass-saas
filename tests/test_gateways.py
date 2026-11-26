"""Unit and integration tests for payment gateways (Mercado Pago, Izipay, Yape, Demo)."""

from __future__ import annotations

import hmac
import json
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from services.accreditation_service.app import create_accreditation_app
from services.accreditation_service.config import AccreditationSettings
from services.audit_service.app import create_audit_app
from services.audit_service.config import AuditSettings
from services.auth_service.app import create_auth_app
from services.auth_service.config import AuthSettings
from services.registration_service.app import create_registration_app
from services.registration_service.config import RegistrationSettings
from shared_kernel.audit_client import AuditClient
from shared_kernel.security import Role


@pytest.fixture
async def gateway_env(tmp_path: Path):
    keys_dir = tmp_path / "keys"
    common = {
        "keys_dir": keys_dir,
        "pii_master_key_b64": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        "dni_blind_index_pepper": "test-pepper-secret-value-12345",
        "payment_webhook_secret": "test-webhook-hmac-secret-999",
        "internal_service_token": "test-internal-s2s-token-xyz",
        "rate_limit_requests": 5000,
    }

    audit_app = create_audit_app(
        AuditSettings(database_url=f"sqlite+aiosqlite:///{tmp_path / 'audit.db'}", **common),
    )

    def make_audit_client():
        return AuditClient(
            base_url="http://audit-service",
            internal_token=common["internal_service_token"],
            client_factory=lambda: httpx.AsyncClient(
                transport=httpx.ASGITransport(app=audit_app), base_url="http://audit-service"
            ),
        )

    auth_app = create_auth_app(
        AuthSettings(database_url=f"sqlite+aiosqlite:///{tmp_path / 'auth.db'}", **common),
        audit_client=make_audit_client(),
    )
    accred_app = create_accreditation_app(
        AccreditationSettings(database_url=f"sqlite+aiosqlite:///{tmp_path / 'accred.db'}", **common),
        audit_client=make_audit_client(),
    )

    def make_accred_client():
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=accred_app),
            base_url="http://accreditation-service",
            headers={"X-Internal-Service-Token": common["internal_service_token"]},
        )

    reg_app = create_registration_app(
        RegistrationSettings(database_url=f"sqlite+aiosqlite:///{tmp_path / 'reg.db'}", **common),
        audit_client=make_audit_client(),
        accreditation_client_factory=make_accred_client,
    )

    async with (
        auth_app.router.lifespan_context(auth_app),
        audit_app.router.lifespan_context(audit_app),
        accred_app.router.lifespan_context(accred_app),
        reg_app.router.lifespan_context(reg_app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=auth_app), base_url="http://auth-service") as auth_cli,
        httpx.AsyncClient(transport=httpx.ASGITransport(app=reg_app), base_url="http://registration-service") as reg_cli,
    ):
        # 1. Register tenant & get admin token
        reg_tenant_res = await auth_cli.post(
            "/api/v1/auth/tenants/register",
            json={
                "company_name": "OtakuFest SAC",
                "company_slug": "otakufest",
                "admin_email": "admin@otakufest.pe",
                "admin_full_name": "Admin Otaku",
                "admin_password": "StrongPassword!123",
            },
        )
        assert reg_tenant_res.status_code == 201, reg_tenant_res.text
        token = reg_tenant_res.json()["tokens"]["access_token"]
        auth_headers = {"Authorization": f"Bearer {token}"}

        # 2. Create Event & Catalog Item
        now = datetime.now(timezone.utc)
        ev_res = await reg_cli.post(
            "/api/v1/registration/events",
            headers=auth_headers,
            json={
                "name": "Anime Comic Con 2026",
                "slug": "anime-comic-con-2026",
                "venue": "Jockey Club del Perú",
                "starts_at": (now + timedelta(days=30)).isoformat(),
                "ends_at": (now + timedelta(days=31)).isoformat(),
                "max_purchases_per_dni": 4,
            },
        )
        assert ev_res.status_code == 201
        event = ev_res.json()

        item_res = await reg_cli.post(
            f"/api/v1/registration/events/{event['id']}/items",
            headers=auth_headers,
            json={
                "code": "ENTRY",
                "name": "Entrada General 1 Día",
                "item_type": "ENTRY",
                "price_cents": 5000,
                "stock_total": 100,
            },
        )
        assert item_res.status_code == 201
        item = item_res.json()

        yield {
            "reg_cli": reg_cli,
            "auth_headers": auth_headers,
            "event": event,
            "item": item,
            "common": common,
        }


@pytest.mark.anyio
async def test_payment_gateway_config_and_masking(gateway_env):
    reg = gateway_env["reg_cli"]
    auth_headers = gateway_env["auth_headers"]
    event = gateway_env["event"]

    # 1. Initial config check
    cfg_res = await reg.get(f"/api/v1/registration/events/{event['id']}/payment-config", headers=auth_headers)
    assert cfg_res.status_code == 200
    cfg = cfg_res.json()
    assert cfg["mp_enabled"] is False
    assert cfg["izipay_enabled"] is False
    assert cfg["yape_enabled"] is True

    # 2. Update config with credentials
    put_res = await reg.put(
        f"/api/v1/registration/events/{event['id']}/payment-config",
        headers=auth_headers,
        json={
            "mp_enabled": True,
            "mp_public_key": "TEST-APP-USR-123456",
            "mp_access_token": "TEST-TOKEN-SUPERSECRET999",
            "mp_sandbox": True,
            "izipay_enabled": True,
            "izipay_merchant_id": "87654321",
            "izipay_public_key": "87654321:testpublickey_abc",
            "izipay_sha256_key": "my-ultra-secret-sha256-hmac",
            "izipay_sandbox": True,
            "yape_enabled": True,
            "yape_provider": "DIRECT",
            "yape_phone_number": "987654321",
            "yape_recipient_name": "OtakuFest SAC",
        },
    )
    assert put_res.status_code == 200
    updated = put_res.json()
    assert updated["mp_enabled"] is True
    # Secrets should be masked in response to protect against UI leaks
    assert updated["mp_has_token"] is True
    assert "SUPERSECRET999" not in updated["mp_token_masked"]
    assert updated["izipay_has_sha256_key"] is True
    assert updated["yape_phone_number"] == "987654321"

    # 3. Public payment methods discovery endpoint (unauthenticated for buyer checkout)
    pub_res = await reg.get(f"/api/v1/registration/events/{event['id']}/public-payment-methods")
    assert pub_res.status_code == 200
    pub = pub_res.json()
    assert pub["mercadopago_enabled"] is True
    assert pub["izipay_enabled"] is True
    assert pub["yape_enabled"] is True
    assert pub["demo_enabled"] is True
    assert pub["yape_phone_number"] == "987654321"
    assert pub["yape_recipient_name"] == "OtakuFest SAC"


@pytest.mark.anyio
async def test_demo_payment_flow(gateway_env):
    reg = gateway_env["reg_cli"]
    event = gateway_env["event"]
    item = gateway_env["item"]

    # 1. Create order
    order_res = await reg.post(
        f"/api/v1/registration/events/{event['id']}/orders",
        headers={"Idempotency-Key": "demo-flow-order-001"},
        json={
            "dni": "72345678",
            "full_name": "Kenshin Himura",
            "email": "kenshin@dojo.pe",
            "payment_method": "DEMO",
            "items": [{"item_id": item["id"], "quantity": 1}],
        },
    )
    assert order_res.status_code == 201, order_res.text
    order = order_res.json()

    # 2. Initiate payment in DEMO mode -> instantly marks PAID and returns QR
    init_res = await reg.post(
        f"/api/v1/registration/orders/{order['order_id']}/initiate-payment",
        json={"payment_method": "DEMO"},
    )
    assert init_res.status_code == 200
    res = init_res.json()
    assert res["status"] == "PAID"
    assert res["qr_token"] is not None
    assert res["credential_id"] is not None


@pytest.mark.anyio
async def test_yape_payment_flow_and_confirmation(gateway_env):
    reg = gateway_env["reg_cli"]
    auth_headers = gateway_env["auth_headers"]
    event = gateway_env["event"]
    item = gateway_env["item"]

    # 1. Enable Yape in config
    await reg.put(
        f"/api/v1/registration/events/{event['id']}/payment-config",
        headers=auth_headers,
        json={
            "yape_enabled": True,
            "yape_phone_number": "912345678",
            "yape_recipient_name": "AnimeCon SAC",
        },
    )

    # 2. Create order with YAPE
    order_res = await reg.post(
        f"/api/v1/registration/events/{event['id']}/orders",
        headers={"Idempotency-Key": "yape-flow-order-002"},
        json={
            "dni": "79876543",
            "full_name": "Sakura Kinomoto",
            "email": "sakura@clow.pe",
            "payment_method": "YAPE",
            "items": [{"item_id": item["id"], "quantity": 2}],
        },
    )
    assert order_res.status_code == 201, order_res.text
    order = order_res.json()

    # 3. Initiate payment with YAPE -> returns dynamic QR payload and reference code
    init_res = await reg.post(
        f"/api/v1/registration/orders/{order['order_id']}/initiate-payment",
        json={"payment_method": "YAPE"},
    )
    assert init_res.status_code == 200
    init_data = init_res.json()
    assert init_data["yape_phone"] == "912345678"
    assert init_data["yape_recipient"] == "AnimeCon SAC"
    assert init_data["total_cents"] == 10000
    assert "EP-" in init_data["reference_code"]
    assert init_data["yape_qr_data"] is not None

    # 4. Buyer sends Yape and enters operation number (e.g. 583921)
    confirm_res = await reg.post(
        f"/api/v1/registration/orders/{order['order_id']}/confirm-yape",
        json={"operation_number": "583921"},
    )
    assert confirm_res.status_code == 200
    conf_data = confirm_res.json()
    assert conf_data["status"] == "PAID"
    assert conf_data["operation_number"] == "583921"
    assert conf_data["qr_token"] is not None
    assert conf_data["credential_id"] is not None


@pytest.mark.anyio
async def test_mercadopago_and_izipay_initiation(gateway_env):
    reg = gateway_env["reg_cli"]
    auth_headers = gateway_env["auth_headers"]
    event = gateway_env["event"]
    item = gateway_env["item"]

    # 1. Enable Mercado Pago and Izipay
    await reg.put(
        f"/api/v1/registration/events/{event['id']}/payment-config",
        headers=auth_headers,
        json={
            "mp_enabled": True,
            "mp_public_key": "TEST-123456",
            "mp_access_token": "TEST-TOKEN-XYZ",
            "mp_sandbox": True,
            "izipay_enabled": True,
            "izipay_merchant_id": "12345678",
            "izipay_public_key": "12345678:testpublickey",
            "izipay_sha256_key": "hmac_key",
            "izipay_sandbox": True,
        },
    )

    # 2. Test Mercado Pago initiation
    order_mp = (await reg.post(
        f"/api/v1/registration/events/{event['id']}/orders",
        headers={"Idempotency-Key": "mp-flow-order-003"},
        json={
            "dni": "71112233",
            "full_name": "Goku Son",
            "email": "goku@kame.pe",
            "payment_method": "MERCADOPAGO",
            "items": [{"item_id": item["id"], "quantity": 1}],
        },
    )).json()

    init_mp = (await reg.post(
        f"/api/v1/registration/orders/{order_mp['order_id']}/initiate-payment",
        json={"payment_method": "MERCADOPAGO"},
    )).json()
    assert init_mp["payment_method"] == "MERCADOPAGO"
    assert init_mp["checkout_url"] is not None

    # 3. Test Izipay initiation
    order_izi = (await reg.post(
        f"/api/v1/registration/events/{event['id']}/orders",
        headers={"Idempotency-Key": "izipay-flow-order-004"},
        json={
            "dni": "72223344",
            "full_name": "Vegeta Prince",
            "email": "vegeta@capsule.pe",
            "payment_method": "IZIPAY",
            "items": [{"item_id": item["id"], "quantity": 1}],
        },
    )).json()

    init_izi = (await reg.post(
        f"/api/v1/registration/orders/{order_izi['order_id']}/initiate-payment",
        json={"payment_method": "IZIPAY"},
    )).json()
    assert init_izi["payment_method"] == "IZIPAY"
    assert init_izi["checkout_url"] is not None
