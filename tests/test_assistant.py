"""Tests for platform-scoped AI assistant (EventPass Copilot)."""

from __future__ import annotations

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
from services.web_portal.assistant import EventPassAssistant
from shared_kernel.audit_client import AuditClient
from shared_kernel.security import CurrentActor, Role


@pytest.fixture
async def assistant_env(tmp_path: Path):
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
            headers={"Authorization": f"Bearer {common['internal_service_token']}"},
        )

    reg_app = create_registration_app(
        RegistrationSettings(database_url=f"sqlite+aiosqlite:///{tmp_path / 'reg.db'}", **common),
        accreditation_client_factory=make_accred_client,
        audit_client=make_audit_client(),
    )

    # Combined custom transport router for assistant HTTP calls
    def route_request(request: httpx.Request):
        url = str(request.url)
        if "registration-service" in url:
            transport = httpx.ASGITransport(app=reg_app)
        elif "auth-service" in url:
            transport = httpx.ASGITransport(app=auth_app)
        elif "accreditation-service" in url:
            transport = httpx.ASGITransport(app=accred_app)
        else:
            transport = httpx.ASGITransport(app=audit_app)
        return transport.handle_async_request(request)

    custom_transport = httpx.MockTransport(route_request)

    assistant = EventPassAssistant(
        registration_service_url="http://registration-service",
        auth_service_url="http://auth-service",
        accreditation_service_url="http://accreditation-service",
        audit_service_url="http://audit-service",
    )

    async with (
        auth_app.router.lifespan_context(auth_app),
        audit_app.router.lifespan_context(audit_app),
        accred_app.router.lifespan_context(accred_app),
        reg_app.router.lifespan_context(reg_app),
    ):
        auth_client = httpx.AsyncClient(transport=httpx.ASGITransport(app=auth_app), base_url="http://auth-service")
        reg_client = httpx.AsyncClient(transport=httpx.ASGITransport(app=reg_app), base_url="http://registration-service")

        ten_res = await auth_client.post(
            "/api/v1/auth/tenants/register",
            json={
                "company_name": "Asistente Fest SAC",
                "company_slug": "asistente-fest",
                "admin_email": "admin@asistente.pe",
                "admin_full_name": "Admin Asistente",
                "admin_password": "AdminPassword123!",
            },
        )
        assert ten_res.status_code == 201
        ten_data = ten_res.json()
        token = ten_data["tokens"]["access_token"]
        tenant_id = ten_data["tenant_id"]

        now = datetime.now(timezone.utc)
        ev_res = await reg_client.post(
            "/api/v1/registration/events",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "name": "Concierto AI 2026",
                "slug": "concierto-ai-2026",
                "venue": "Jockey Club, Lima",
                "starts_at": (now + timedelta(days=1)).isoformat(),
                "ends_at": (now + timedelta(days=3)).isoformat(),
                "max_purchases_per_dni": 4,
            },
        )
        assert ev_res.status_code == 201
        event_id = ev_res.json()["id"]

        client = httpx.AsyncClient(transport=custom_transport, base_url="http://eventpass")
        yield {
            "assistant": assistant,
            "token": token,
            "tenant_id": tenant_id,
            "event_id": event_id,
            "client": client,
            "reg_client": reg_client,
        }


async def test_assistant_role_security(assistant_env):
    env = assistant_env
    assistant: EventPassAssistant = env["assistant"]

    # VALIDATOR role is denied
    val_actor = CurrentActor(user_id="u1", tenant_id=env["tenant_id"], role=Role.VALIDATOR, jti="j1")
    res = await assistant.execute_command("Crear entrada VIP a 100 soles", val_actor, env["token"], env["event_id"], env["client"])
    assert res["ok"] is False
    assert res["action_taken"] == "UNAUTHORIZED"


async def test_assistant_create_and_update_items(assistant_env):
    env = assistant_env
    assistant: EventPassAssistant = env["assistant"]
    admin_actor = CurrentActor(user_id="u-admin", tenant_id=env["tenant_id"], role=Role.ADMIN, jti="j-adm")

    # 1. Crear entrada VIP a 120 soles con 50 cupos
    res1 = await assistant.execute_command(
        "Crea una entrada VIP a 120 soles con 50 cupos",
        admin_actor,
        env["token"],
        env["event_id"],
        env["client"],
    )
    assert res1["ok"] is True
    assert res1["action_taken"] == "CREATE_CATALOG_ITEM"
    assert res1["refresh_needed"] is True
    assert res1["data"]["price_cents"] == 12000
    assert res1["data"]["stock_total"] == 50

    # 2. Listar entradas
    res_list = await assistant.execute_command("Listar entradas", admin_actor, env["token"], env["event_id"], env["client"])
    assert res_list["ok"] is True
    assert "VIP" in res_list["reply"]

    # 3. Cambiar el precio de la entrada VIP a 135 soles
    res_price = await assistant.execute_command(
        "Cambia el precio de VIP a 135 soles",
        admin_actor,
        env["token"],
        env["event_id"],
        env["client"],
    )
    assert res_price["ok"] is True
    assert res_price["action_taken"] == "UPDATE_CATALOG_ITEM_PRICE"
    assert res_price["data"]["price_cents"] == 13500

    # 4. Modificar stock a 80 cupos
    res_stock = await assistant.execute_command(
        "Aumenta el stock de VIP a 80 cupos",
        admin_actor,
        env["token"],
        env["event_id"],
        env["client"],
    )
    assert res_stock["ok"] is True
    assert res_stock["action_taken"] == "UPDATE_CATALOG_ITEM_STOCK"
    assert res_stock["data"]["stock_total"] == 80

    # 5. Consultar métricas del evento
    res_metrics = await assistant.execute_command(
        "¿Cuánto hemos vendido hoy?",
        admin_actor,
        env["token"],
        env["event_id"],
        env["client"],
    )
    assert res_metrics["ok"] is True
    assert res_metrics["action_taken"] == "EVENT_METRICS"

    # 6. Registrar promotor / canal RRPP
    res_promo = await assistant.execute_command(
        "Crea código PROMO20 para RRPP",
        admin_actor,
        env["token"],
        env["event_id"],
        env["client"],
    )
    assert res_promo["ok"] is True
    assert res_promo["action_taken"] == "CREATE_PROMOTER"
    assert res_promo["data"]["code_prefix"] == "PROMO20"

    # 7. Pausar el evento
    res_pause = await assistant.execute_command(
        "Pausa el evento",
        admin_actor,
        env["token"],
        env["event_id"],
        env["client"],
    )
    assert res_pause["ok"] is True
    assert res_pause["action_taken"] == "TOGGLE_EVENT_STATUS"

    # 8. Crear interacción con artista: Foto
    res_artist_photo = await assistant.execute_command(
        "Crea foto con Mario Castañeda a 60 soles con 50 cupos",
        admin_actor,
        env["token"],
        env["event_id"],
        env["client"],
    )
    assert res_artist_photo["ok"] is True
    assert res_artist_photo["action_taken"] == "CREATE_CATALOG_ITEM"
    assert res_artist_photo["data"]["item_type"] == "INTERACTION"
    assert res_artist_photo["data"]["artist_name"] == "Mario Castañeda"
    assert res_artist_photo["data"]["interaction_type"] == "FOTO"
    assert res_artist_photo["data"]["price_cents"] == 6000
    assert res_artist_photo["data"]["stock_total"] == 50

    # 9. Crear interacción con artista: Firma de autógrafo
    res_artist_sign = await assistant.execute_command(
        "Crea firma de René García a 50 soles con 40 cupos",
        admin_actor,
        env["token"],
        env["event_id"],
        env["client"],
    )
    assert res_artist_sign["ok"] is True
    assert res_artist_sign["data"]["item_type"] == "INTERACTION"
    assert res_artist_sign["data"]["artist_name"] == "René García"
    assert res_artist_sign["data"]["interaction_type"] == "FIRMA"
    assert res_artist_sign["data"]["price_cents"] == 5000
    assert res_artist_sign["data"]["stock_total"] == 40

    # 10. Listar artistas y experiencias
    res_artists = await assistant.execute_command(
        "Listar artistas",
        admin_actor,
        env["token"],
        env["event_id"],
        env["client"],
    )
    assert res_artists["ok"] is True
    assert res_artists["action_taken"] == "LIST_ARTISTS"
    assert "Mario Castañeda" in res_artists["reply"]
    assert "René García" in res_artists["reply"]

    # 11. Consultar aforo en puerta
    res_door = await assistant.execute_command(
        "¿Cómo va la puerta?",
        admin_actor,
        env["token"],
        env["event_id"],
        env["client"],
    )
    assert res_door["ok"] is True
    assert res_door["action_taken"] == "DOOR_METRICS"

    # 12. Consultar staff
    res_staff = await assistant.execute_command(
        "Personal de staff",
        admin_actor,
        env["token"],
        env["event_id"],
        env["client"],
    )
    assert res_staff["ok"] is True
    assert res_staff["action_taken"] == "STAFF_SUMMARY"
