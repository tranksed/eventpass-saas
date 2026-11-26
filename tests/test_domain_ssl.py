"""Automated tests for SuperAdmin Domain, DNS verification, and SSL Management."""

from pathlib import Path
import pytest
from httpx import ASGITransport, AsyncClient

from services.auth_service.app import AuthSettings, create_auth_app
from services.registration_service.app import RegistrationSettings, create_registration_app


@pytest.fixture
def test_settings(tmp_path: Path):
    keys_dir = tmp_path / "keys"
    common = {
        "keys_dir": keys_dir,
        "pii_master_key_b64": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        "dni_blind_index_pepper": "test-pepper-secret-value-12345",
        "payment_webhook_secret": "test-webhook-hmac-secret-999",
        "internal_service_token": "test-internal-s2s-token-xyz",
        "rate_limit_requests": 5000,
        "superadmin_email": "superadmin@eventpass.pe",
        "superadmin_password": "SuperPass2026!",
    }
    auth_cfg = AuthSettings(database_url=f"sqlite+aiosqlite:///{tmp_path / 'auth.db'}", **common)
    reg_cfg = RegistrationSettings(database_url=f"sqlite+aiosqlite:///{tmp_path / 'reg.db'}", **common)
    return auth_cfg, reg_cfg


@pytest.mark.asyncio
async def test_domain_ssl_superadmin_flow(test_settings):
    auth_cfg, _ = test_settings
    auth_app = create_auth_app(auth_cfg)
    async with auth_app.router.lifespan_context(auth_app):
        transport = ASGITransport(app=auth_app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Login as SuperAdmin
            login_res = await client.post(
                "/api/v1/auth/superadmin/login",
                json={"email": "superadmin@eventpass.pe", "password": "SuperPass2026!"},
            )
            assert login_res.status_code == 200, login_res.text
            token = login_res.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}

            # 2. Get current Domain & SSL status
            ssl_status_res = await client.get("/api/v1/auth/superadmin/domain-ssl", headers=headers)
            assert ssl_status_res.status_code == 200
            data = ssl_status_res.json()
            assert "server_public_ip" in data
            assert "primary_domain" in data
            assert "ssl_enabled" in data

            # 3. Check DNS for localhost / dummy domain
            dns_check_res = await client.post(
                "/api/v1/auth/superadmin/domain-ssl/check-dns",
                headers=headers,
                json={"domain": "localhost"},
            )
            assert dns_check_res.status_code == 200
            dns_data = dns_check_res.json()
            assert dns_data["domain"] == "localhost"
            assert isinstance(dns_data["resolved_ips"], list)

            # 4. Configure Primary Domain & SSL settings
            conf_res = await client.post(
                "/api/v1/auth/superadmin/domain-ssl/configure",
                headers=headers,
                json={
                    "primary_domain": "tickets.eventpass.pe",
                    "ssl_enabled": True,
                    "ssl_auto_renew": True,
                    "force_https_redirect": True,
                    "contact_email": "admin@eventpass.pe",
                },
            )
            assert conf_res.status_code == 200
            conf_data = conf_res.json()
            assert conf_data["primary_domain"] == "tickets.eventpass.pe"
            assert conf_data["ssl_status"] in ("ACTIVE", "PENDING_DNS")
            assert conf_data["force_https_redirect"] is True

            # 5. List tenant domains
            tenant_domains_res = await client.get("/api/v1/auth/superadmin/tenants/domains", headers=headers)
            assert tenant_domains_res.status_code == 200
            tenants = tenant_domains_res.json()
            assert isinstance(tenants, list)

            # 6. Non-superadmin is blocked
            non_admin_res = await client.get("/api/v1/auth/superadmin/domain-ssl")
            assert non_admin_res.status_code == 401


@pytest.mark.asyncio
async def test_superadmin_can_edit_items_without_404(test_settings):
    auth_cfg, reg_cfg = test_settings
    auth_app = create_auth_app(auth_cfg)
    async with auth_app.router.lifespan_context(auth_app):
        auth_transport = ASGITransport(app=auth_app)
        async with AsyncClient(transport=auth_transport, base_url="http://test") as auth_client:
            login_res = await auth_client.post(
                "/api/v1/auth/superadmin/login",
                json={"email": "superadmin@eventpass.pe", "password": "SuperPass2026!"},
            )
            token = login_res.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}", "Idempotency-Key": "IDEMP-EVENT-CREATE-001"}

    reg_app = create_registration_app(reg_cfg)
    async with reg_app.router.lifespan_context(reg_app):
        reg_transport = ASGITransport(app=reg_app)
        async with AsyncClient(transport=reg_transport, base_url="http://test") as reg_client:
            # Create an event under a specific tenant
            create_ev = await reg_client.post(
                "/api/v1/registration/events",
                headers=headers,
                json={
                    "slug": "concierto-lima-2026",
                    "name": "Concierto Lima 2026",
                    "venue": "Estadio Nacional",
                    "starts_at": "2026-12-01T20:00:00Z",
                    "ends_at": "2026-12-02T02:00:00Z",
                    "max_purchases_per_dni": 2,
                },
            )
            assert create_ev.status_code == 201, create_ev.text
            event_id = create_ev.json()["id"]

            # SuperAdmin creates a catalog item
            create_item = await reg_client.post(
                f"/api/v1/registration/events/{event_id}/items",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "code": "VIP_01",
                    "name": "Entrada VIP",
                    "item_type": "ENTRY",
                    "price_cents": 15000,
                    "stock_total": 200,
                },
            )
            assert create_item.status_code == 201, create_item.text
            item_id = create_item.json()["id"]

            # SuperAdmin modifies the item (name, price, stock)
            # Previously failed with 404 Event Not Found due to tenant_id mismatch!
            patch_item = await reg_client.patch(
                f"/api/v1/registration/events/{event_id}/items/{item_id}",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "name": "Entrada Super VIP",
                    "price_cents": 18000,
                    "stock_total": 250,
                },
            )
            assert patch_item.status_code == 200, patch_item.text
            updated = patch_item.json()
            assert updated["name"] == "Entrada Super VIP"
            assert updated["price_cents"] == 18000
            assert updated["stock_total"] == 250

            # SuperAdmin can view event metrics
            metrics_res = await reg_client.get(
                f"/api/v1/registration/events/{event_id}/metrics",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert metrics_res.status_code == 200
            metrics = metrics_res.json()
            assert metrics["event_name"] == "Concierto Lima 2026"
