"""Tests for order editing/deletion, accreditation links, and branded email ticketing."""

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from httpx import ASGITransport, AsyncClient

from services.accreditation_service.app import create_accreditation_app
from services.accreditation_service.config import AccreditationSettings
from services.registration_service.app import create_registration_app
from services.registration_service.config import RegistrationSettings
from shared_kernel.crypto import PIIEncryptor, ensure_ed25519_keypair, issue_jwt, mask_dni
from shared_kernel.email_service import (
    generate_qr_with_logo,
    render_ticket_email_html,
    send_email_async,
)
from shared_kernel.security import Role


@pytest.fixture
def keys_dir(tmp_path: Path) -> Path:
    kdir = tmp_path / "keys"
    kdir.mkdir()
    ensure_ed25519_keypair(kdir, "jwt")
    ensure_ed25519_keypair(kdir, "qr")
    return kdir


@pytest.mark.asyncio
async def test_email_service_rendering(tmp_path: Path):
    """Test generating styled QR code with center badge and rendering email HTML."""
    qr_bytes = generate_qr_with_logo("eventpass_test_qr_token_9988", brand_color="#06b6d4")
    assert len(qr_bytes) > 500
    assert qr_bytes.startswith(b"\x89PNG")

    html = render_ticket_email_html(
        event_name="Expo Tech 2026",
        buyer_name="Carlos Gomez",
        dni_last4="7890",
        order_id="ord-abc-123",
        items_summary="1x VIP, 1x MEET & GREET",
        total_soles="250.00",
        venue="Jockey Plaza",
        venue_address="Av. Javier Prado Este 4200",
        starts_at_str="15/12/2026 18:00",
        brand_color="#06b6d4",
    )
    assert "Expo Tech 2026" in html
    assert "Carlos Gomez" in html
    assert "cid:ticket_qr" in html
    assert "250.00" in html

    settings = RegistrationSettings(data_dir=tmp_path / "data", smtp_host="")
    res = await send_email_async(
        settings,
        to_email="comprador@ejemplo.com",
        subject="Tus Entradas",
        html_body=html,
        qr_png_bytes=qr_bytes,
    )
    assert res["status"] == "simulated"
    assert res["recipient"] == "comprador@ejemplo.com"


@pytest.mark.asyncio
async def test_accreditation_company_links_and_lifecycle(tmp_path: Path, keys_dir: Path):
    """Test creating accredited company, viewing decrypted links, regenerating links, and deletion."""
    settings = AccreditationSettings(
        database_url=f"sqlite+aiosqlite:///{tmp_path}/accred.db",
        keys_dir=keys_dir,
        data_dir=tmp_path / "data",
    )
    app = create_accreditation_app(settings)
    priv_jwt, _ = ensure_ed25519_keypair(keys_dir, "jwt")
    token, _ = issue_jwt(
        priv_jwt,
        subject="admin-1",
        tenant_id="tenant-accred",
        role="ADMIN",
        ttl_minutes=60,
    )
    headers = {"Authorization": f"Bearer {token}"}

    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # 1. Create accredited company
            create_res = await client.post(
                "/api/v1/accreditation/companies",
                json={
                    "event_id": "event-1",
                    "company_name": "Sponsor Tech SAC",
                    "contact_email": "sponsor@tech.pe",
                    "custom_quota": 8,
                },
                headers=headers,
            )
            assert create_res.status_code == 201
            data = create_res.json()
            assert data["company_name"] == "Sponsor Tech SAC"
            assert data["staff_quota"] == 8
            assert data["invite_token"] is not None
            assert "/acreditacion?token=" in data["invite_url"]
            cid = data["company_id"]
            old_token = data["invite_token"]

            # 2. List companies and verify link is visible and decryptable
            list_res = await client.get("/api/v1/accreditation/companies", headers=headers)
            assert list_res.status_code == 200
            companies = list_res.json()
            assert len(companies) == 1
            assert companies[0]["invite_token"] == old_token
            assert companies[0]["invite_url"] == f"/acreditacion?token={old_token}"

            # 3. Regenerate invite link
            regen_res = await client.post(
                f"/api/v1/accreditation/companies/{cid}/regenerate-link",
                headers=headers,
            )
            assert regen_res.status_code == 200
            new_data = regen_res.json()
            assert new_data["invite_token"] is not None
            assert new_data["invite_token"] != old_token

            # 4. Delete accredited company
            del_res = await client.delete(
                f"/api/v1/accreditation/companies/{cid}",
                headers=headers,
            )
            assert del_res.status_code == 200
            assert del_res.json()["status"] == "deleted"

            # 5. Verify list is empty
            list_res2 = await client.get("/api/v1/accreditation/companies", headers=headers)
            assert len(list_res2.json()) == 0


@pytest.mark.asyncio
async def test_order_edit_delete_and_email(tmp_path: Path, keys_dir: Path):
    """Test editing an order, sending tickets email, and deleting order with inventory restoration."""
    accred_settings = AccreditationSettings(
        database_url=f"sqlite+aiosqlite:///{tmp_path}/accred.db",
        keys_dir=keys_dir,
        data_dir=tmp_path / "data",
    )
    accred_app = create_accreditation_app(accred_settings)

    def accred_factory():
        return AsyncClient(transport=ASGITransport(app=accred_app), base_url="http://test")

    reg_settings = RegistrationSettings(
        database_url=f"sqlite+aiosqlite:///{tmp_path}/reg.db",
        keys_dir=keys_dir,
        data_dir=tmp_path / "data",
    )
    reg_app = create_registration_app(reg_settings, accreditation_client_factory=accred_factory)

    priv_jwt, _ = ensure_ed25519_keypair(keys_dir, "jwt")
    token, _ = issue_jwt(
        priv_jwt,
        subject="admin-1",
        tenant_id="tenant-orders",
        role="ADMIN",
        ttl_minutes=60,
    )
    headers = {"Authorization": f"Bearer {token}"}

    async with accred_app.router.lifespan_context(accred_app):
        async with reg_app.router.lifespan_context(reg_app):
            async with AsyncClient(transport=ASGITransport(app=reg_app), base_url="http://test") as client:
                # 1. Create Event
                now = datetime.now(timezone.utc)
                ev_res = await client.post(
                    "/api/v1/registration/events",
                    json={
                        "name": "Festival de Verano 2026",
                        "slug": "festival-verano",
                        "starts_at": (now + timedelta(days=5)).isoformat(),
                        "ends_at": (now + timedelta(days=6)).isoformat(),
                        "max_purchases_per_dni": 5,
                    },
                    headers=headers,
                )
                assert ev_res.status_code == 201
                event_id = ev_res.json()["id"]

                # 2. Create Catalog Item
                item_res = await client.post(
                    f"/api/v1/registration/events/{event_id}/items",
                    json={
                        "code": "GEN",
                        "name": "Entrada General",
                        "item_type": "ENTRY",
                        "price_cents": 5000,
                        "stock_total": 20,
                    },
                    headers=headers,
                )
                assert item_res.status_code == 201
                item_id = item_res.json()["id"]

                # 3. Create Order
                order_res = await client.post(
                    f"/api/v1/registration/events/{event_id}/orders",
                    json={
                        "dni": "44556677",
                        "full_name": "Pedro Castillo",
                        "email": "pedro@test.pe",
                        "items": [{"item_id": item_id, "quantity": 2}],
                    },
                    headers={"idempotency-key": "idemp-test-order-1"},
                )
                assert order_res.status_code == 201, order_res.text
                order_id = order_res.json()["order_id"]
                assert order_res.json()["status"] == "PENDING"

                # Check stock reserved = 2
                items_check = await client.get(f"/api/v1/registration/events/{event_id}/items")
                assert items_check.json()[0]["stock_reserved"] == 2
                assert items_check.json()[0]["stock_sold"] == 0

                # 4. Edit Order (Update Buyer details & set status to PAID)
                edit_res = await client.patch(
                    f"/api/v1/registration/orders/{order_id}",
                    json={
                        "full_name": "Pedro Actualizado",
                        "email": "pedro.nuevo@test.pe",
                        "status": "PAID",
                        "payment_method": "YAPE",
                    },
                    headers=headers,
                )
                assert edit_res.status_code == 200
                assert edit_res.json()["status"] == "ok"
                assert edit_res.json()["order_status"] == "PAID"

                # Check stock transferred to sold
                items_check2 = await client.get(f"/api/v1/registration/events/{event_id}/items")
                assert items_check2.json()[0]["stock_reserved"] == 0
                assert items_check2.json()[0]["stock_sold"] == 2

                # Verify updated name and email in list
                orders_list = await client.get(f"/api/v1/registration/events/{event_id}/orders", headers=headers)
                assert orders_list.status_code == 200
                orders_data = orders_list.json()
                assert len(orders_data) == 1
                assert orders_data[0]["full_name"] == "Pedro Actualizado"
                assert orders_data[0]["email"] == "pedro.nuevo@test.pe"
                assert orders_data[0]["payment_method"] == "YAPE"
                assert orders_data[0]["status"] == "PAID"

                # 5. Send order ticket email with branded QR
                email_res = await client.post(
                    f"/api/v1/registration/orders/{order_id}/send-email",
                    headers=headers,
                )
                assert email_res.status_code == 200
                assert email_res.json()["status"] == "ok"
                assert email_res.json()["recipient"] == "pedro.nuevo@test.pe"

                # 6. Delete order permanently and verify stock is restored and DNI freed
                del_res = await client.delete(f"/api/v1/registration/orders/{order_id}", headers=headers)
                assert del_res.status_code == 200
                assert del_res.json()["status"] == "deleted"

                # Stock sold must be restored to 0
                items_check3 = await client.get(f"/api/v1/registration/events/{event_id}/items")
                assert items_check3.json()[0]["stock_sold"] == 0
                assert items_check3.json()[0]["stock_reserved"] == 0

                # Orders list must now be empty
                orders_list2 = await client.get(f"/api/v1/registration/events/{event_id}/orders", headers=headers)
                assert len(orders_list2.json()) == 0

                # Now test that the same DNI can buy again (since previous order was deleted during tests)
                reorder_res = await client.post(
                    f"/api/v1/registration/events/{event_id}/orders",
                    json={
                        "dni": "44556677",
                        "full_name": "Pedro Test Nuevamente",
                        "email": "pedro@test.pe",
                        "items": [{"item_id": item_id, "quantity": 1}],
                    },
                    headers={"idempotency-key": "idemp-test-order-2"},
                )
                assert reorder_res.status_code == 201
                assert reorder_res.json()["status"] == "PENDING"


@pytest.mark.asyncio
async def test_smtp_config_lifecycle(tmp_path: Path, keys_dir: Path):
    """Test retrieving, updating and testing tenant SMTP settings."""
    reg_settings = RegistrationSettings(
        database_url=f"sqlite+aiosqlite:///{tmp_path}/reg_smtp.db",
        keys_dir=keys_dir,
        data_dir=tmp_path / "data",
    )
    reg_app = create_registration_app(reg_settings)
    priv_jwt, _ = ensure_ed25519_keypair(keys_dir, "jwt")
    token, _ = issue_jwt(
        priv_jwt,
        subject="admin-smtp",
        tenant_id="tenant-smtp-1",
        role="ADMIN",
        ttl_minutes=60,
    )
    headers = {"Authorization": f"Bearer {token}"}

    async with reg_app.router.lifespan_context(reg_app):
        async with AsyncClient(transport=ASGITransport(app=reg_app), base_url="http://test") as client:
            # 1. Default config
            get_res = await client.get("/api/v1/registration/email-config", headers=headers)
            assert get_res.status_code == 200
            data = get_res.json()
            assert data["tenant_id"] == "tenant-smtp-1"
            assert data["has_password"] is False

            # 2. Update config
            put_res = await client.put(
                "/api/v1/registration/email-config",
                json={
                    "smtp_enabled": True,
                    "smtp_host": "smtp.mailgun.org",
                    "smtp_port": 587,
                    "smtp_user": "postmaster@eventpass.pe",
                    "smtp_password": "super-secret-password-123",
                    "smtp_from_email": "tickets@eventpass.pe",
                    "smtp_from_name": "EventPass Notificaciones",
                    "smtp_use_tls": True,
                    "smtp_use_ssl": False,
                },
                headers=headers,
            )
            assert put_res.status_code == 200
            updated = put_res.json()
            assert updated["smtp_host"] == "smtp.mailgun.org"
            assert updated["has_password"] is True
            assert updated["smtp_from_name"] == "EventPass Notificaciones"

            # 3. Test email dispatch (falls back gracefully to simulation if host unreachable)
            test_res = await client.post(
                "/api/v1/registration/email-config/test",
                json={"recipient_email": "destinatario@test.pe"},
                headers=headers,
            )
            assert test_res.status_code == 200
            res_data = test_res.json()
            assert "recipient" in res_data
            assert res_data["recipient"] == "destinatario@test.pe"


@pytest.mark.asyncio
async def test_promoters_and_courtesy_codes_validity_and_lifecycle(tmp_path: Path, keys_dir: Path):
    """Test promoters CRUD, code batches with day/time validity, and expiration checks."""
    accred_settings = AccreditationSettings(
        database_url=f"sqlite+aiosqlite:///{tmp_path}/accred2.db",
        keys_dir=keys_dir,
        data_dir=tmp_path / "data",
    )
    accred_app = create_accreditation_app(accred_settings)

    def accred_factory():
        return AsyncClient(transport=ASGITransport(app=accred_app), base_url="http://test")

    reg_settings = RegistrationSettings(
        database_url=f"sqlite+aiosqlite:///{tmp_path}/reg2.db",
        keys_dir=keys_dir,
        data_dir=tmp_path / "data",
    )
    reg_app = create_registration_app(reg_settings, accreditation_client_factory=accred_factory)

    priv_jwt, _ = ensure_ed25519_keypair(keys_dir, "jwt")
    token, _ = issue_jwt(
        priv_jwt,
        subject="admin-prom",
        tenant_id="tenant-prom",
        role="ADMIN",
        ttl_minutes=60,
    )
    headers = {"Authorization": f"Bearer {token}"}

    async with accred_app.router.lifespan_context(accred_app):
        async with reg_app.router.lifespan_context(reg_app):
            async with AsyncClient(transport=ASGITransport(app=reg_app), base_url="http://test") as client:
                now = datetime.now(timezone.utc)
                ev_res = await client.post(
                    "/api/v1/registration/events",
                    json={
                        "name": "Concierto Rock 2026",
                        "slug": "concierto-rock",
                        "starts_at": (now + timedelta(days=2)).isoformat(),
                        "ends_at": (now + timedelta(days=3)).isoformat(),
                    },
                    headers=headers,
                )
                assert ev_res.status_code == 201
                event_id = ev_res.json()["id"]

                item_res = await client.post(
                    f"/api/v1/registration/events/{event_id}/items",
                    json={
                        "code": "VIP",
                        "name": "Zona VIP Rock",
                        "item_type": "ENTRY",
                        "price_cents": 12000,
                        "stock_total": 50,
                    },
                    headers=headers,
                )
                assert item_res.status_code == 201
                item_id = item_res.json()["id"]

                # 1. Create promoter
                prom_res = await client.post(
                    f"/api/v1/registration/events/{event_id}/promoters",
                    json={
                        "name": "Agencia RockFest",
                        "code_prefix": "ROCK",
                        "email": "rrpp@rockfest.pe",
                    },
                    headers=headers,
                )
                assert prom_res.status_code == 201
                promoter_id = prom_res.json()["id"]

                # 2. Update promoter
                patch_res = await client.patch(
                    f"/api/v1/registration/promoters/{promoter_id}",
                    json={
                        "name": "Agencia RockFest Oficial",
                        "code_prefix": "ROCKVIP",
                        "email": "contacto@rockfest.pe",
                    },
                    headers=headers,
                )
                assert patch_res.status_code == 200
                assert patch_res.json()["name"] == "Agencia RockFest Oficial"
                assert patch_res.json()["code_prefix"] == "ROCKVIP"

                # 3. Generate courtesy codes with validity day and 48-hour expiration
                batch_res = await client.post(
                    f"/api/v1/registration/events/{event_id}/codes/batch",
                    json={
                        "catalog_item_id": item_id,
                        "promoter_id": promoter_id,
                        "quantity": 3,
                        "valid_day": "Día 1 - Apertura",
                        "validity_hours": 48,
                    },
                    headers=headers,
                )
                assert batch_res.status_code == 201
                codes = batch_res.json()
                assert len(codes) == 3
                assert codes[0]["valid_day"] == "Día 1 - Apertura"
                assert codes[0]["expires_at"] is not None
                assert codes[0]["item_name"] == "Zona VIP Rock"
                assert codes[0]["promoter_name"] == "Agencia RockFest Oficial"

                # 4. List codes
                list_codes = await client.get(f"/api/v1/registration/events/{event_id}/codes", headers=headers)
                assert list_codes.status_code == 200
                assert len(list_codes.json()) == 3

                # 5. Update code valid day
                code_to_update = codes[0]["id"]
                upd_code = await client.patch(
                    f"/api/v1/registration/codes/{code_to_update}",
                    json={"valid_day": "Pase Completo"},
                    headers=headers,
                )
                assert upd_code.status_code == 200
                assert upd_code.json()["valid_day"] == "Pase Completo"

                # 6. Delete unredeemed code
                code_to_del = codes[1]["id"]
                del_code = await client.delete(f"/api/v1/registration/codes/{code_to_del}", headers=headers)
                assert del_code.status_code == 200
                assert del_code.json()["status"] == "deleted"

                # 7. Create already-expired code to verify expiration check during redemption
                exp_res = await client.post(
                    f"/api/v1/registration/events/{event_id}/codes/batch",
                    json={
                        "catalog_item_id": item_id,
                        "promoter_id": promoter_id,
                        "quantity": 1,
                        "valid_day": "Día 1",
                        "expires_at": (now - timedelta(hours=2)).isoformat(),
                    },
                    headers=headers,
                )
                assert exp_res.status_code == 201
                expired_code = exp_res.json()[0]["code"]

                redeem_fail = await client.post(
                    "/api/v1/registration/public/redeem-code",
                    json={
                        "event_id": event_id,
                        "code": expired_code,
                        "dni": "77889900",
                        "full_name": "Juan Expirado",
                        "email": "juan@test.pe",
                    },
                )
                assert redeem_fail.status_code == 409
                assert "expirado" in redeem_fail.json()["detail"].lower()

                # 8. Delete promoter
                del_prom = await client.delete(f"/api/v1/registration/promoters/{promoter_id}", headers=headers)
                assert del_prom.status_code == 200
                assert del_prom.json()["status"] == "deleted"


@pytest.mark.asyncio
async def test_physical_thermal_ticket_batches(tmp_path: Path, keys_dir: Path):
    """Test generating physical thermal ticket batches with sequential numbering and scannable QRs."""
    accred_settings = AccreditationSettings(
        database_url=f"sqlite+aiosqlite:///{tmp_path}/accred3.db",
        keys_dir=keys_dir,
        data_dir=tmp_path / "data",
    )
    accred_app = create_accreditation_app(accred_settings)

    def accred_factory():
        return AsyncClient(transport=ASGITransport(app=accred_app), base_url="http://test")

    reg_settings = RegistrationSettings(
        database_url=f"sqlite+aiosqlite:///{tmp_path}/reg3.db",
        keys_dir=keys_dir,
        data_dir=tmp_path / "data",
    )
    reg_app = create_registration_app(reg_settings, accreditation_client_factory=accred_factory)

    priv_jwt, _ = ensure_ed25519_keypair(keys_dir, "jwt")
    token, _ = issue_jwt(
        priv_jwt,
        subject="admin-thermal",
        tenant_id="tenant-thermal",
        role="ADMIN",
        ttl_minutes=60,
    )
    headers = {"Authorization": f"Bearer {token}"}

    async with accred_app.router.lifespan_context(accred_app):
        async with reg_app.router.lifespan_context(reg_app):
            async with AsyncClient(transport=ASGITransport(app=reg_app), base_url="http://test") as client:
                now = datetime.now(timezone.utc)
                ev_res = await client.post(
                    "/api/v1/registration/events",
                    json={
                        "name": "Feria Gastronómica Lima 2026",
                        "slug": "feria-gastro",
                        "starts_at": (now + timedelta(days=1)).isoformat(),
                        "ends_at": (now + timedelta(days=2)).isoformat(),
                        "venue": "Costa Verde, San Miguel",
                    },
                    headers=headers,
                )
                assert ev_res.status_code == 201
                event_id = ev_res.json()["id"]

                item_res = await client.post(
                    f"/api/v1/registration/events/{event_id}/items",
                    json={
                        "code": "GASTRO",
                        "name": "Pase General Gastronomía",
                        "item_type": "ENTRY",
                        "price_cents": 3500,
                        "stock_total": 100,
                    },
                    headers=headers,
                )
                assert item_res.status_code == 201
                item_id = item_res.json()["id"]

                # 1. Create physical ticket batch (5 units, 80mm roll, sequential prefix GASTRO)
                batch_res = await client.post(
                    f"/api/v1/registration/events/{event_id}/physical-tickets/batches",
                    json={
                        "catalog_item_id": item_id,
                        "batch_name": "Boletería Puerta Principal",
                        "quantity": 5,
                        "prefix": "GAST",
                        "start_sequence": 1,
                        "paper_width": "80mm",
                    },
                    headers=headers,
                )
                assert batch_res.status_code == 201
                batch_data = batch_res.json()
                batch_id = batch_data["id"]
                assert batch_data["quantity"] == 5
                assert batch_data["start_sequence"] == 1
                assert batch_data["end_sequence"] == 5

                # Verify stock deducted
                items_res = await client.get(f"/api/v1/registration/events/{event_id}/items")
                assert items_res.json()[0]["stock_sold"] == 5

                # 2. List physical ticket batches
                list_res = await client.get(
                    f"/api/v1/registration/events/{event_id}/physical-tickets/batches",
                    headers=headers,
                )
                assert list_res.status_code == 200
                assert len(list_res.json()) == 1

                # 3. Retrieve batch detail with serialized tickets and valid QRs
                detail_res = await client.get(
                    f"/api/v1/registration/physical-tickets/batches/{batch_id}",
                    headers=headers,
                )
                assert detail_res.status_code == 200
                detail = detail_res.json()
                assert detail["event_name"] == "Feria Gastronómica Lima 2026"
                assert len(detail["tickets"]) == 5
                first_ticket = detail["tickets"][0]
                assert first_ticket["ticket_number"] == "GAST-0001"
                assert first_ticket["qr_token"] != ""
                assert first_ticket["credential_id"] != ""
                last_ticket = detail["tickets"][4]
                assert last_ticket["ticket_number"] == "GAST-0005"

                # 4. Delete batch and verify stock is restored
                del_res = await client.delete(
                    f"/api/v1/registration/physical-tickets/batches/{batch_id}",
                    headers=headers,
                )
                assert del_res.status_code == 200
                assert del_res.json()["status"] == "deleted"

                # Check stock returned
                items_restored = await client.get(f"/api/v1/registration/events/{event_id}/items")
                assert items_restored.json()[0]["stock_sold"] == 0
