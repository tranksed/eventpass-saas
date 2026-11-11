"""Live walkthrough against the 4 running microservices on ports 8001-8004."""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone

import httpx

from shared_kernel.config import get_base_settings
from shared_kernel.crypto import sign_webhook_payload


def main() -> None:
    cfg = get_base_settings()
    services = {
        "auth": "http://127.0.0.1:8001",
        "registration": "http://127.0.0.1:8002",
        "accreditation": "http://127.0.0.1:8003",
        "audit": "http://127.0.0.1:8004",
    }

    print("=== 1. HEALTH CHECKS ===")
    for name, url in services.items():
        r = httpx.get(f"{url}/health", timeout=5.0)
        print(f"  [{name}] {r.status_code} -> {r.json()}")

    suffix = secrets.token_hex(3)
    print("\n=== 2. CREANDO EMPRESA (TENANT) + ADMIN + SUPERVISOR + VALIDATOR ===")
    t_res = httpx.post(
        f"{services['auth']}/api/v1/auth/tenants/register",
        json={
            "company_name": f"Demo Events {suffix}",
            "company_slug": f"demo-{suffix}",
            "admin_email": "admin@demo.com",
            "admin_full_name": "Ana Admin",
            "admin_password": "DemoPassword!123",
        },
        timeout=5.0,
    )
    t_res.raise_for_status()
    t_data = t_res.json()
    admin_token = t_data["tokens"]["access_token"]
    print(f"  Tenant ID: {t_data['tenant_id']} | Admin JWT issued (EdDSA)")

    val_res = httpx.post(
        f"{services['auth']}/api/v1/auth/users",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "email": "validador@demo.com",
            "full_name": "Validador Puerta 1",
            "password": "ValPassword!123",
            "role": "VALIDATOR",
        },
        timeout=5.0,
    )
    val_res.raise_for_status()
    val_login = httpx.post(
        f"{services['auth']}/api/v1/auth/login",
        json={
            "tenant_slug": f"demo-{suffix}",
            "email": "validador@demo.com",
            "password": "ValPassword!123",
            "device_id": "PUERTA_VIP_01",
        },
        timeout=5.0,
    )
    val_token = val_login.json()["access_token"]
    print(f"  Validator ID: {val_res.json()['id']} | Role: {val_res.json()['role']}")

    print("\n=== 3. EVENTO (LIMITE DNI=3) + COMPRA DE ENTRADA + FOTO + FIRMA ===")
    now = datetime.now(timezone.utc)
    ev = httpx.post(
        f"{services['registration']}/api/v1/registration/events",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Festival Tech 2026",
            "slug": f"fest-{suffix}",
            "starts_at": (now + timedelta(days=1)).isoformat(),
            "ends_at": (now + timedelta(days=2)).isoformat(),
            "max_purchases_per_dni": 3,
        },
        timeout=5.0,
    ).json()

    entry = httpx.post(
        f"{services['registration']}/api/v1/registration/events/{ev['id']}/items",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"code": "ENTRY", "name": "Entrada General", "item_type": "ENTRY", "price_cents": 5000, "stock_total": 500},
        timeout=5.0,
    ).json()
    photo = httpx.post(
        f"{services['registration']}/api/v1/registration/events/{ev['id']}/items",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"code": "PHOTO", "name": "Foto con Artista", "item_type": "INTERACTION", "price_cents": 8000, "stock_total": 100},
        timeout=5.0,
    ).json()

    order = httpx.post(
        f"{services['registration']}/api/v1/registration/events/{ev['id']}/orders",
        headers={"Idempotency-Key": f"demo-idem-{suffix}"},
        json={
            "dni": "74561234",
            "full_name": "Lucia Mendoza",
            "email": "lucia@example.com",
            "items": [
                {"item_id": entry["id"], "quantity": 1},
                {"item_id": photo["id"], "quantity": 1},
            ],
        },
        timeout=5.0,
    ).json()
    print(f"  Order {order['order_id']} creada | DNI enmascarado: {order['dni_last4']} | Estado: {order['status']}")

    wh_body = json.dumps({"order_id": order["order_id"], "payment_reference": f"PAY_{suffix}", "status": "PAID"}).encode()
    wh_sig = sign_webhook_payload(wh_body, cfg.payment_webhook_secret)
    wh = httpx.post(
        f"{services['registration']}/api/v1/registration/webhooks/payment",
        content=wh_body,
        headers={"X-Webhook-Signature": wh_sig, "Content-Type": "application/json"},
        timeout=5.0,
    ).json()
    print(f"  Pago confirmado -> Credential ID: {wh['credential_id']}")
    print(f"  QR Token (Ed25519 JWS): {wh['qr_token'][:55]}...")

    print("\n=== 4. ACREDITACION PRIVADA DE STAFF (CUPO DEFAULT 6) + CHECK-IN ===")
    comp = httpx.post(
        f"{services['accreditation']}/api/v1/accreditation/companies",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"event_id": ev["id"], "company_name": "Producciones Alfa", "contact_email": "ops@alfa.com"},
        timeout=5.0,
    ).json()
    staff = httpx.post(
        f"{services['accreditation']}/api/v1/accreditation/invite/{comp['invite_token']}/staff",
        json={"dni": "41234567", "full_name": "Marco Torres", "role_title": "Camarografo"},
        timeout=5.0,
    ).json()
    print(f"  Empresa '{comp['company_name']}' (Cupo: {comp['staff_quota']}) -> Staff registrado, cupo restante: {staff['remaining_quota']}")

    ci = httpx.post(
        f"{services['accreditation']}/api/v1/accreditation/check-in",
        headers={"Authorization": f"Bearer {val_token}"},
        json={"qr_token": wh["qr_token"], "entitlement_code": "ENTRY", "gate_id": "PUERTA_A"},
        timeout=5.0,
    ).json()
    print(f"  Check-in Online -> {ci['outcome']} | Titular: {ci['display_name']} ({ci['dni_last4']}) | Restantes: {ci['all_remaining']}")

    chain = httpx.get(
        f"{services['audit']}/api/v1/audit/verify-chain",
        headers={"Authorization": f"Bearer {admin_token}"},
        timeout=5.0,
    ).json()
    print(f"\n=== 5. AUDITORIA INMUTABLE ===\n  Hash-chain intacta: {chain['intact']} | Registros totales: {chain['total_entries']}")


if __name__ == "__main__":
    main()
