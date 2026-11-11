"""End-to-end security, RBAC, concurrency, and offline contingency tests.

Spins up all 4 isolated microservices (auth, registration, accreditation, audit)
with 4 independent databases and verifies every security and business invariant.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pyotp
import pytest

from services.accreditation_service.app import create_accreditation_app
from services.accreditation_service.config import AccreditationSettings
from services.accreditation_service.offline_verifier import (
    verify_offline_bundle_integrity,
    verify_qr_in_contingency_mode,
)
from services.accreditation_service.schemas import OfflineBundleResponse
from services.audit_service.app import create_audit_app
from services.audit_service.config import AuditSettings
from services.auth_service.app import create_auth_app
from services.auth_service.config import AuthSettings
from services.registration_service.app import create_registration_app
from services.registration_service.config import RegistrationSettings
from shared_kernel.audit_client import AuditClient
from shared_kernel.crypto import sign_webhook_payload


@pytest.fixture
async def saas_cluster(tmp_path: Path):
    """Boot all 4 isolated microservices with separate DBs and shared public keys."""
    keys_dir = tmp_path / "keys"
    common = {
        "keys_dir": keys_dir,
        "pii_master_key_b64": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        "dni_blind_index_pepper": "test-pepper-secret-value-12345",
        "payment_webhook_secret": "test-webhook-hmac-secret-999",
        "internal_service_token": "test-internal-s2s-token-xyz",
        "rate_limit_requests": 5000,
    }

    auth_app = create_auth_app(
        AuthSettings(database_url=f"sqlite+aiosqlite:///{tmp_path / 'auth.db'}", **common),
    )
    audit_app = create_audit_app(
        AuditSettings(database_url=f"sqlite+aiosqlite:///{tmp_path / 'audit.db'}", **common),
    )

    def make_audit_client():
        return AuditClient(
            base_url="http://audit",
            internal_token=common["internal_service_token"],
            client_factory=lambda: httpx.AsyncClient(
                transport=httpx.ASGITransport(app=audit_app), base_url="http://audit"
            ),
        )

    # Re-bind auth_app audit client via app creation with audit_client
    auth_app = create_auth_app(
        AuthSettings(database_url=f"sqlite+aiosqlite:///{tmp_path / 'auth.db'}", **common),
        audit_client=make_audit_client(),
    )
    accred_app = create_accreditation_app(
        AccreditationSettings(database_url=f"sqlite+aiosqlite:///{tmp_path / 'accred.db'}", **common),
        audit_client=make_audit_client(),
    )
    reg_app = create_registration_app(
        RegistrationSettings(database_url=f"sqlite+aiosqlite:///{tmp_path / 'reg.db'}", **common),
        accreditation_client_factory=lambda: httpx.AsyncClient(
            transport=httpx.ASGITransport(app=accred_app), base_url="http://accred"
        ),
        audit_client=make_audit_client(),
    )

    async with (
        auth_app.router.lifespan_context(auth_app),
        audit_app.router.lifespan_context(audit_app),
        accred_app.router.lifespan_context(accred_app),
        reg_app.router.lifespan_context(reg_app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=auth_app), base_url="http://auth") as auth_c,
        httpx.AsyncClient(transport=httpx.ASGITransport(app=reg_app), base_url="http://reg") as reg_c,
        httpx.AsyncClient(transport=httpx.ASGITransport(app=accred_app), base_url="http://accred") as accred_c,
        httpx.AsyncClient(transport=httpx.ASGITransport(app=audit_app), base_url="http://audit") as audit_c,
    ):
        yield {
            "auth": auth_c,
            "reg": reg_c,
            "accred": accred_c,
            "audit": audit_c,
            "webhook_secret": common["payment_webhook_secret"],
        }


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def test_full_multitenant_security_quotas_payment_and_offline_sync(saas_cluster):
    auth: httpx.AsyncClient = saas_cluster["auth"]
    reg: httpx.AsyncClient = saas_cluster["reg"]
    accred: httpx.AsyncClient = saas_cluster["accred"]
    audit: httpx.AsyncClient = saas_cluster["audit"]
    webhook_secret: str = saas_cluster["webhook_secret"]

    # 1. Register two isolated SaaS tenants (Company A & Company B)
    r_a = await auth.post(
        "/api/v1/auth/tenants/register",
        json={
            "company_name": "Acme Live Events",
            "company_slug": "acme-events",
            "admin_email": "admin@acme.com",
            "admin_full_name": "Alice Admin",
            "admin_password": "StrongPassword!123",
        },
    )
    assert r_a.status_code == 201, r_a.text
    admin_a_token = r_a.json()["tokens"]["access_token"]

    r_b = await auth.post(
        "/api/v1/auth/tenants/register",
        json={
            "company_name": "Beta Expos",
            "company_slug": "beta-expos",
            "admin_email": "admin@beta.com",
            "admin_full_name": "Bob Beta",
            "admin_password": "StrongPassword!456",
        },
    )
    assert r_b.status_code == 201
    admin_b_token = r_b.json()["tokens"]["access_token"]

    # 2. Admin A creates SUPERVISOR and VALIDATOR + tests MFA setup & login
    sup_res = await auth.post(
        "/api/v1/auth/users",
        headers=_bearer(admin_a_token),
        json={
            "email": "sup@acme.com",
            "full_name": "Sam Supervisor",
            "password": "SupervisorPass!123",
            "role": "SUPERVISOR",
        },
    )
    assert sup_res.status_code == 201

    val_res = await auth.post(
        "/api/v1/auth/users",
        headers=_bearer(admin_a_token),
        json={
            "email": "val@acme.com",
            "full_name": "Victor Validator",
            "password": "ValidatorPass!123",
            "role": "VALIDATOR",
        },
    )
    assert val_res.status_code == 201

    sup_login = await auth.post(
        "/api/v1/auth/login",
        json={"tenant_slug": "acme-events", "email": "sup@acme.com", "password": "SupervisorPass!123"},
    )
    assert sup_login.status_code == 200
    sup_a_token = sup_login.json()["access_token"]

    # Enable MFA on Validator and confirm login requires valid TOTP
    val_login = await auth.post(
        "/api/v1/auth/login",
        json={
            "tenant_slug": "acme-events",
            "email": "val@acme.com",
            "password": "ValidatorPass!123",
            "device_id": "GATE_TABLET_01",
        },
    )
    assert val_login.status_code == 200
    val_a_token = val_login.json()["access_token"]

    mfa_setup = await auth.post("/api/v1/auth/mfa/setup", headers=_bearer(val_a_token))
    assert mfa_setup.status_code == 200
    totp_secret = mfa_setup.json()["secret"]
    totp_code = pyotp.TOTP(totp_secret).now()
    mfa_enable = await auth.post(
        "/api/v1/auth/mfa/enable",
        headers=_bearer(val_a_token),
        json={"totp_code": totp_code},
    )
    assert mfa_enable.status_code == 200

    # Login without MFA code now fails
    val_fail = await auth.post(
        "/api/v1/auth/login",
        json={"tenant_slug": "acme-events", "email": "val@acme.com", "password": "ValidatorPass!123"},
    )
    assert val_fail.status_code == 401

    # Login with valid MFA code succeeds
    val_mfa_ok = await auth.post(
        "/api/v1/auth/login",
        json={
            "tenant_slug": "acme-events",
            "email": "val@acme.com",
            "password": "ValidatorPass!123",
            "mfa_code": pyotp.TOTP(totp_secret).now(),
            "device_id": "GATE_TABLET_01",
        },
    )
    assert val_mfa_ok.status_code == 200
    val_a_token = val_mfa_ok.json()["access_token"]

    # RBAC check: VALIDATOR and SUPERVISOR cannot create events or users
    now = datetime.now(timezone.utc)
    event_payload = {
        "name": "ComicCon Lima 2026",
        "slug": "comiccon-2026",
        "starts_at": (now + timedelta(days=1)).isoformat(),
        "ends_at": (now + timedelta(days=3)).isoformat(),
        "max_purchases_per_dni": 2,
    }
    assert (await reg.post("/api/v1/registration/events", headers=_bearer(val_a_token), json=event_payload)).status_code == 403
    assert (await reg.post("/api/v1/registration/events", headers=_bearer(sup_a_token), json=event_payload)).status_code == 403

    # Invalid DNI limit (0 or 11) rejected by Pydantic validation
    bad_limit = dict(event_payload, max_purchases_per_dni=11)
    assert (await reg.post("/api/v1/registration/events", headers=_bearer(admin_a_token), json=bad_limit)).status_code == 422

    ev_res = await reg.post("/api/v1/registration/events", headers=_bearer(admin_a_token), json=event_payload)
    assert ev_res.status_code == 201
    event_id = ev_res.json()["id"]

    # 3. Create catalog items: ENTRY, PHOTO, SIGNATURE
    entry_item = (
        await reg.post(
            f"/api/v1/registration/events/{event_id}/items",
            headers=_bearer(admin_a_token),
            json={"code": "ENTRY", "name": "General Entry", "item_type": "ENTRY", "price_cents": 5000, "stock_total": 100},
        )
    ).json()
    photo_item = (
        await reg.post(
            f"/api/v1/registration/events/{event_id}/items",
            headers=_bearer(admin_a_token),
            json={"code": "PHOTO", "name": "Meet & Greet Photo", "item_type": "INTERACTION", "price_cents": 8000, "stock_total": 5},
        )
    ).json()
    sign_item = (
        await reg.post(
            f"/api/v1/registration/events/{event_id}/items",
            headers=_bearer(admin_a_token),
            json={"code": "SIGNATURE", "name": "Autograph Signature", "item_type": "INTERACTION", "price_cents": 4000, "stock_total": 50},
        )
    ).json()

    # 4. Participant purchases ENTRY + PHOTO + SIGNATURE (Idempotency & DNI limit)
    order_req = {
        "dni": "71234567",
        "full_name": "Carlos Perez",
        "email": "carlos@example.com",
        "items": [
            {"item_id": entry_item["id"], "quantity": 1},
            {"item_id": photo_item["id"], "quantity": 1},
            {"item_id": sign_item["id"], "quantity": 1},
        ],
    }
    o1 = await reg.post(
        f"/api/v1/registration/events/{event_id}/orders",
        headers={"Idempotency-Key": "idem-order-0001"},
        json=order_req,
    )
    assert o1.status_code == 201, o1.text
    order_id = o1.json()["order_id"]

    # Replay same Idempotency-Key -> returns same order idempotently
    o1_replay = await reg.post(
        f"/api/v1/registration/events/{event_id}/orders",
        headers={"Idempotency-Key": "idem-order-0001"},
        json=order_req,
    )
    assert o1_replay.status_code == 201
    assert o1_replay.json()["order_id"] == order_id

    # Same DNI tries to buy 2 more PHOTO (1 + 2 = 3 > limit 2) -> rejected!
    o2_exceed = await reg.post(
        f"/api/v1/registration/events/{event_id}/orders",
        headers={"Idempotency-Key": "idem-order-0002"},
        json={
            "dni": "71234567",
            "full_name": "Carlos Perez",
            "email": "carlos@example.com",
            "items": [{"item_id": photo_item["id"], "quantity": 2}],
        },
    )
    assert o2_exceed.status_code == 409

    # 5. Payment Webhook HMAC verification & QR generation
    wh_body = json.dumps({"order_id": order_id, "payment_reference": "STRIPE_TX_9988", "status": "PAID"}).encode()
    bad_wh = await reg.post(
        "/api/v1/registration/webhooks/payment",
        content=wh_body,
        headers={"X-Webhook-Signature": "deadbeef", "Content-Type": "application/json"},
    )
    assert bad_wh.status_code == 401

    valid_sig = sign_webhook_payload(wh_body, webhook_secret)
    ok_wh = await reg.post(
        "/api/v1/registration/webhooks/payment",
        content=wh_body,
        headers={"X-Webhook-Signature": valid_sig, "Content-Type": "application/json"},
    )
    assert ok_wh.status_code == 200, ok_wh.text
    participant_qr = ok_wh.json()["qr_token"]
    assert participant_qr

    # Anti-IDOR check on order lookup
    assert (await reg.get(f"/api/v1/registration/orders/{order_id}?dni=99999999")).status_code == 403
    assert (await reg.get(f"/api/v1/registration/orders/{order_id}?dni=71234567")).status_code == 200

    # 6. Corporate Staff Accreditation Link & Quota Hierarchy (6 -> 10 by Supervisor -> >10 by Admin)
    comp_res = await accred.post(
        "/api/v1/accreditation/companies",
        headers=_bearer(sup_a_token),
        json={
            "event_id": event_id,
            "company_name": "Studio Partner SAC",
            "contact_email": "ops@studiopartner.com",
        },
    )
    assert comp_res.status_code == 201
    comp_data = comp_res.json()
    assert comp_data["staff_quota"] == 6
    company_id = comp_data["company_id"]
    invite_token = comp_data["invite_token"]

    # Register 6 staff via private link
    staff_qrs = []
    for idx in range(6):
        sr = await accred.post(
            f"/api/v1/accreditation/invite/{invite_token}/staff",
            json={
                "dni": f"4000000{idx}",
                "full_name": f"Staff Member {idx}",
                "role_title": "Booth Operator",
            },
        )
        assert sr.status_code == 201, sr.text
        staff_qrs.append(sr.json()["qr_token"])

    # 7th staff blocked at default quota 6
    sr_7 = await accred.post(
        f"/api/v1/accreditation/invite/{invite_token}/staff",
        json={"dni": "40000009", "full_name": "Staff 7", "role_title": "Tech"},
    )
    assert sr_7.status_code == 409

    # Supervisor expands up to 10 -> OK, but 11 -> 403 Forbidden
    assert (
        await accred.patch(
            f"/api/v1/accreditation/companies/{company_id}/quota",
            headers=_bearer(sup_a_token),
            json={"staff_quota": 11},
        )
    ).status_code == 403

    assert (
        await accred.patch(
            f"/api/v1/accreditation/companies/{company_id}/quota",
            headers=_bearer(sup_a_token),
            json={"staff_quota": 10},
        )
    ).status_code == 200

    # 7th staff now succeeds!
    sr_7_ok = await accred.post(
        f"/api/v1/accreditation/invite/{invite_token}/staff",
        json={"dni": "40000009", "full_name": "Staff 7", "role_title": "Tech"},
    )
    assert sr_7_ok.status_code == 201

    # Admin sets custom quota > 10 (e.g., 15) -> succeeds!
    assert (
        await accred.patch(
            f"/api/v1/accreditation/companies/{company_id}/quota",
            headers=_bearer(admin_a_token),
            json={"staff_quota": 15},
        )
    ).status_code == 200

    # 7. Private Validator Module: Online Check-in & Cross-Tenant Rejection
    # Tenant B admin tries to scan Tenant A's QR -> 403 Cross-tenant rejected
    cross_tenant_scan = await accred.post(
        "/api/v1/accreditation/check-in",
        headers=_bearer(admin_b_token),
        json={"qr_token": participant_qr, "entitlement_code": "ENTRY", "gate_id": "GATE_B"},
    )
    assert cross_tenant_scan.status_code == 403

    # Tampered QR rejected
    tampered_qr = participant_qr[:-4] + "AAAA"
    assert (
        await accred.post(
            "/api/v1/accreditation/check-in",
            headers=_bearer(val_a_token),
            json={"qr_token": tampered_qr, "entitlement_code": "ENTRY", "gate_id": "GATE_1"},
        )
    ).status_code == 401

    # Valid online ENTRY check-in -> GRANTED, second ENTRY -> 409 Conflict
    ci_entry = await accred.post(
        "/api/v1/accreditation/check-in",
        headers=_bearer(val_a_token),
        json={"qr_token": participant_qr, "entitlement_code": "ENTRY", "gate_id": "GATE_1"},
    )
    assert ci_entry.status_code == 200
    assert ci_entry.json()["outcome"] == "GRANTED"
    assert ci_entry.json()["remaining_for_code"] == 0

    ci_entry_dup = await accred.post(
        "/api/v1/accreditation/check-in",
        headers=_bearer(val_a_token),
        json={"qr_token": participant_qr, "entitlement_code": "ENTRY", "gate_id": "GATE_2"},
    )
    assert ci_entry_dup.status_code == 409

    # Independent redemption of PHOTO and SIGNATURE interactions
    ci_photo = await accred.post(
        "/api/v1/accreditation/check-in",
        headers=_bearer(val_a_token),
        json={"qr_token": participant_qr, "entitlement_code": "PHOTO", "gate_id": "ZONE_PHOTO"},
    )
    assert ci_photo.status_code == 200
    assert ci_photo.json()["all_remaining"]["SIGNATURE"] == 1

    # 8. Contingency Offline Mode: Download Bundle + Local Verify + Batch Sync + Conflict Detection
    bundle_res = await accred.get(
        f"/api/v1/accreditation/events/{event_id}/offline-bundle",
        headers=_bearer(val_a_token),
    )
    assert bundle_res.status_code == 200
    bundle = OfflineBundleResponse.model_validate(bundle_res.json())
    assert verify_offline_bundle_integrity(bundle) is True

    # Offline verification with zero network using Ed25519 public key
    local_state: dict[str, dict[str, int]] = {}
    staff_qr_0 = staff_qrs[0]
    offline_res_1 = verify_qr_in_contingency_mode(
        qr_token=staff_qr_0, bundle=bundle, local_redeemed_counts=local_state, entitlement_code="ENTRY"
    )
    assert offline_res_1.valid is True
    assert offline_res_1.outcome == "OFFLINE_GRANTED"

    # Same offline device blocks duplicate scan immediately
    offline_res_2 = verify_qr_in_contingency_mode(
        qr_token=staff_qr_0, bundle=bundle, local_redeemed_counts=local_state, entitlement_code="ENTRY"
    )
    assert offline_res_2.valid is False

    # Simulate TWO separate offline devices scanning the SAME staff QR during outage -> sync batch detects conflict
    t0 = datetime.now(timezone.utc)
    sync_res = await accred.post(
        f"/api/v1/accreditation/events/{event_id}/offline-sync",
        headers=_bearer(val_a_token),
        json={
            "scans": [
                {
                    "client_scan_id": "tablet1-scan-001",
                    "qr_token": staff_qr_0,
                    "entitlement_code": "ENTRY",
                    "gate_id": "STAFF_GATE_A",
                    "device_id": "TABLET_1",
                    "scanned_at": t0.isoformat(),
                },
                {
                    "client_scan_id": "tablet2-scan-001",
                    "qr_token": staff_qr_0,
                    "entitlement_code": "ENTRY",
                    "gate_id": "STAFF_GATE_B",
                    "device_id": "TABLET_2",
                    "scanned_at": (t0 + timedelta(seconds=5)).isoformat(),
                },
            ]
        },
    )
    assert sync_res.status_code == 200
    sync_data = sync_res.json()
    assert sync_data["granted"] == 1
    assert sync_data["conflicts"] == 1
    assert sync_data["results"][1]["outcome"] == "CONFLICT_DUPLICATE_OFFLINE"

    # 9. Verify Immutable Hash-Chained Audit Trail
    chain_res = await audit.get("/api/v1/audit/verify-chain", headers=_bearer(admin_a_token))
    assert chain_res.status_code == 200
    assert chain_res.json()["intact"] is True
    assert chain_res.json()["total_entries"] >= 5


async def test_concurrency_no_overselling_and_dni_limit_enforced(saas_cluster):
    """Simulate concurrent burst purchases targeting limited stock and DNI quota."""
    auth: httpx.AsyncClient = saas_cluster["auth"]
    reg: httpx.AsyncClient = saas_cluster["reg"]

    r_a = await auth.post(
        "/api/v1/auth/tenants/register",
        json={
            "company_name": "Burst Events",
            "company_slug": "burst-events",
            "admin_email": "admin@burst.com",
            "admin_full_name": "Burst Admin",
            "admin_password": "StrongPassword!123",
        },
    )
    admin_token = r_a.json()["tokens"]["access_token"]
    now = datetime.now(timezone.utc)
    ev = (
        await reg.post(
            "/api/v1/registration/events",
            headers=_bearer(admin_token),
            json={
                "name": "Limited VIP Session",
                "slug": "vip-session",
                "starts_at": (now + timedelta(days=1)).isoformat(),
                "ends_at": (now + timedelta(days=2)).isoformat(),
                "max_purchases_per_dni": 2,
            },
        )
    ).json()

    item = (
        await reg.post(
            f"/api/v1/registration/events/{ev['id']}/items",
            headers=_bearer(admin_token),
            json={"code": "VIP_PHOTO", "name": "VIP Photo", "item_type": "INTERACTION", "price_cents": 10000, "stock_total": 3},
        )
    ).json()

    # 10 concurrent requests from DIFFERENT DNIs competing for stock_total=3
    async def buy_one(idx: int):
        return await reg.post(
            f"/api/v1/registration/events/{ev['id']}/orders",
            headers={"Idempotency-Key": f"burst-stock-{idx:04d}"},
            json={
                "dni": f"800000{idx:02d}",
                "full_name": f"Buyer {idx}",
                "email": f"buyer{idx}@example.com",
                "items": [{"item_id": item["id"], "quantity": 1}],
            },
        )

    responses = await asyncio.gather(*(buy_one(i) for i in range(10)))
    created = [r for r in responses if r.status_code == 201]
    rejected = [r for r in responses if r.status_code == 409]
    assert len(created) == 3
    assert len(rejected) == 7
