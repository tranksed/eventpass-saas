"""Offline contingency verifier for validator gate devices.

Allows a validator device to verify QR credentials cryptographically with zero
network connectivity using the downloaded Ed25519 public key and local snapshot.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

import jwt

from services.accreditation_service.schemas import OfflineBundleResponse
from shared_kernel.crypto import pem_to_public_key, verify_qr_credential


@dataclass
class OfflineVerifyResult:
    valid: bool
    outcome: str
    credential_id: str | None
    display_name: str | None
    dni_last4: str | None
    holder_type: str | None
    remaining_for_code: int


def verify_offline_bundle_integrity(bundle: OfflineBundleResponse) -> bool:
    """Verify the Ed25519 signature over the offline contingency snapshot."""
    pub_key = pem_to_public_key(bundle.qr_public_key_pem)
    claims = jwt.decode(bundle.bundle_token, pub_key, algorithms=["EdDSA"])
    snapshot_bytes = json.dumps(
        [c.model_dump() for c in bundle.credentials], sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    expected_digest = hashlib.sha256(snapshot_bytes).hexdigest()
    return (
        claims.get("tid") == bundle.tenant_id
        and claims.get("eid") == bundle.event_id
        and claims.get("digest") == expected_digest
    )


def verify_qr_in_contingency_mode(
    *,
    qr_token: str,
    bundle: OfflineBundleResponse,
    local_redeemed_counts: dict[str, dict[str, int]],
    entitlement_code: str = "ENTRY",
) -> OfflineVerifyResult:
    """Validate a QR completely offline using Ed25519 signature + snapshot state."""
    pub_key = pem_to_public_key(bundle.qr_public_key_pem)
    try:
        claims = verify_qr_credential(qr_token, pub_key)
    except jwt.InvalidTokenError:
        return OfflineVerifyResult(False, "INVALID_SIGNATURE_OR_EXPIRED", None, None, None, None, 0)

    if claims.get("tid") != bundle.tenant_id or claims.get("eid") != bundle.event_id:
        return OfflineVerifyResult(False, "TENANT_OR_EVENT_MISMATCH", None, None, None, None, 0)

    cred_id = claims["cid"]
    snap_by_id = {c.credential_id: c for c in bundle.credentials}
    snap = snap_by_id.get(cred_id)

    if snap is not None and snap.status != "ACTIVE":
        return OfflineVerifyResult(
            False, "REVOKED", cred_id, snap.display_name, snap.dni_last4, snap.holder_type, 0
        )

    entitlements = snap.entitlements if snap is not None else claims.get("ent", {})
    allowed = int(entitlements.get(entitlement_code, 0))
    already_redeemed = int((snap.redeemed.get(entitlement_code, 0) if snap else 0)) + int(
        local_redeemed_counts.get(cred_id, {}).get(entitlement_code, 0)
    )
    remaining = allowed - already_redeemed

    if remaining <= 0:
        return OfflineVerifyResult(
            False,
            "ALREADY_REDEEMED_OR_NOT_ENTITLED",
            cred_id,
            snap.display_name if snap else None,
            claims.get("d4"),
            claims.get("ht"),
            0,
        )

    # Record offline redemption in local device state
    local_redeemed_counts.setdefault(cred_id, {})
    local_redeemed_counts[cred_id][entitlement_code] = (
        local_redeemed_counts[cred_id].get(entitlement_code, 0) + 1
    )
    return OfflineVerifyResult(
        True,
        "OFFLINE_GRANTED",
        cred_id,
        snap.display_name if snap else "Verified Offline Holder",
        claims.get("d4"),
        claims.get("ht"),
        remaining - 1,
    )
