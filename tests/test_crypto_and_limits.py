"""Unit tests for cryptographic primitives, PII encryption, blind indexing, and QR PNG rendering."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from shared_kernel.crypto import (
    PIIEncryptor,
    ensure_ed25519_keypair,
    hash_password,
    mask_dni,
    normalize_dni,
    sign_qr_credential,
    verify_password,
    verify_qr_credential,
)


def test_dni_normalization_masking_and_scoped_blind_index():
    assert normalize_dni(" 7123-4567 ") == "71234567"
    assert mask_dni("71234567") == "****4567"

    with pytest.raises(ValueError):
        normalize_dni("123")

    enc = PIIEncryptor("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", "pepper-123")
    idx_t1 = enc.blind_index_dni("tenant-1", "evt-1", "71234567")
    idx_t2 = enc.blind_index_dni("tenant-2", "evt-1", "71234567")
    assert idx_t1 != idx_t2  # Cross-tenant correlation prevented

    ct = enc.encrypt("71234567", aad="evt-1")
    assert "71234567" not in ct
    assert enc.decrypt(ct, aad="evt-1") == "71234567"


def test_scrypt_password_hashing():
    hashed = hash_password("MyUltraSecurePass!99")
    assert verify_password("MyUltraSecurePass!99", hashed) is True
    assert verify_password("WrongPass!99", hashed) is False


def test_ed25519_qr_roundtrip(tmp_path: Path):
    priv, pub = ensure_ed25519_keypair(tmp_path, "qr")
    token = sign_qr_credential(
        priv,
        cred_id="cred-1",
        tenant_id="tenant-1",
        event_id="evt-1",
        holder_type="PARTICIPANT",
        dni_last4="****4567",
        entitlements={"ENTRY": 1, "PHOTO": 1, "SIGNATURE": 2},
        expires_at=datetime.now(timezone.utc) + timedelta(hours=12),
    )
    claims = verify_qr_credential(token, pub)
    assert claims["cid"] == "cred-1"
    assert claims["ent"]["SIGNATURE"] == 2
