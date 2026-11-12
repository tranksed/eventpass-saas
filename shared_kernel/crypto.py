"""Cryptographic primitives for EventPass SaaS.

Provides:
- Ed25519 asymmetric signing/verification for JWTs and offline-verifiable QR credentials.
- AES-256-GCM authenticated encryption for PII (DNI, phone, personal details).
- Scoped HMAC-SHA256 blind indexing for DNI quota enforcement without storing plaintext DNIs.
- Scrypt password hashing and constant-time HMAC webhook signature verification.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_DNI_CLEAN_RE = re.compile(r"[^A-Z0-9]")


def normalize_dni(raw_dni: str) -> str:
    """Normalize a DNI / national ID to uppercase alphanumeric characters."""
    cleaned = _DNI_CLEAN_RE.sub("", raw_dni.strip().upper())
    if len(cleaned) < 6 or len(cleaned) > 20:
        raise ValueError("DNI must contain between 6 and 20 alphanumeric characters.")
    return cleaned


def mask_dni(raw_dni: str) -> str:
    """Return last 4 characters masked representation (e.g. '****5678')."""
    cleaned = normalize_dni(raw_dni)
    return f"****{cleaned[-4:]}"


def hash_password(password: str) -> str:
    """Hash password with scrypt and a random 16-byte salt."""
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt$16384$8$1${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored scrypt hash in constant time."""
    try:
        algo, n_s, r_s, p_s, salt_b64, digest_b64 = stored_hash.split("$")
        if algo != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        candidate = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n_s),
            r=int(r_s),
            p=int(p_s),
            dklen=len(expected),
        )
        return hmac.compare_digest(candidate, expected)
    except Exception:
        return False


def hash_opaque_token(token: str) -> str:
    """Hash high-entropy opaque tokens (company invite links, refresh tokens) with SHA-256."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_secure_token(nbytes: int = 32) -> str:
    """Generate a URL-safe cryptographic token."""
    return secrets.token_urlsafe(nbytes)


class PIIEncryptor:
    """AES-256-GCM authenticated encryptor + scoped HMAC-SHA256 blind indexer."""

    def __init__(self, master_key_b64: str, blind_index_pepper: str) -> None:
        raw_key = base64.b64decode(master_key_b64)
        if len(raw_key) != 32:
            raise ValueError("PII master key must decode to exactly 32 bytes (AES-256).")
        self._aesgcm = AESGCM(raw_key)
        self._pepper = blind_index_pepper.encode("utf-8")

    def encrypt(self, plaintext: str, aad: str = "") -> str:
        """Encrypt UTF-8 plaintext with random 96-bit nonce and optional AAD."""
        nonce = os.urandom(12)
        ct = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad.encode("utf-8") or None)
        return base64.b64encode(nonce + ct).decode("ascii")

    def decrypt(self, token_b64: str, aad: str = "") -> str:
        """Decrypt AES-256-GCM payload and verify authentication tag."""
        raw = base64.b64decode(token_b64)
        nonce, ct = raw[:12], raw[12:]
        pt = self._aesgcm.decrypt(nonce, ct, aad.encode("utf-8") or None)
        return pt.decode("utf-8")

    def blind_index_dni(self, tenant_id: str, event_id: str, raw_dni: str) -> str:
        """Compute tenant+event-scoped HMAC-SHA256 blind index for normalized DNI.

        Scoping to (tenant_id, event_id) prevents cross-tenant correlation attacks.
        """
        normalized = normalize_dni(raw_dni)
        msg = f"{tenant_id}:{event_id}:{normalized}".encode("utf-8")
        return hmac.new(self._pepper, msg, hashlib.sha256).hexdigest()


def ensure_ed25519_keypair(keys_dir: Path, name: str) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Load or generate an Ed25519 keypair under `keys_dir/{name}_private.pem` safely across workers."""
    keys_dir.mkdir(parents=True, exist_ok=True)
    priv_path = keys_dir / f"{name}_private.pem"
    pub_path = keys_dir / f"{name}_public.pem"
    lock_path = keys_dir / f".{name}.lock"

    def _load_existing() -> tuple[Ed25519PrivateKey, Ed25519PublicKey] | None:
        if priv_path.exists() and pub_path.exists() and priv_path.stat().st_size > 0 and pub_path.stat().st_size > 0:
            private_key = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
            public_key = serialization.load_pem_public_key(pub_path.read_bytes())
            assert isinstance(private_key, Ed25519PrivateKey)
            assert isinstance(public_key, Ed25519PublicKey)
            return private_key, public_key
        return None

    loaded = _load_existing()
    if loaded is not None:
        return loaded

    lock_file = None
    try:
        try:
            import fcntl

            lock_file = open(lock_path, "w", encoding="utf-8")
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        except ImportError:
            pass

        loaded = _load_existing()
        if loaded is not None:
            return loaded

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        priv_tmp = keys_dir / f".{name}_private.{os.getpid()}.tmp"
        pub_tmp = keys_dir / f".{name}_public.{os.getpid()}.tmp"
        priv_tmp.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        pub_tmp.write_bytes(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        os.replace(priv_tmp, priv_path)
        os.replace(pub_tmp, pub_path)
        return private_key, public_key
    finally:
        if lock_file is not None:
            try:
                import fcntl

                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            lock_file.close()


def load_ed25519_public_key(keys_dir: Path, name: str) -> Ed25519PublicKey:
    """Load only the Ed25519 public key (used by verifier services & offline bundles)."""
    pub_path = keys_dir / f"{name}_public.pem"
    if not pub_path.exists():
        # In multi-container startup with :ro volume, wait briefly for auth-service to write the key
        if keys_dir.exists() and not os.access(keys_dir, os.W_OK):
            for _ in range(40):
                if pub_path.exists() and pub_path.stat().st_size > 0:
                    break
                time.sleep(0.5)
        if not pub_path.exists():
            # Ensure pair exists in shared local dev/test mode if auth hasn't booted yet
            _, pub = ensure_ed25519_keypair(keys_dir, name)
            return pub
    public_key = serialization.load_pem_public_key(pub_path.read_bytes())
    assert isinstance(public_key, Ed25519PublicKey)
    return public_key


def public_key_to_pem(public_key: Ed25519PublicKey) -> str:
    """Serialize Ed25519 public key to PEM string for offline contingency bundles."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def pem_to_public_key(pem: str) -> Ed25519PublicKey:
    """Deserialize an Ed25519 public key from PEM string."""
    key = serialization.load_pem_public_key(pem.encode("ascii"))
    assert isinstance(key, Ed25519PublicKey)
    return key


def issue_jwt(
    private_key: Ed25519PrivateKey,
    *,
    subject: str,
    tenant_id: str,
    role: str,
    ttl_minutes: int = 15,
    token_type: str = "access",
    extra_claims: dict[str, Any] | None = None,
) -> tuple[str, str]:
    """Issue an EdDSA-signed JWT and return (token, jti)."""
    now = datetime.now(timezone.utc)
    jti = secrets.token_hex(16)
    payload: dict[str, Any] = {
        "sub": subject,
        "tenant_id": tenant_id,
        "role": role,
        "typ": token_type,
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ttl_minutes)).timestamp()),
    }
    if extra_claims:
        payload.update(extra_claims)
    token = jwt.encode(payload, private_key, algorithm="EdDSA")
    return token, jti


def verify_jwt(token: str, public_key: Ed25519PublicKey, expected_type: str = "access") -> dict[str, Any]:
    """Verify an EdDSA-signed JWT and enforce token type."""
    payload = jwt.decode(token, public_key, algorithms=["EdDSA"])
    if payload.get("typ") != expected_type:
        raise jwt.InvalidTokenError("Unexpected token type.")
    return payload


def sign_qr_credential(
    private_key: Ed25519PrivateKey,
    *,
    cred_id: str,
    tenant_id: str,
    event_id: str,
    holder_type: str,
    dni_last4: str,
    entitlements: dict[str, int],
    expires_at: datetime,
) -> str:
    """Sign a compact JWS QR credential verifiable offline using only the Ed25519 public key."""
    now = datetime.now(timezone.utc)
    payload = {
        "cid": cred_id,
        "tid": tenant_id,
        "eid": event_id,
        "ht": holder_type,  # PARTICIPANT | STAFF
        "d4": dni_last4,
        "ent": entitlements,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    return jwt.encode(payload, private_key, algorithm="EdDSA")


def verify_qr_credential(qr_token: str, public_key: Ed25519PublicKey) -> dict[str, Any]:
    """Verify an EdDSA-signed QR credential (works both online and offline)."""
    return jwt.decode(qr_token, public_key, algorithms=["EdDSA"])


def sign_webhook_payload(payload_bytes: bytes, secret: str) -> str:
    """Compute hex HMAC-SHA256 signature for payment webhook payloads."""
    return hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()


def verify_webhook_signature(payload_bytes: bytes, signature: str, secret: str) -> bool:
    """Verify webhook HMAC-SHA256 signature in constant time."""
    expected = sign_webhook_payload(payload_bytes, secret)
    return hmac.compare_digest(expected, signature.strip().lower())
