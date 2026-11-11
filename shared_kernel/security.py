"""RBAC, multi-tenant isolation, rate limiting, and HTTP security middleware."""

from __future__ import annotations

import hmac
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from enum import StrEnum
from typing import Callable

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Depends, Header, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.middleware.base import BaseHTTPMiddleware

from shared_kernel.crypto import verify_jwt


class Role(StrEnum):
    """Three-tier RBAC roles per tenant company."""

    ADMIN = "ADMIN"
    SUPERVISOR = "SUPERVISOR"
    VALIDATOR = "VALIDATOR"


@dataclass(frozen=True)
class CurrentActor:
    """Authenticated tenant-scoped actor extracted from a verified EdDSA JWT."""

    user_id: str
    tenant_id: str
    role: Role
    jti: str
    device_id: str | None = None


_bearer_scheme = HTTPBearer(auto_error=False)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach hardened security headers to every HTTP response."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'"
        )
        return response


class SlidingWindowRateLimiterMiddleware(BaseHTTPMiddleware):
    """In-memory sliding-window rate limiter (Redis-compatible interface for single node/dev)."""

    def __init__(self, app, max_requests: int = 120, window_seconds: int = 60) -> None:
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._buckets: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path in {"/health", "/.well-known/jwks.json"}:
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        key = f"{client_ip}:{request.url.path}"
        now = time.monotonic()
        bucket = self._buckets[key]
        cutoff = now - self.window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.popleft()

        if len(bucket) >= self.max_requests:
            return Response(
                content='{"detail":"Too many requests. Please slow down."}',
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                media_type="application/json",
                headers={"Retry-After": str(self.window_seconds)},
            )

        bucket.append(now)
        return await call_next(request)


def make_role_dependency(
    public_key_provider: Callable[[], Ed25519PublicKey],
    *allowed_roles: Role,
):
    """Create a FastAPI dependency that validates EdDSA JWT and enforces RBAC + tenant presence."""

    async def _dependency(
        credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    ) -> CurrentActor:
        if credentials is None or not credentials.credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing bearer authentication token.",
            )
        try:
            payload = verify_jwt(credentials.credentials, public_key_provider(), expected_type="access")
        except jwt.ExpiredSignatureError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication token expired.",
            ) from exc
        except jwt.InvalidTokenError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token.",
            ) from exc

        try:
            role = Role(payload["role"])
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid role claim.",
            ) from exc

        if allowed_roles and role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{role.value}' is not authorized for this operation.",
            )

        tenant_id = payload.get("tenant_id")
        user_id = payload.get("sub")
        jti = payload.get("jti")
        if not tenant_id or not user_id or not jti:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Malformed token claims.",
            )

        return CurrentActor(
            user_id=user_id,
            tenant_id=tenant_id,
            role=role,
            jti=jti,
            device_id=payload.get("device_id"),
        )

    return _dependency


def make_internal_service_dependency(expected_token_provider: Callable[[], str]):
    """Authenticate internal service-to-service calls (mTLS fallback header)."""

    async def _verify_internal(
        x_internal_service_token: str | None = Header(default=None),
    ) -> None:
        expected = expected_token_provider()
        if not x_internal_service_token or not hmac.compare_digest(
            x_internal_service_token, expected
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: invalid internal service credentials.",
            )

    return _verify_internal
