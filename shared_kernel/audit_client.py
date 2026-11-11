"""Non-blocking audit trail client for microservice event emission.

Supports direct HTTP delivery (with pluggable httpx transport for tests/mesh)
and safe fallback logging if audit service is temporarily unreachable.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

import httpx

logger = logging.getLogger("eventpass.audit")


class AuditClient:
    """Async client to append immutable events to audit-service."""

    def __init__(
        self,
        base_url: str,
        internal_token: str,
        client_factory: Callable[[], httpx.AsyncClient] | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.internal_token = internal_token
        self._client_factory = client_factory

    async def record(
        self,
        *,
        tenant_id: str,
        service: str,
        action: str,
        actor_id: str,
        actor_role: str,
        resource_type: str,
        resource_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Send an audit event without failing the primary transaction on transient error."""
        if not self.base_url and self._client_factory is None:
            return

        payload = {
            "tenant_id": tenant_id,
            "service": service,
            "action": action,
            "actor_id": actor_id,
            "actor_role": actor_role,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "metadata": metadata or {},
        }
        headers = {"X-Internal-Service-Token": self.internal_token}
        try:
            if self._client_factory is not None:
                async with self._client_factory() as client:
                    await client.post("/internal/audit/events", json=payload, headers=headers)
            else:
                async with httpx.AsyncClient(base_url=self.base_url, timeout=2.0) as client:
                    await client.post("/internal/audit/events", json=payload, headers=headers)
        except Exception as exc:
            logger.warning("Audit event delivery deferred (%s): %s", action, exc)
