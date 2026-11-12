"""FastAPI application for tamper-evident hash-chained audit-service."""

from __future__ import annotations

import asyncio
import hashlib
import json
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from services.audit_service.config import AuditSettings
from services.audit_service.models import AuditEntry
from shared_kernel.crypto import load_ed25519_public_key
from shared_kernel.database import Base, create_service_db, get_db_session, init_db_schema
from shared_kernel.security import (
    CurrentActor,
    Role,
    SecurityHeadersMiddleware,
    make_internal_service_dependency,
    make_role_dependency,
)


class IngestAuditEventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=36)
    service: str = Field(min_length=1, max_length=60)
    action: str = Field(min_length=1, max_length=80)
    actor_id: str = Field(min_length=1, max_length=64)
    actor_role: str = Field(min_length=1, max_length=30)
    resource_type: str = Field(min_length=1, max_length=50)
    resource_id: str = Field(min_length=1, max_length=64)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _compute_entry_hash(
    *,
    seq: int,
    tenant_id: str,
    service: str,
    action: str,
    actor_id: str,
    resource_id: str,
    metadata_json: str,
    prev_hash: str,
) -> str:
    canonical = (
        f"{seq}|{tenant_id}|{service}|{action}|{actor_id}|{resource_id}|{metadata_json}|{prev_hash}"
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def create_audit_app(settings: AuditSettings | None = None) -> FastAPI:
    """Create the isolated audit-service FastAPI application."""
    cfg = settings or AuditSettings()
    engine, session_factory = create_service_db(cfg.database_url)
    jwt_pub_key = load_ed25519_public_key(cfg.keys_dir, "jwt")
    append_lock = asyncio.Lock()

    async def get_db():
        async for sess in get_db_session(session_factory):
            yield sess

    require_internal = make_internal_service_dependency(lambda: cfg.internal_service_token)
    require_admin_or_supervisor = make_role_dependency(lambda: jwt_pub_key, Role.ADMIN, Role.SUPERVISOR)
    require_superadmin = make_role_dependency(lambda: jwt_pub_key, Role.SUPERADMIN)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await init_db_schema(engine, Base.metadata)
        yield
        await engine.dispose()

    app = FastAPI(title="EventPass Audit Service", version="1.0.0", lifespan=lifespan)
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": cfg.service_name}

    @app.post("/internal/audit/events", status_code=status.HTTP_201_CREATED)
    async def ingest_event(
        payload: IngestAuditEventRequest,
        _: None = Depends(require_internal),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, str | int]:
        async with append_lock:
            last = await db.scalar(select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(1))
            seq = (last.seq + 1) if last is not None else 1
            prev_hash = last.entry_hash if last is not None else "0" * 64
            metadata_json = json.dumps(payload.metadata, sort_keys=True, separators=(",", ":"))
            entry_hash = _compute_entry_hash(
                seq=seq,
                tenant_id=payload.tenant_id,
                service=payload.service,
                action=payload.action,
                actor_id=payload.actor_id,
                resource_id=payload.resource_id,
                metadata_json=metadata_json,
                prev_hash=prev_hash,
            )
            entry = AuditEntry(
                seq=seq,
                tenant_id=payload.tenant_id,
                service=payload.service,
                action=payload.action,
                actor_id=payload.actor_id,
                actor_role=payload.actor_role,
                resource_type=payload.resource_type,
                resource_id=payload.resource_id,
                metadata_json=metadata_json,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
            )
            db.add(entry)
            await db.commit()
            return {"id": entry.id, "seq": seq, "entry_hash": entry_hash}

    @app.get("/api/v1/audit/events")
    async def list_tenant_audit_events(
        limit: int = Query(default=100, ge=1, le=500),
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> list[dict[str, Any]]:
        rows = (
            await db.scalars(
                select(AuditEntry)
                .where(AuditEntry.tenant_id == actor.tenant_id)
                .order_by(AuditEntry.seq.desc())
                .limit(limit)
            )
        ).all()
        return [
            {
                "seq": r.seq,
                "service": r.service,
                "action": r.action,
                "actor_id": r.actor_id,
                "actor_role": r.actor_role,
                "resource_type": r.resource_type,
                "resource_id": r.resource_id,
                "metadata": json.loads(r.metadata_json),
                "entry_hash": r.entry_hash,
                "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ]

    @app.get("/api/v1/audit/verify-chain")
    async def verify_chain(
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, Any]:
        """Verify cryptographic hash-chain integrity across all audit records."""
        rows = (await db.scalars(select(AuditEntry).order_by(AuditEntry.seq.asc()))).all()
        expected_prev = "0" * 64
        for r in rows:
            expected_hash = _compute_entry_hash(
                seq=r.seq,
                tenant_id=r.tenant_id,
                service=r.service,
                action=r.action,
                actor_id=r.actor_id,
                resource_id=r.resource_id,
                metadata_json=r.metadata_json,
                prev_hash=expected_prev,
            )
            if r.prev_hash != expected_prev or r.entry_hash != expected_hash:
                return {"intact": False, "broken_at_seq": r.seq, "total_entries": len(rows)}
            expected_prev = r.entry_hash
        return {"intact": True, "total_entries": len(rows)}

    @app.get("/api/v1/audit/superadmin/events")
    async def list_superadmin_audit_events(
        limit: int = Query(default=50, ge=1, le=500),
        actor: CurrentActor = Depends(require_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> list[dict[str, Any]]:
        """Return latest cross-tenant audit ledger events for platform SuperAdmin."""
        rows = (
            await db.scalars(select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(limit))
        ).all()
        return [
            {
                "seq": r.seq,
                "tenant_id": r.tenant_id,
                "service": r.service,
                "action": r.action,
                "actor_id": r.actor_id,
                "actor_role": r.actor_role,
                "resource_type": r.resource_type,
                "resource_id": r.resource_id,
                "metadata": json.loads(r.metadata_json),
                "entry_hash": r.entry_hash,
                "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ]

    return app


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(create_audit_app(), host="0.0.0.0", port=8004)
