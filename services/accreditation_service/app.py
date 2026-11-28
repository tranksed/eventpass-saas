"""FastAPI application for accreditation-service.

Handles:
- Represented companies & private staff invite links (default 6, Supervisor up to 10, Admin custom).
- Ed25519 signed QR credentials for both participants and staff.
- Private validator module: atomic online check-in + offline contingency bundle & batch sync.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import secrets
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import jwt
import qrcode
from fastapi import Depends, FastAPI, HTTPException, Response, status
from sqlalchemy import delete, select, text, update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from services.accreditation_service.config import AccreditationSettings
from services.accreditation_service.models import (
    AccreditedCompany,
    CheckInLog,
    Credential,
    StaffMember,
)
from services.accreditation_service.schemas import (
    AccreditedCompanyResponse,
    CheckInRequest,
    CheckInResponse,
    CreateAccreditedCompanyRequest,
    IssueInternalCredentialRequest,
    OfflineBundleResponse,
    OfflineCredentialSnapshot,
    OfflineSyncBatchRequest,
    OfflineSyncBatchResponse,
    OfflineSyncResultItem,
    RegisterStaffByInviteRequest,
    StaffCredentialResponse,
    UpdateCompanyQuotaRequest,
)
from shared_kernel.audit_client import AuditClient
from shared_kernel.crypto import (
    PIIEncryptor,
    ensure_ed25519_keypair,
    generate_secure_token,
    hash_opaque_token,
    load_ed25519_public_key,
    mask_dni,
    normalize_dni,
    public_key_to_pem,
    sign_qr_credential,
    verify_qr_credential,
)
from shared_kernel.database import Base, create_service_db, get_db_session, init_db_schema
from shared_kernel.security import (
    CurrentActor,
    Role,
    SecurityHeadersMiddleware,
    SlidingWindowRateLimiterMiddleware,
    make_internal_service_dependency,
    make_role_dependency,
)


def _as_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


async def _ensure_accreditation_schema_columns(conn: AsyncConnection) -> None:
    is_pg = conn.dialect.name == "postgresql"
    try:
        if is_pg:
            await conn.execute(text("ALTER TABLE accredited_companies ADD COLUMN IF NOT EXISTS invite_token_encrypted VARCHAR(512)"))
        else:
            async with conn.begin_nested():
                await conn.execute(text("ALTER TABLE accredited_companies ADD COLUMN invite_token_encrypted VARCHAR(512)"))
    except Exception:
        pass


def create_accreditation_app(
    settings: AccreditationSettings | None = None,
    audit_client: AuditClient | None = None,
) -> FastAPI:
    """Create the isolated accreditation-service FastAPI application."""
    cfg = settings or AccreditationSettings()
    engine, session_factory = create_service_db(cfg.database_url)

    jwt_pub_key = load_ed25519_public_key(cfg.keys_dir, "jwt")
    qr_priv_key, qr_pub_key = ensure_ed25519_keypair(cfg.keys_dir, "qr")
    pii_crypto = PIIEncryptor(cfg.pii_master_key_b64, cfg.dni_blind_index_pepper)
    audit = audit_client or AuditClient(cfg.audit_service_url, cfg.internal_service_token)

    company_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
    credential_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def get_db():
        async for sess in get_db_session(session_factory):
            yield sess

    require_admin_or_supervisor = make_role_dependency(
        lambda: jwt_pub_key, Role.SUPERADMIN, Role.ADMIN, Role.SUPERVISOR
    )
    require_superadmin = make_role_dependency(lambda: jwt_pub_key, Role.SUPERADMIN)
    require_validator_module = make_role_dependency(
        lambda: jwt_pub_key, Role.SUPERADMIN, Role.ADMIN, Role.SUPERVISOR, Role.VALIDATOR
    )
    require_internal = make_internal_service_dependency(lambda: cfg.internal_service_token)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await init_db_schema(engine, Base.metadata, post_init=_ensure_accreditation_schema_columns)
        yield
        await engine.dispose()

    app = FastAPI(title="EventPass Accreditation Service", version="1.0.0", lifespan=lifespan)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        SlidingWindowRateLimiterMiddleware,
        max_requests=cfg.rate_limit_requests,
        window_seconds=cfg.rate_limit_window_seconds,
    )

    def _compute_remaining(entitlements: dict[str, int], redeemed: dict[str, int]) -> dict[str, int]:
        return {
            code: max(0, int(qty) - int(redeemed.get(code, 0)))
            for code, qty in entitlements.items()
        }

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": cfg.service_name}

    # ------------------------------------------------------------------
    # Internal S2S Credential Issuance (called by registration-service)
    # ------------------------------------------------------------------
    @app.post("/internal/accreditation/credentials/issue", status_code=status.HTTP_201_CREATED)
    async def issue_credential_internal(
        payload: IssueInternalCredentialRequest,
        _: None = Depends(require_internal),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, str]:
        cred = Credential(
            tenant_id=payload.tenant_id,
            event_id=payload.event_id,
            order_id=payload.order_id,
            holder_type=payload.holder_type,
            holder_ref_id=payload.holder_ref_id,
            display_name=payload.display_name,
            dni_last4=payload.dni_last4,
            entitlements_json=json.dumps(payload.entitlements),
            redeemed_json="{}",
            status="ACTIVE",
            qr_token="pending",
            expires_at=payload.expires_at,
        )
        db.add(cred)
        await db.flush()

        qr_token = sign_qr_credential(
            qr_priv_key,
            cred_id=cred.id,
            tenant_id=cred.tenant_id,
            event_id=cred.event_id,
            holder_type=cred.holder_type,
            dni_last4=cred.dni_last4,
            entitlements=payload.entitlements,
            expires_at=_as_utc(payload.expires_at),
        )
        cred.qr_token = qr_token
        await db.commit()
        return {"credential_id": cred.id, "qr_token": qr_token}

    # ------------------------------------------------------------------
    # Represented Company & Private Staff Accreditation Link Management
    # ------------------------------------------------------------------
    @app.post(
        "/api/v1/accreditation/companies",
        response_model=AccreditedCompanyResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def create_accredited_company(
        payload: CreateAccreditedCompanyRequest,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> AccreditedCompanyResponse:
        """Register an exhibitor/partner company with default 6 staff quota (or custom for ADMIN)."""
        quota = cfg.default_staff_quota
        if payload.custom_quota is not None:
            if actor.role == Role.SUPERVISOR and payload.custom_quota > cfg.supervisor_max_staff_quota:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Supervisor can expand staff quota up to 10; Administrator is required for higher custom quotas.",
                )
            quota = payload.custom_quota

        raw_invite = generate_secure_token(32)
        now = datetime.now(timezone.utc)
        expires_at = payload.event_ends_at or (now + timedelta(hours=cfg.invite_link_ttl_hours))

        company = AccreditedCompany(
            tenant_id=actor.tenant_id,
            event_id=payload.event_id,
            company_name=payload.company_name,
            contact_email_encrypted=pii_crypto.encrypt(payload.contact_email.lower(), aad=actor.tenant_id),
            invite_token_hash=hash_opaque_token(raw_invite),
            invite_token_encrypted=pii_crypto.encrypt(raw_invite, aad=actor.tenant_id),
            staff_quota=quota,
            staff_used=0,
            link_expires_at=expires_at,
            created_by=actor.user_id,
        )
        db.add(company)
        await db.commit()

        await audit.record(
            tenant_id=actor.tenant_id,
            service=cfg.service_name,
            action="ACCREDITED_COMPANY_CREATED",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="accredited_company",
            resource_id=company.id,
            metadata={"staff_quota": quota, "event_id": payload.event_id},
        )
        return AccreditedCompanyResponse(
            company_id=company.id,
            tenant_id=company.tenant_id,
            event_id=company.event_id,
            company_name=company.company_name,
            staff_quota=company.staff_quota,
            staff_used=company.staff_used,
            invite_url=f"/acreditacion?token={raw_invite}",
            invite_token=raw_invite,
            link_expires_at=company.link_expires_at,
        )

    @app.patch(
        "/api/v1/accreditation/companies/{company_id}/quota",
        response_model=AccreditedCompanyResponse,
    )
    async def update_company_staff_quota(
        company_id: str,
        payload: UpdateCompanyQuotaRequest,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> AccreditedCompanyResponse:
        """Expand or adjust staff quota: SUPERVISOR <= 10, ADMIN custom."""
        query = select(AccreditedCompany).where(AccreditedCompany.id == company_id)
        if actor.role != Role.SUPERADMIN:
            query = query.where(AccreditedCompany.tenant_id == actor.tenant_id)
        company = await db.scalar(query)
        if company is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Accredited company not found.")

        if actor.role == Role.SUPERVISOR and payload.staff_quota > cfg.supervisor_max_staff_quota:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Supervisor cannot expand staff quota beyond 10. Administrator approval required.",
            )

        if payload.staff_quota < company.staff_used:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Cannot set quota ({payload.staff_quota}) below already registered staff ({company.staff_used}).",
            )

        previous = company.staff_quota
        company.staff_quota = payload.staff_quota
        await db.commit()

        await audit.record(
            tenant_id=actor.tenant_id,
            service=cfg.service_name,
            action="STAFF_QUOTA_UPDATED",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="accredited_company",
            resource_id=company.id,
            metadata={"previous_quota": previous, "new_quota": company.staff_quota},
        )
        return AccreditedCompanyResponse(
            company_id=company.id,
            tenant_id=company.tenant_id,
            event_id=company.event_id,
            company_name=company.company_name,
            staff_quota=company.staff_quota,
            staff_used=company.staff_used,
            link_expires_at=company.link_expires_at,
        )

    @app.get(
        "/api/v1/accreditation/companies",
        response_model=list[AccreditedCompanyResponse],
    )
    async def list_accredited_companies(
        event_id: str | None = None,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> list[AccreditedCompanyResponse]:
        """List accredited partner companies inside the actor's tenant with decrypted invite tokens."""
        stmt = select(AccreditedCompany)
        if actor.role != Role.SUPERADMIN:
            stmt = stmt.where(AccreditedCompany.tenant_id == actor.tenant_id)
        if event_id:
            stmt = stmt.where(AccreditedCompany.event_id == event_id)
        rows = (await db.scalars(stmt.order_by(AccreditedCompany.created_at.desc()))).all()
        result: list[AccreditedCompanyResponse] = []
        for c in rows:
            raw_token: str | None = None
            if c.invite_token_encrypted:
                try:
                    raw_token = pii_crypto.decrypt(c.invite_token_encrypted, aad=c.tenant_id)
                except Exception:
                    raw_token = None
            result.append(
                AccreditedCompanyResponse(
                    company_id=c.id,
                    tenant_id=c.tenant_id,
                    event_id=c.event_id,
                    company_name=c.company_name,
                    staff_quota=c.staff_quota,
                    staff_used=c.staff_used,
                    invite_url=f"/acreditacion?token={raw_token}" if raw_token else None,
                    invite_token=raw_token,
                    link_expires_at=c.link_expires_at,
                )
            )
        return result

    @app.post(
        "/api/v1/accreditation/companies/{company_id}/regenerate-link",
        response_model=AccreditedCompanyResponse,
    )
    async def regenerate_company_invite_link(
        company_id: str,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> AccreditedCompanyResponse:
        """Regenerate a fresh private accreditation invite link for a company."""
        company = await db.scalar(select(AccreditedCompany).where(AccreditedCompany.id == company_id))
        if not company:
            raise HTTPException(status_code=404, detail="Empresa no encontrada")
        if actor.role != Role.SUPERADMIN and company.tenant_id != actor.tenant_id:
            raise HTTPException(status_code=403, detail="No autorizado")

        raw_invite = generate_secure_token(32)
        company.invite_token_hash = hash_opaque_token(raw_invite)
        company.invite_token_encrypted = pii_crypto.encrypt(raw_invite, aad=company.tenant_id)
        now = datetime.now(timezone.utc)
        if _as_utc(company.link_expires_at) <= now:
            company.link_expires_at = now + timedelta(days=30)
        await db.commit()

        await audit.record(
            tenant_id=company.tenant_id,
            service=cfg.service_name,
            action="ACCREDITED_COMPANY_LINK_REGENERATED",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="accredited_company",
            resource_id=company.id,
        )
        return AccreditedCompanyResponse(
            company_id=company.id,
            tenant_id=company.tenant_id,
            event_id=company.event_id,
            company_name=company.company_name,
            staff_quota=company.staff_quota,
            staff_used=company.staff_used,
            invite_url=f"/acreditacion?token={raw_invite}",
            invite_token=raw_invite,
            link_expires_at=company.link_expires_at,
        )

    @app.delete("/api/v1/accreditation/companies/{company_id}")
    async def delete_accredited_company(
        company_id: str,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, str]:
        """Delete an accredited company and revoke all issued staff credentials."""
        company = await db.scalar(select(AccreditedCompany).where(AccreditedCompany.id == company_id))
        if not company:
            raise HTTPException(status_code=404, detail="Empresa no encontrada")
        if actor.role != Role.SUPERADMIN and company.tenant_id != actor.tenant_id:
            raise HTTPException(status_code=403, detail="No autorizado")

        staff = (await db.scalars(select(StaffMember).where(StaffMember.company_id == company.id))).all()
        for s in staff:
            if s.credential_id:
                await db.execute(update(Credential).where(Credential.id == s.credential_id).values(status="REVOKED"))
        await db.execute(delete(StaffMember).where(StaffMember.company_id == company.id))
        await db.execute(delete(AccreditedCompany).where(AccreditedCompany.id == company.id))
        await db.commit()

        await audit.record(
            tenant_id=company.tenant_id,
            service=cfg.service_name,
            action="ACCREDITED_COMPANY_DELETED",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="accredited_company",
            resource_id=company.id,
        )
        return {"status": "deleted", "company_id": company_id}

    @app.get(
        "/api/v1/accreditation/invite/{invite_token}",
        response_model=AccreditedCompanyResponse,
    )
    async def get_invite_company_summary(
        invite_token: str,
        db: AsyncSession = Depends(get_db),
    ) -> AccreditedCompanyResponse:
        """Public summary for a private company invite link (no staff PII exposed)."""
        token_hash = hash_opaque_token(invite_token)
        company = await db.scalar(
            select(AccreditedCompany).where(
                AccreditedCompany.invite_token_hash == token_hash,
                AccreditedCompany.is_active.is_(True),
            )
        )
        if company is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invalid accreditation invite link.")
        if _as_utc(company.link_expires_at) <= datetime.now(timezone.utc):
            raise HTTPException(status_code=status.HTTP_410_GONE, detail="Accreditation invite link has expired.")
        return AccreditedCompanyResponse(
            company_id=company.id,
            tenant_id=company.tenant_id,
            event_id=company.event_id,
            company_name=company.company_name,
            staff_quota=company.staff_quota,
            staff_used=company.staff_used,
            link_expires_at=company.link_expires_at,
        )

    @app.post(
        "/api/v1/accreditation/invite/{invite_token}/staff",
        response_model=StaffCredentialResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def register_staff_via_private_link(
        invite_token: str,
        payload: RegisterStaffByInviteRequest,
        db: AsyncSession = Depends(get_db),
    ) -> StaffCredentialResponse:
        """Private form link endpoint used by the represented company to accredit its staff."""
        token_hash = hash_opaque_token(invite_token)
        company = await db.scalar(
            select(AccreditedCompany).where(
                AccreditedCompany.invite_token_hash == token_hash,
                AccreditedCompany.is_active.is_(True),
            )
        )
        if company is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invalid accreditation invite link.")

        now = datetime.now(timezone.utc)
        if _as_utc(company.link_expires_at) <= now:
            raise HTTPException(status_code=status.HTTP_410_GONE, detail="Accreditation invite link has expired.")

        try:
            normalized_dni = normalize_dni(payload.dni)
            dni_last4 = mask_dni(normalized_dni)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

        dni_idx = pii_crypto.blind_index_dni(company.tenant_id, company.event_id, normalized_dni)

        async with company_locks[company.id]:
            await db.refresh(company)

            duplicate_staff = await db.scalar(
                select(StaffMember).where(
                    StaffMember.company_id == company.id,
                    StaffMember.dni_blind_index == dni_idx,
                )
            )
            if duplicate_staff is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="This DNI is already accredited for this company.",
                )

            # Atomic quota increment preventing concurrent over-accreditation
            res = await db.execute(
                update(AccreditedCompany)
                .where(
                    AccreditedCompany.id == company.id,
                    AccreditedCompany.staff_used < AccreditedCompany.staff_quota,
                )
                .values(staff_used=AccreditedCompany.staff_used + 1)
            )
            if res.rowcount != 1:
                current_quota = company.staff_quota
                await db.rollback()
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Staff quota reached ({current_quota}/{current_quota}). Contact Supervisor/Admin to expand.",
                )

            staff = StaffMember(
                tenant_id=company.tenant_id,
                event_id=company.event_id,
                company_id=company.id,
                dni_blind_index=dni_idx,
                dni_encrypted=pii_crypto.encrypt(normalized_dni, aad=company.event_id),
                dni_last4=dni_last4,
                full_name_encrypted=pii_crypto.encrypt(payload.full_name, aad=company.event_id),
                role_title=payload.role_title,
            )
            db.add(staff)
            await db.flush()

            staff_entitlements = {"ENTRY": 1, "STAFF_ACCESS": 1}
            cred = Credential(
                tenant_id=company.tenant_id,
                event_id=company.event_id,
                company_id=company.id,
                holder_type="STAFF",
                holder_ref_id=staff.id,
                display_name=payload.full_name,
                company_label=company.company_name,
                dni_last4=dni_last4,
                entitlements_json=json.dumps(staff_entitlements),
                redeemed_json="{}",
                status="ACTIVE",
                qr_token="pending",
                expires_at=_as_utc(company.link_expires_at) + timedelta(days=7),
            )
            db.add(cred)
            await db.flush()

            cred.qr_token = sign_qr_credential(
                qr_priv_key,
                cred_id=cred.id,
                tenant_id=company.tenant_id,
                event_id=company.event_id,
                holder_type="STAFF",
                dni_last4=dni_last4,
                entitlements=staff_entitlements,
                expires_at=_as_utc(cred.expires_at),
            )
            staff.credential_id = cred.id
            await db.commit()
            await db.refresh(company)

        return StaffCredentialResponse(
            staff_id=staff.id,
            company_id=company.id,
            company_name=company.company_name,
            display_name=payload.full_name,
            dni_last4=dni_last4,
            credential_id=cred.id,
            qr_token=cred.qr_token,
            remaining_quota=max(0, company.staff_quota - company.staff_used),
        )

    @app.post("/api/v1/accreditation/credentials/{credential_id}/revoke")
    async def revoke_credential(
        credential_id: str,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, str]:
        cred = await db.scalar(
            select(Credential).where(Credential.id == credential_id, Credential.tenant_id == actor.tenant_id)
        )
        if cred is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credential not found.")
        cred.status = "REVOKED"
        cred.version += 1
        await db.commit()
        await audit.record(
            tenant_id=actor.tenant_id,
            service=cfg.service_name,
            action="CREDENTIAL_REVOKED",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="credential",
            resource_id=cred.id,
            metadata={"holder_type": cred.holder_type},
        )
        return {"credential_id": cred.id, "status": cred.status}

    @app.get("/api/v1/accreditation/credentials/{credential_id}/qr-png")
    async def render_qr_png(
        credential_id: str,
        actor: CurrentActor = Depends(require_validator_module),
        db: AsyncSession = Depends(get_db),
    ) -> Response:
        cred = await db.scalar(
            select(Credential).where(Credential.id == credential_id, Credential.tenant_id == actor.tenant_id)
        )
        if cred is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credential not found.")
        img = qrcode.make(cred.qr_token)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return Response(content=buf.getvalue(), media_type="image/png")

    def _resolve_entitlement_target(
        entitlements: dict[str, int],
        redeemed: dict[str, int],
        requested_code: str,
    ) -> tuple[str, int, int]:
        """Resolve requested entitlement code against credential entitlements.

        Supports backward-compatibility when validator asks for 'ENTRY', but credential was
        issued with a specific item code (e.g. {'GNRALSAB': 1}) or vice versa.
        Returns: (effective_code, allowed, used)
        """
        allowed = int(entitlements.get(requested_code, 0))
        used = int(redeemed.get(requested_code, 0))
        if allowed > 0:
            return requested_code, allowed, used

        if requested_code == "ENTRY":
            non_entry_exclusions = {"PHOTO", "SIGNATURE", "STAFF_ACCESS", "MERCH"}
            eligible_keys = [k for k in entitlements.keys() if k not in non_entry_exclusions]
            for k in eligible_keys:
                k_allowed = int(entitlements.get(k, 0))
                k_used = int(redeemed.get(k, 0))
                if k_allowed > k_used:
                    return k, k_allowed, k_used
            if eligible_keys:
                first_k = eligible_keys[0]
                return first_k, int(entitlements.get(first_k, 0)), int(redeemed.get(first_k, 0))

        return requested_code, 0, 0

    # ------------------------------------------------------------------
    # Private Validator Module: Online Check-in + Offline Contingency
    # ------------------------------------------------------------------
    @app.post("/api/v1/accreditation/check-in", response_model=CheckInResponse)
    async def online_check_in(
        payload: CheckInRequest,
        actor: CurrentActor = Depends(require_validator_module),
        db: AsyncSession = Depends(get_db),
    ) -> CheckInResponse:
        """Private online check-in validating Ed25519 QR signature and atomically redeeming entitlement."""
        try:
            claims = verify_qr_credential(payload.qr_token, qr_pub_key)
        except jwt.ExpiredSignatureError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="QR credential expired.") from exc
        except jwt.InvalidTokenError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid QR signature.") from exc

        if actor.role != Role.SUPERADMIN and claims.get("tid") != actor.tenant_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cross-tenant QR rejected: credential belongs to a different organization.",
            )

        cred_id = claims["cid"]
        scan_id = payload.client_scan_id or f"online-{secrets.token_hex(12)}"

        async with credential_locks[cred_id]:
            query = select(Credential).where(Credential.id == cred_id)
            if actor.role != Role.SUPERADMIN:
                query = query.where(Credential.tenant_id == actor.tenant_id)
            cred = await db.scalar(query)
            if cred is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credential not found.")
            if cred.status != "ACTIVE":
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Credential is {cred.status}.")

            entitlements: dict[str, int] = json.loads(cred.entitlements_json)
            redeemed: dict[str, int] = json.loads(cred.redeemed_json)

            target_code, allowed, used = _resolve_entitlement_target(
                entitlements, redeemed, payload.entitlement_code
            )

            if allowed <= 0:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Credential does not include '{payload.entitlement_code}'.",
                )
            if used >= allowed:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Entitlement '{target_code}' already fully redeemed ({used}/{allowed}).",
                )

            redeemed[target_code] = used + 1
            if target_code != payload.entitlement_code:
                redeemed[payload.entitlement_code] = int(redeemed.get(payload.entitlement_code, 0)) + 1
            if target_code == "ENTRY":
                non_entry_exclusions = {"PHOTO", "SIGNATURE", "STAFF_ACCESS", "MERCH", "ENTRY"}
                for k in entitlements.keys():
                    if k not in non_entry_exclusions and redeemed.get(k, 0) < entitlements.get(k, 0):
                        redeemed[k] = int(redeemed.get(k, 0)) + 1
                        break

            res = await db.execute(
                update(Credential)
                .where(Credential.id == cred.id, Credential.version == cred.version)
                .values(redeemed_json=json.dumps(redeemed), version=cred.version + 1)
            )
            if res.rowcount != 1:
                await db.rollback()
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Concurrent check-in conflict.")

            now = datetime.now(timezone.utc)
            db.add(
                CheckInLog(
                    tenant_id=cred.tenant_id,
                    event_id=cred.event_id,
                    credential_id=cred.id,
                    entitlement_code=payload.entitlement_code,
                    mode="ONLINE",
                    outcome="GRANTED",
                    gate_id=payload.gate_id,
                    device_id=actor.device_id or payload.device_id,
                    validator_user_id=actor.user_id,
                    client_scan_id=scan_id,
                    scanned_at=now,
                )
            )
            await db.commit()

        remaining_map = _compute_remaining(entitlements, redeemed)
        await audit.record(
            tenant_id=actor.tenant_id,
            service=cfg.service_name,
            action="CHECKIN_ONLINE_GRANTED",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="credential",
            resource_id=cred.id,
            metadata={"entitlement": payload.entitlement_code, "gate_id": payload.gate_id},
        )
        return CheckInResponse(
            outcome="GRANTED",
            credential_id=cred.id,
            holder_type=cred.holder_type,
            display_name=cred.display_name,
            company_label=cred.company_label,
            dni_last4=cred.dni_last4,
            entitlement_code=payload.entitlement_code,
            remaining_for_code=remaining_map.get(payload.entitlement_code, remaining_map.get(target_code, 0)),
            all_remaining=remaining_map,
        )

    @app.get(
        "/api/v1/accreditation/events/{event_id}/offline-bundle",
        response_model=OfflineBundleResponse,
    )
    async def download_offline_contingency_bundle(
        event_id: str,
        actor: CurrentActor = Depends(require_validator_module),
        db: AsyncSession = Depends(get_db),
    ) -> OfflineBundleResponse:
        """Download signed contingency snapshot + Ed25519 public key for offline gate operation."""
        query = select(Credential).where(Credential.event_id == event_id)
        if actor.role != Role.SUPERADMIN:
            query = query.where(Credential.tenant_id == actor.tenant_id)
        creds = (await db.scalars(query)).all()

        snapshots = [
            OfflineCredentialSnapshot(
                credential_id=c.id,
                holder_type=c.holder_type,
                display_name=c.display_name,
                company_label=c.company_label,
                dni_last4=c.dni_last4,
                status=c.status,
                entitlements=json.loads(c.entitlements_json),
                redeemed=json.loads(c.redeemed_json),
            )
            for c in creds
        ]
        snapshot_bytes = json.dumps(
            [s.model_dump() for s in snapshots], sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        digest = hashlib.sha256(snapshot_bytes).hexdigest()
        now = datetime.now(timezone.utc)
        target_tid = creds[0].tenant_id if creds else actor.tenant_id

        bundle_token = jwt.encode(
            {
                "tid": target_tid,
                "eid": event_id,
                "digest": digest,
                "iat": int(now.timestamp()),
                "exp": int((now + timedelta(hours=24)).timestamp()),
            },
            qr_priv_key,
            algorithm="EdDSA",
        )
        return OfflineBundleResponse(
            tenant_id=target_tid,
            event_id=event_id,
            generated_at=now,
            qr_public_key_pem=public_key_to_pem(qr_pub_key),
            credentials=snapshots,
            bundle_token=bundle_token,
        )

    @app.post(
        "/api/v1/accreditation/events/{event_id}/offline-sync",
        response_model=OfflineSyncBatchResponse,
    )
    async def sync_offline_checkins(
        event_id: str,
        payload: OfflineSyncBatchRequest,
        actor: CurrentActor = Depends(require_validator_module),
        db: AsyncSession = Depends(get_db),
    ) -> OfflineSyncBatchResponse:
        """Synchronize offline gate scans chronologically, detecting duplicate/conflict redemptions."""
        ordered_scans = sorted(payload.scans, key=lambda s: s.scanned_at)
        granted = conflicts = duplicates_ignored = rejected = 0
        results: list[OfflineSyncResultItem] = []

        for scan in ordered_scans:
            existing_log = await db.scalar(
                select(CheckInLog).where(
                    CheckInLog.event_id == event_id,
                    CheckInLog.client_scan_id == scan.client_scan_id,
                )
            )
            if existing_log is not None:
                duplicates_ignored += 1
                results.append(
                    OfflineSyncResultItem(
                        client_scan_id=scan.client_scan_id,
                        credential_id=existing_log.credential_id,
                        outcome="DUPLICATE_IGNORED",
                        detail="Scan already synchronized.",
                    )
                )
                continue

            try:
                claims = verify_qr_credential(scan.qr_token, qr_pub_key)
            except jwt.InvalidTokenError:
                rejected += 1
                results.append(
                    OfflineSyncResultItem(
                        client_scan_id=scan.client_scan_id,
                        outcome="REJECTED",
                        detail="Invalid or expired QR signature.",
                    )
                )
                continue

            if claims.get("tid") != actor.tenant_id or claims.get("eid") != event_id:
                rejected += 1
                results.append(
                    OfflineSyncResultItem(
                        client_scan_id=scan.client_scan_id,
                        outcome="REJECTED",
                        detail="Tenant or event mismatch.",
                    )
                )
                continue

            cred_id = claims["cid"]
            async with credential_locks[cred_id]:
                cred = await db.scalar(
                    select(Credential).where(
                        Credential.id == cred_id,
                        Credential.tenant_id == actor.tenant_id,
                        Credential.event_id == event_id,
                    )
                )
                if cred is None or cred.status != "ACTIVE":
                    conflicts += 1
                    outcome = "CONFLICT_REVOKED_OR_MISSING"
                    if cred is not None:
                        db.add(
                            CheckInLog(
                                tenant_id=actor.tenant_id,
                                event_id=event_id,
                                credential_id=cred.id,
                                entitlement_code=scan.entitlement_code,
                                mode="OFFLINE_SYNC",
                                outcome=outcome,
                                gate_id=scan.gate_id,
                                device_id=scan.device_id,
                                validator_user_id=actor.user_id,
                                client_scan_id=scan.client_scan_id,
                                scanned_at=scan.scanned_at,
                            )
                        )
                        await db.commit()
                    results.append(
                        OfflineSyncResultItem(
                            client_scan_id=scan.client_scan_id,
                            credential_id=cred_id,
                            outcome=outcome,
                            detail="Credential missing or revoked before sync.",
                        )
                    )
                    continue

                entitlements: dict[str, int] = json.loads(cred.entitlements_json)
                redeemed: dict[str, int] = json.loads(cred.redeemed_json)
                target_code, allowed, used = _resolve_entitlement_target(
                    entitlements, redeemed, scan.entitlement_code
                )

                if used < allowed:
                    redeemed[target_code] = used + 1
                    if target_code != scan.entitlement_code:
                        redeemed[scan.entitlement_code] = int(redeemed.get(scan.entitlement_code, 0)) + 1
                    if target_code == "ENTRY":
                        non_entry_exclusions = {"PHOTO", "SIGNATURE", "STAFF_ACCESS", "MERCH", "ENTRY"}
                        for k in entitlements.keys():
                            if k not in non_entry_exclusions and redeemed.get(k, 0) < entitlements.get(k, 0):
                                redeemed[k] = int(redeemed.get(k, 0)) + 1
                                break
                    cred.redeemed_json = json.dumps(redeemed)
                    cred.version += 1
                    outcome = "SYNCED_GRANTED"
                    granted += 1
                    detail = f"Offline check-in consolidated ({target_code})."
                else:
                    outcome = "CONFLICT_DUPLICATE_OFFLINE"
                    conflicts += 1
                    detail = f"Already redeemed ({used}/{allowed}) on another gate."
                    await audit.record(
                        tenant_id=actor.tenant_id,
                        service=cfg.service_name,
                        action="OFFLINE_DUPLICATE_CONFLICT",
                        actor_id=actor.user_id,
                        actor_role=actor.role.value,
                        resource_type="credential",
                        resource_id=cred.id,
                        metadata={
                            "gate_id": scan.gate_id,
                            "device_id": scan.device_id,
                            "entitlement": scan.entitlement_code,
                        },
                    )

                db.add(
                    CheckInLog(
                        tenant_id=actor.tenant_id,
                        event_id=event_id,
                        credential_id=cred.id,
                        entitlement_code=scan.entitlement_code,
                        mode="OFFLINE_SYNC",
                        outcome=outcome,
                        gate_id=scan.gate_id,
                        device_id=scan.device_id,
                        validator_user_id=actor.user_id,
                        client_scan_id=scan.client_scan_id,
                        scanned_at=scan.scanned_at,
                    )
                )
                await db.commit()
                results.append(
                    OfflineSyncResultItem(
                        client_scan_id=scan.client_scan_id,
                        credential_id=cred.id,
                        outcome=outcome,
                        detail=detail,
                    )
                )

        return OfflineSyncBatchResponse(
            processed=len(ordered_scans),
            granted=granted,
            conflicts=conflicts,
            duplicates_ignored=duplicates_ignored,
            rejected=rejected,
            results=results,
        )

    @app.get("/api/v1/accreditation/events/{event_id}/metrics")
    async def get_event_accreditation_metrics(
        event_id: str,
        actor: AuthenticatedActor = Depends(require_validator_module),
        db: AsyncSession = Depends(get_db),
    ) -> dict:
        c_query = select(Credential).where(Credential.event_id == event_id)
        l_query = select(CheckInLog).where(CheckInLog.event_id == event_id)
        co_query = select(AccreditedCompany).where(AccreditedCompany.event_id == event_id)
        if actor.role != Role.SUPERADMIN:
            c_query = c_query.where(Credential.tenant_id == actor.tenant_id)
            l_query = l_query.where(CheckInLog.tenant_id == actor.tenant_id)
            co_query = co_query.where(AccreditedCompany.tenant_id == actor.tenant_id)

        creds = list(await db.scalars(c_query))
        logs = list(await db.scalars(l_query))
        companies = list(await db.scalars(co_query))

        total_active_credentials = sum(1 for c in creds if c.status == "ACTIVE")
        by_holder_type: dict[str, dict[str, int]] = {
            "PARTICIPANT": {"total": 0, "checked_in": 0},
            "STAFF": {"total": 0, "checked_in": 0},
        }
        checked_in_entry = 0
        for c in creds:
            if c.status != "ACTIVE":
                continue
            ht = c.holder_type if c.holder_type in by_holder_type else "PARTICIPANT"
            by_holder_type[ht]["total"] += 1
            redeemed = json.loads(c.redeemed_json or "{}")
            if int(redeemed.get("ENTRY", 0)) > 0 or int(redeemed.get("STAFF_ACCESS", 0)) > 0:
                checked_in_entry += 1
                by_holder_type[ht]["checked_in"] += 1

        by_gate: dict[str, int] = defaultdict(int)
        by_entitlement: dict[str, int] = defaultdict(int)
        by_mode: dict[str, int] = defaultdict(int)
        offline_conflicts = 0
        for log in logs:
            by_mode[log.mode] += 1
            if log.outcome in ("GRANTED", "SYNCED_GRANTED"):
                by_gate[log.gate_id] += 1
                by_entitlement[log.entitlement_code] += 1
            elif log.outcome in ("CONFLICT_DUPLICATE_OFFLINE", "CONFLICT_REVOKED_OR_MISSING"):
                offline_conflicts += 1

        total_staff_quota = sum(c.staff_quota for c in companies)
        total_staff_used = sum(c.staff_used for c in companies)

        return {
            "event_id": event_id,
            "total_active_credentials": total_active_credentials,
            "checked_in_entry": checked_in_entry,
            "occupancy_pct": round((checked_in_entry / total_active_credentials * 100), 1)
            if total_active_credentials
            else 0.0,
            "by_holder_type": by_holder_type,
            "by_gate": dict(by_gate),
            "by_entitlement": dict(by_entitlement),
            "by_mode": dict(by_mode),
            "total_scan_events": len(logs),
            "offline_conflicts": offline_conflicts,
            "staff_companies_summary": {
                "companies_count": len(companies),
                "total_quota": total_staff_quota,
                "total_used": total_staff_used,
                "companies": [
                    {
                        "id": c.id,
                        "company_name": c.company_name,
                        "staff_quota": c.staff_quota,
                        "staff_used": c.staff_used,
                        "is_active": c.is_active,
                    }
                    for c in companies
                ],
            },
        }

    @app.get("/internal/accreditation/events/{event_id}/credentials-scan-status")
    async def get_credentials_scan_status_internal(
        event_id: str,
        _: None = Depends(require_internal),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, dict]:
        """Internal endpoint mapping each credential's redemption and scan timestamps."""
        creds = (await db.scalars(select(Credential).where(Credential.event_id == event_id))).all()
        logs = (
            await db.scalars(
                select(CheckInLog)
                .where(CheckInLog.event_id == event_id, CheckInLog.outcome.in_(["GRANTED", "SYNCED_GRANTED"]))
                .order_by(CheckInLog.scanned_at.asc())
            )
        ).all()
        logs_by_cred: dict[str, CheckInLog] = {}
        for l in logs:
            if l.credential_id not in logs_by_cred:
                logs_by_cred[l.credential_id] = l

        status_map: dict[str, dict] = {}
        for c in creds:
            red = json.loads(c.redeemed_json or "{}")
            is_redeemed = any(int(v) > 0 for v in red.values())
            first_log = logs_by_cred.get(c.id)
            status_map[c.id] = {
                "is_redeemed": is_redeemed,
                "scanned_at": _as_utc(first_log.scanned_at).isoformat() if first_log else None,
                "gate_id": first_log.gate_id if first_log else None,
                "created_at": _as_utc(c.created_at).isoformat(),
            }
        return status_map

    @app.get("/api/v1/accreditation/events/{event_id}/check-ins")
    async def list_event_checkins(
        event_id: str,
        actor: AuthenticatedActor = Depends(require_validator_module),
        db: AsyncSession = Depends(get_db),
    ) -> list[dict]:
        """List chronological check-in scan events for gate verification auditing."""
        c_query = select(Credential).where(Credential.event_id == event_id)
        l_query = (
            select(CheckInLog)
            .where(CheckInLog.event_id == event_id)
            .order_by(CheckInLog.scanned_at.desc())
            .limit(200)
        )
        if actor.role != Role.SUPERADMIN:
            c_query = c_query.where(Credential.tenant_id == actor.tenant_id)
            l_query = l_query.where(CheckInLog.tenant_id == actor.tenant_id)

        creds = {c.id: c for c in (await db.scalars(c_query)).all()}
        logs = (await db.scalars(l_query)).all()

        res = []
        for l in logs:
            c = creds.get(l.credential_id)
            res.append(
                {
                    "id": l.id,
                    "credential_id": l.credential_id,
                    "display_name": c.display_name if c else "-",
                    "dni_last4": c.dni_last4 if c else "----",
                    "company_label": c.company_label if c else None,
                    "holder_type": c.holder_type if c else "-",
                    "entitlement_code": l.entitlement_code,
                    "gate_id": l.gate_id,
                    "device_id": l.device_id,
                    "mode": l.mode,
                    "outcome": l.outcome,
                    "scanned_at": _as_utc(l.scanned_at).isoformat(),
                    "created_at": _as_utc(c.created_at).isoformat() if c else None,
                }
            )
        return res

    @app.get("/api/v1/accreditation/superadmin/overview")
    async def superadmin_accreditation_overview(
        actor: CurrentActor = Depends(require_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, Any]:
        """Cross-tenant credentials, check-ins, and staff quota summary for SuperAdmin."""
        creds = (await db.scalars(select(Credential))).all()
        checkins_count = len((await db.scalars(select(CheckInLog.id))).all())
        companies = (await db.scalars(select(AccreditedCompany))).all()
        return {
            "total_credentials": len(creds),
            "active_credentials": sum(1 for c in creds if c.status == "ACTIVE"),
            "total_checkins": checkins_count,
            "total_companies": len(companies),
            "total_staff_quota": sum(int(c.staff_quota or 0) for c in companies),
            "total_staff_used": sum(int(c.staff_used or 0) for c in companies),
        }

    async def _delete_accreditation_cascade(db: AsyncSession, event_id: str) -> None:
        """Delete all accreditation records related to an event in safe FK order."""
        await db.execute(delete(CheckInLog).where(CheckInLog.event_id == event_id))
        await db.execute(delete(Credential).where(Credential.event_id == event_id))
        await db.execute(delete(StaffMember).where(StaffMember.event_id == event_id))
        await db.execute(delete(AccreditedCompany).where(AccreditedCompany.event_id == event_id))

    @app.delete("/api/v1/accreditation/events/{event_id}")
    async def delete_tenant_event_accreditation(
        event_id: str,
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, str]:
        """Delete all accreditation records for an organizer event."""
        await _delete_accreditation_cascade(db, event_id)
        await db.commit()
        return {"deleted_event": event_id}

    @app.delete("/api/v1/accreditation/superadmin/events/{event_id}")
    async def superadmin_delete_event_accreditation(
        event_id: str,
        actor: CurrentActor = Depends(require_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, str]:
        """SuperAdmin endpoint to delete an event's credentials and staff."""
        await _delete_accreditation_cascade(db, event_id)
        await db.commit()
        return {"deleted_event": event_id}

    @app.delete("/api/v1/accreditation/superadmin/tenants/{tenant_id}/events")
    async def superadmin_delete_tenant_accreditation(
        tenant_id: str,
        actor: CurrentActor = Depends(require_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, str]:
        """SuperAdmin endpoint to delete all accreditation records belonging to a tenant."""
        await db.execute(delete(CheckInLog).where(CheckInLog.tenant_id == tenant_id))
        await db.execute(delete(Credential).where(Credential.tenant_id == tenant_id))
        await db.execute(delete(StaffMember).where(StaffMember.tenant_id == tenant_id))
        await db.execute(delete(AccreditedCompany).where(AccreditedCompany.tenant_id == tenant_id))
        await db.commit()
        return {"deleted_tenant": tenant_id}

    return app


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(create_accreditation_app(), host="0.0.0.0", port=8003)
