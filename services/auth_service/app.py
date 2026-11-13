"""FastAPI application for auth-service (Multi-tenant Identity, MFA, EdDSA JWTs)."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import pyotp
from fastapi import Depends, FastAPI, HTTPException, status
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from services.auth_service.config import AuthSettings
from services.auth_service.models import RefreshToken, Tenant, User
from services.auth_service.schemas import (
    CreateUserRequest,
    EnableMFARequest,
    LoginRequest,
    RefreshRequest,
    SuperAdminLoginRequest,
    SuperAdminSetupRequest,
    TenantRegisterRequest,
    TenantRegisterResponse,
    TokenResponse,
    UpdateTenantStatusRequest,
    UserSummary,
)
from shared_kernel.audit_client import AuditClient
from shared_kernel.crypto import (
    PIIEncryptor,
    ensure_ed25519_keypair,
    generate_secure_token,
    hash_opaque_token,
    hash_password,
    issue_jwt,
    public_key_to_pem,
    verify_password,
)
from shared_kernel.database import Base, create_service_db, get_db_session, init_db_schema
from shared_kernel.security import (
    CurrentActor,
    Role,
    SecurityHeadersMiddleware,
    SlidingWindowRateLimiterMiddleware,
    make_role_dependency,
)


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def create_auth_app(
    settings: AuthSettings | None = None,
    audit_client: AuditClient | None = None,
) -> FastAPI:
    """Create the isolated auth-service FastAPI application."""
    cfg = settings or AuthSettings()
    engine, session_factory = create_service_db(cfg.database_url)
    jwt_priv_key, jwt_pub_key = ensure_ed25519_keypair(cfg.keys_dir, "jwt")
    pii_crypto = PIIEncryptor(cfg.pii_master_key_b64, cfg.dni_blind_index_pepper)
    audit = audit_client or AuditClient(cfg.audit_service_url, cfg.internal_service_token)

    async def get_db():
        async for sess in get_db_session(session_factory):
            yield sess

    require_any_staff = make_role_dependency(lambda: jwt_pub_key, Role.ADMIN, Role.SUPERVISOR, Role.VALIDATOR)
    require_admin_or_supervisor = make_role_dependency(lambda: jwt_pub_key, Role.ADMIN, Role.SUPERVISOR)
    require_admin = make_role_dependency(lambda: jwt_pub_key, Role.ADMIN)
    require_superadmin = make_role_dependency(lambda: jwt_pub_key, Role.SUPERADMIN)

    async def _create_superadmin_account(
        db: AsyncSession, *, email: str, full_name: str, password: str
    ) -> User:
        platform_tenant = await db.scalar(select(Tenant).where(Tenant.slug == "platform"))
        if platform_tenant is None:
            try:
                async with db.begin_nested():
                    platform_tenant = Tenant(id="__platform__", name="EventPass Platform", slug="platform", is_active=True)
                    db.add(platform_tenant)
                    await db.flush()
            except IntegrityError:
                platform_tenant = await db.scalar(select(Tenant).where(Tenant.slug == "platform"))
        if platform_tenant is None:
            raise HTTPException(status_code=500, detail="Could not resolve platform tenant.")
        sa_user = User(
            tenant_id=platform_tenant.id,
            email=email.lower(),
            full_name=full_name,
            password_hash=hash_password(password),
            role=Role.SUPERADMIN.value,
        )
        db.add(sa_user)
        await db.commit()
        return sa_user

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await init_db_schema(engine, Base.metadata)
        if cfg.superadmin_password and len(cfg.superadmin_password) >= 8:
            async with session_factory() as db:
                try:
                    existing_sa = await db.scalar(select(User).where(User.role == Role.SUPERADMIN.value))
                    if existing_sa is None:
                        await _create_superadmin_account(
                            db,
                            email=cfg.superadmin_email,
                            full_name="Platform SuperAdmin",
                            password=cfg.superadmin_password,
                        )
                except IntegrityError:
                    await db.rollback()
        yield
        await engine.dispose()

    app = FastAPI(title="EventPass Auth Service", version="1.0.0", lifespan=lifespan)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        SlidingWindowRateLimiterMiddleware,
        max_requests=cfg.rate_limit_requests,
        window_seconds=cfg.rate_limit_window_seconds,
    )

    async def _issue_session_tokens(
        db: AsyncSession,
        user: User,
        device_id: str | None = None,
    ) -> TokenResponse:
        access_token, _ = issue_jwt(
            jwt_priv_key,
            subject=user.id,
            tenant_id=user.tenant_id,
            role=user.role,
            ttl_minutes=cfg.access_token_ttl_minutes,
            token_type="access",
            extra_claims={"device_id": device_id} if device_id else None,
        )
        raw_refresh = generate_secure_token(32)
        db.add(
            RefreshToken(
                user_id=user.id,
                tenant_id=user.tenant_id,
                token_hash=hash_opaque_token(raw_refresh),
                device_id=device_id,
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=cfg.refresh_token_ttl_minutes),
            )
        )
        await db.commit()
        return TokenResponse(
            access_token=access_token,
            refresh_token=raw_refresh,
            expires_in_seconds=cfg.access_token_ttl_minutes * 60,
            tenant_id=user.tenant_id,
            user_id=user.id,
            role=Role(user.role),
        )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": cfg.service_name}

    @app.get("/.well-known/jwks.json")
    async def get_public_key() -> dict[str, str]:
        """Expose Ed25519 public key so downstream services verify JWTs autonomously."""
        return {"alg": "EdDSA", "kty": "OKP", "crv": "Ed25519", "public_key_pem": public_key_to_pem(jwt_pub_key)}

    @app.post(
        "/api/v1/auth/tenants/register",
        response_model=TenantRegisterResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def register_tenant(
        payload: TenantRegisterRequest,
        db: AsyncSession = Depends(get_db),
    ) -> TenantRegisterResponse:
        if payload.company_slug == "platform":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Reserved tenant slug.")
        existing_slug = await db.scalar(select(Tenant).where(Tenant.slug == payload.company_slug))
        if existing_slug is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Company slug already exists.")

        tenant = Tenant(name=payload.company_name, slug=payload.company_slug)
        db.add(tenant)
        await db.flush()

        admin_user = User(
            tenant_id=tenant.id,
            email=payload.admin_email.lower(),
            full_name=payload.admin_full_name,
            password_hash=hash_password(payload.admin_password),
            role=Role.ADMIN.value,
        )
        db.add(admin_user)
        await db.flush()

        tokens = await _issue_session_tokens(db, admin_user)
        await audit.record(
            tenant_id=tenant.id,
            service=cfg.service_name,
            action="TENANT_REGISTERED",
            actor_id=admin_user.id,
            actor_role=Role.ADMIN.value,
            resource_type="tenant",
            resource_id=tenant.id,
            metadata={"slug": tenant.slug},
        )
        return TenantRegisterResponse(
            tenant_id=tenant.id,
            company_name=tenant.name,
            company_slug=tenant.slug,
            user=UserSummary(
                id=admin_user.id,
                tenant_id=tenant.id,
                email=admin_user.email,
                full_name=admin_user.full_name,
                role=Role.ADMIN,
                mfa_enabled=admin_user.mfa_enabled,
                is_active=admin_user.is_active,
            ),
            tokens=tokens,
        )

    @app.post("/api/v1/auth/login", response_model=TokenResponse)
    async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
        tenant = await db.scalar(
            select(Tenant).where(Tenant.slug == payload.tenant_slug, Tenant.is_active.is_(True))
        )
        if tenant is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")

        user = await db.scalar(
            select(User).where(User.tenant_id == tenant.id, User.email == payload.email.lower())
        )
        if user is None or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")

        now = datetime.now(timezone.utc)
        locked_until = _as_utc(user.locked_until)
        if locked_until and locked_until > now:
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Account temporarily locked due to repeated failed attempts.",
            )

        if not verify_password(payload.password, user.password_hash):
            user.failed_attempts += 1
            if user.failed_attempts >= cfg.max_failed_login_attempts:
                user.locked_until = now + timedelta(minutes=cfg.lockout_minutes)
                user.failed_attempts = 0
            await db.commit()
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")

        if user.mfa_enabled:
            if not payload.mfa_code or not user.mfa_secret_enc:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="MFA TOTP code required.")
            totp_secret = pii_crypto.decrypt(user.mfa_secret_enc, aad=user.id)
            if not pyotp.TOTP(totp_secret).verify(payload.mfa_code, valid_window=1):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code.")

        user.failed_attempts = 0
        user.locked_until = None
        tokens = await _issue_session_tokens(db, user, device_id=payload.device_id)
        await audit.record(
            tenant_id=tenant.id,
            service=cfg.service_name,
            action="USER_LOGIN",
            actor_id=user.id,
            actor_role=user.role,
            resource_type="user",
            resource_id=user.id,
            metadata={"device_id": payload.device_id or "web"},
        )
        return tokens

    @app.post("/api/v1/auth/refresh", response_model=TokenResponse)
    async def refresh_session(payload: RefreshRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
        token_hash = hash_opaque_token(payload.refresh_token)
        stored = await db.scalar(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
        if stored is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token.")

        now = datetime.now(timezone.utc)
        if stored.revoked_at is not None:
            # Reuse detected -> revoke all active refresh tokens for this user!
            await db.execute(
                update(RefreshToken)
                .where(RefreshToken.user_id == stored.user_id, RefreshToken.revoked_at.is_(None))
                .values(revoked_at=now)
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token reuse detected. All sessions revoked.",
            )

        expires_at = _as_utc(stored.expires_at)
        if expires_at is None or expires_at <= now:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired.")

        user = await db.scalar(select(User).where(User.id == stored.user_id, User.is_active.is_(True)))
        if user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User inactive.")

        stored.revoked_at = now
        return await _issue_session_tokens(db, user, device_id=payload.device_id or stored.device_id)

    @app.post("/api/v1/auth/mfa/setup")
    async def setup_mfa(
        actor: CurrentActor = Depends(require_any_staff),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, str]:
        user = await db.scalar(select(User).where(User.id == actor.user_id, User.tenant_id == actor.tenant_id))
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
        secret = pyotp.random_base32()
        user.mfa_secret_enc = pii_crypto.encrypt(secret, aad=user.id)
        await db.commit()
        uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="EventPass SaaS")
        return {"secret": secret, "otpauth_uri": uri}

    @app.post("/api/v1/auth/mfa/enable")
    async def enable_mfa(
        payload: EnableMFARequest,
        actor: CurrentActor = Depends(require_any_staff),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, bool]:
        user = await db.scalar(select(User).where(User.id == actor.user_id, User.tenant_id == actor.tenant_id))
        if user is None or not user.mfa_secret_enc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA setup not initiated.")
        secret = pii_crypto.decrypt(user.mfa_secret_enc, aad=user.id)
        if not pyotp.TOTP(secret).verify(payload.totp_code, valid_window=1):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid TOTP verification code.")
        user.mfa_enabled = True
        await db.commit()
        return {"mfa_enabled": True}

    @app.post("/api/v1/auth/users", response_model=UserSummary, status_code=status.HTTP_201_CREATED)
    async def create_company_user(
        payload: CreateUserRequest,
        actor: CurrentActor = Depends(require_admin),
        db: AsyncSession = Depends(get_db),
    ) -> UserSummary:
        """ADMIN-only endpoint to create ADMIN, SUPERVISOR, or VALIDATOR accounts inside their tenant."""
        if payload.role == Role.SUPERADMIN:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot assign SUPERADMIN inside tenant.")
        existing = await db.scalar(
            select(User).where(User.tenant_id == actor.tenant_id, User.email == payload.email.lower())
        )
        if existing is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User email already exists in tenant.")

        new_user = User(
            tenant_id=actor.tenant_id,
            email=payload.email.lower(),
            full_name=payload.full_name,
            password_hash=hash_password(payload.password),
            role=payload.role.value,
        )
        db.add(new_user)
        await db.commit()
        await audit.record(
            tenant_id=actor.tenant_id,
            service=cfg.service_name,
            action="USER_CREATED",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="user",
            resource_id=new_user.id,
            metadata={"assigned_role": payload.role.value},
        )
        return UserSummary(
            id=new_user.id,
            tenant_id=new_user.tenant_id,
            email=new_user.email,
            full_name=new_user.full_name,
            role=Role(new_user.role),
            mfa_enabled=new_user.mfa_enabled,
            is_active=new_user.is_active,
        )

    @app.get("/api/v1/auth/users", response_model=list[UserSummary])
    async def list_company_users(
        actor: CurrentActor = Depends(require_admin_or_supervisor),
        db: AsyncSession = Depends(get_db),
    ) -> list[UserSummary]:
        rows = (
            await db.scalars(select(User).where(User.tenant_id == actor.tenant_id).order_by(User.created_at.desc()))
        ).all()
        return [
            UserSummary(
                id=u.id,
                tenant_id=u.tenant_id,
                email=u.email,
                full_name=u.full_name,
                role=Role(u.role),
                mfa_enabled=u.mfa_enabled,
                is_active=u.is_active,
            )
            for u in rows
        ]

    # ------------------------------------------------------------------
    # Platform SuperAdmin Management
    # ------------------------------------------------------------------
    @app.get("/api/v1/auth/superadmin/status")
    async def superadmin_status(db: AsyncSession = Depends(get_db)) -> dict[str, bool]:
        count = await db.scalar(select(func.count(User.id)).where(User.role == Role.SUPERADMIN.value))
        return {"initialized": bool(count and count > 0)}

    @app.post("/api/v1/auth/superadmin/setup", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
    async def setup_first_superadmin(
        payload: SuperAdminSetupRequest,
        db: AsyncSession = Depends(get_db),
    ) -> TokenResponse:
        existing_sa = await db.scalar(select(User).where(User.role == Role.SUPERADMIN.value))
        if existing_sa is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="SuperAdmin already initialized.")
        sa_user = await _create_superadmin_account(
            db, email=payload.email, full_name=payload.full_name, password=payload.password
        )
        return await _issue_session_tokens(db, sa_user, device_id="superadmin-console")

    @app.post("/api/v1/auth/superadmin/login", response_model=TokenResponse)
    async def superadmin_login(
        payload: SuperAdminLoginRequest,
        db: AsyncSession = Depends(get_db),
    ) -> TokenResponse:
        user = await db.scalar(
            select(User).where(
                User.role == Role.SUPERADMIN.value,
                User.email == payload.email.lower(),
                User.is_active.is_(True),
            )
        )
        if user is None or not verify_password(payload.password, user.password_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid SuperAdmin credentials.")
        if user.mfa_enabled:
            if not payload.mfa_code or not user.mfa_secret_enc:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="MFA code required.")
            secret = pii_crypto.decrypt(user.mfa_secret_enc, aad=user.id)
            if not pyotp.TOTP(secret).verify(payload.mfa_code, valid_window=1):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code.")
        return await _issue_session_tokens(db, user, device_id="superadmin-console")

    @app.get("/api/v1/auth/superadmin/tenants")
    async def superadmin_list_tenants(
        _: CurrentActor = Depends(require_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> list[dict]:
        tenants = (
            await db.scalars(
                select(Tenant).where(Tenant.slug != "platform").order_by(Tenant.created_at.desc())
            )
        ).all()
        counts_rows = (
            await db.execute(select(User.tenant_id, func.count(User.id)).group_by(User.tenant_id))
        ).all()
        counts_map = {tid: cnt for tid, cnt in counts_rows}
        return [
            {
                "id": t.id,
                "name": t.name,
                "slug": t.slug,
                "is_active": t.is_active,
                "users_count": int(counts_map.get(t.id, 0)),
                "created_at": t.created_at.isoformat(),
            }
            for t in tenants
        ]

    @app.post("/api/v1/auth/superadmin/tenants", status_code=status.HTTP_201_CREATED)
    async def superadmin_create_tenant(
        payload: TenantRegisterRequest,
        actor: CurrentActor = Depends(require_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> TenantRegisterResponse:
        res = await register_tenant(payload, db)
        await audit.record(
            tenant_id=actor.tenant_id,
            service=cfg.service_name,
            action="SUPERADMIN_CREATED_TENANT",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="tenant",
            resource_id=res.tenant_id,
            metadata={"slug": res.company_slug},
        )
        return res

    @app.patch("/api/v1/auth/superadmin/tenants/{tenant_id}/status")
    async def superadmin_update_tenant_status(
        tenant_id: str,
        payload: UpdateTenantStatusRequest,
        actor: CurrentActor = Depends(require_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> dict:
        tenant = await db.scalar(select(Tenant).where(Tenant.id == tenant_id, Tenant.slug != "platform"))
        if tenant is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found.")
        tenant.is_active = payload.is_active
        await db.commit()
        await audit.record(
            tenant_id=actor.tenant_id,
            service=cfg.service_name,
            action="SUPERADMIN_TENANT_STATUS",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="tenant",
            resource_id=tenant.id,
            metadata={"is_active": tenant.is_active},
        )
        return {"id": tenant.id, "slug": tenant.slug, "is_active": tenant.is_active}

    @app.post("/api/v1/auth/superadmin/tenants/{tenant_id}/impersonate")
    async def superadmin_impersonate_tenant(
        tenant_id: str,
        actor: CurrentActor = Depends(require_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> dict:
        tenant = await db.scalar(select(Tenant).where(Tenant.id == tenant_id, Tenant.slug != "platform"))
        if tenant is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found.")
        admin_user = await db.scalar(
            select(User).where(User.tenant_id == tenant.id, User.role == Role.ADMIN.value, User.is_active.is_(True))
        )
        if admin_user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active tenant admin not found.")
        access_token, _ = issue_jwt(
            jwt_priv_key,
            subject=admin_user.id,
            tenant_id=tenant.id,
            role=Role.ADMIN.value,
            ttl_minutes=cfg.access_token_ttl_minutes,
            token_type="access",
            extra_claims={"impersonated_by": actor.user_id},
        )
        await audit.record(
            tenant_id=tenant.id,
            service=cfg.service_name,
            action="SUPERADMIN_IMPERSONATED",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="tenant",
            resource_id=tenant.id,
            metadata={"slug": tenant.slug},
        )
        return {
            "access_token": access_token,
            "tenant_id": tenant.id,
            "tenant_slug": tenant.slug,
            "role": Role.ADMIN.value,
        }

    @app.delete("/api/v1/auth/superadmin/tenants/{tenant_id}")
    async def superadmin_delete_tenant(
        tenant_id: str,
        actor: CurrentActor = Depends(require_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, str]:
        tenant = await db.scalar(select(Tenant).where(Tenant.id == tenant_id, Tenant.slug != "platform"))
        if tenant is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found.")
        slug = tenant.slug
        await db.execute(delete(RefreshToken).where(RefreshToken.tenant_id == tenant_id))
        await db.execute(delete(User).where(User.tenant_id == tenant_id))
        await db.execute(delete(Tenant).where(Tenant.id == tenant_id))
        await db.commit()
        await audit.record(
            tenant_id=actor.tenant_id,
            service=cfg.service_name,
            action="SUPERADMIN_DELETED_TENANT",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="tenant",
            resource_id=tenant_id,
            metadata={"slug": slug},
        )
        return {"deleted": tenant_id, "slug": slug}

    return app


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(create_auth_app(), host="0.0.0.0", port=8001)
