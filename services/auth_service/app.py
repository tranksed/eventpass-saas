"""FastAPI application for auth-service (Multi-tenant Identity, MFA, EdDSA JWTs)."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import httpx
import pyotp
from fastapi import Depends, FastAPI, HTTPException, Request, status
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from services.auth_service.config import AuthSettings
from services.auth_service.models import PlatformDomainConfig, RefreshToken, Tenant, User
from services.auth_service.schemas import (
    CheckDnsRequest,
    CheckDnsResponse,
    ConfigureDomainSslRequest,
    CreateUserRequest,
    EnableMFARequest,
    LoginRequest,
    PlatformDomainConfigResponse,
    RefreshRequest,
    SuperAdminLoginRequest,
    SuperAdminResetPasswordRequest,
    SuperAdminSetupRequest,
    SuperAdminUpdateTenantRequest,
    SuperAdminUpdateUserRequest,
    TenantDomainSummary,
    TenantRegisterRequest,
    TenantRegisterResponse,
    TokenResponse,
    UpdateTenantCustomDomainRequest,
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

    async def _ensure_schema_columns(conn) -> None:
        """Safely add newly introduced columns on existing SQLite/Postgres DBs."""
        is_pg = conn.dialect.name == "postgresql"
        alter_columns = [
            ("tenants", "custom_domain", "VARCHAR(255)"),
        ]
        for table, col, col_def in alter_columns:
            try:
                if is_pg:
                    await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col} {col_def}"))
                else:
                    info = await conn.execute(text(f"PRAGMA table_info({table})"))
                    cols = [row[1] for row in info.fetchall()]
                    if col not in cols:
                        await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {col_def}"))
            except Exception:
                pass

    async def _resolve_domain_ips(domain: str) -> list[str]:
        """Resolve domain A records asynchronously using socket.getaddrinfo and DoH fallbacks."""
        clean_domain = domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0].split(":")[0]
        if not clean_domain:
            return []

        resolved: set[str] = set()

        # 1. Standard socket resolution
        try:
            res = await asyncio.to_thread(socket.getaddrinfo, clean_domain, None, socket.AF_INET)
            for item in res:
                if item and len(item) > 4 and item[4][0]:
                    resolved.add(item[4][0])
        except Exception:
            pass

        # 2. Direct DoH queries to authoritative public resolvers (Cloudflare & Google)
        if not resolved:
            doh_urls = [
                f"https://cloudflare-dns.com/dns-query?name={clean_domain}&type=A",
                f"https://dns.google/resolve?name={clean_domain}&type=A",
            ]
            for url in doh_urls:
                try:
                    async with httpx.AsyncClient(timeout=3.0, headers={"accept": "application/dns-json", "User-Agent": "curl/8.0"}) as client:
                        resp = await client.get(url)
                        if resp.status_code == 200:
                            data = resp.json()
                            for ans in data.get("Answer", []):
                                if ans.get("type") == 1 and ans.get("data"):
                                    ip_val = ans["data"].strip()
                                    if ip_val:
                                        resolved.add(ip_val)
                            if resolved:
                                break
                except Exception:
                    continue

        return sorted(list(resolved))

    def _is_valid_public_ip(candidate: str | None) -> bool:
        if not candidate:
            return False
        candidate = candidate.strip().split(":")[0]
        try:
            ip_obj = ipaddress.ip_address(candidate)
            return bool(ip_obj.is_global and not ip_obj.is_private)
        except Exception:
            return False

    async def _get_server_public_ip(request: Request | None = None, override_ip: str | None = None) -> str:
        """Detect public IP of the VPS with multi-layer fallback, strictly filtering out private docker bridge IPs."""
        # 0. Explicit override (if provided and valid)
        if override_ip and _is_valid_public_ip(override_ip):
            return override_ip.strip()

        # 1. Environment variable explicitly set by VPS install/update scripts
        env_ip = os.getenv("SERVER_PUBLIC_IP", "").strip()
        if _is_valid_public_ip(env_ip):
            return env_ip

        # 2. Extract host from incoming HTTP request if user accessed directly via public IP
        if request is not None:
            for header_name in ["x-forwarded-host", "x-forwarded-server", "host"]:
                val = request.headers.get(header_name, "")
                if val:
                    candidate = val.split(":")[0].strip()
                    if _is_valid_public_ip(candidate):
                        return candidate

        # 3. External IP detection services (with 3.5s timeout & curl User-Agent)
        for url in [
            "https://api.ipify.org",
            "https://icanhazip.com",
            "https://ifconfig.me/ip",
            "https://ipinfo.io/ip",
            "https://checkip.amazonaws.com",
        ]:
            try:
                async with httpx.AsyncClient(timeout=3.5, headers={"User-Agent": "curl/8.0"}) as client:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        candidate = resp.text.strip()
                        if _is_valid_public_ip(candidate):
                            return candidate
            except Exception:
                continue

        # 4. In test / dev environments, fallback to 127.0.0.1
        env_name = os.getenv("ENVIRONMENT", "").lower()
        if env_name in ("development", "test", "local") or not env_name:
            return "127.0.0.1"

        # 5. Fallback to env_ip if provided
        if env_ip:
            return env_ip

        return "127.0.0.1"

    async def _get_or_create_platform_domain_config(db: AsyncSession) -> PlatformDomainConfig:
        conf = await db.scalar(select(PlatformDomainConfig))
        if conf is None:
            is_ssl = os.getenv("SSL_ENABLED", "false").lower() in ("true", "1")
            conf = PlatformDomainConfig(
                primary_domain=os.getenv("PLATFORM_DOMAIN", ""),
                ssl_enabled=is_ssl,
                ssl_status="ACTIVE" if is_ssl else "NOT_CONFIGURED",
                ssl_provider="LETS_ENCRYPT",
                ssl_auto_renew=True,
                force_https_redirect=True,
                contact_email=os.getenv("SUPERADMIN_EMAIL", ""),
                last_error="",
            )
            db.add(conf)
            await db.flush()
        return conf

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await init_db_schema(engine, Base.metadata, post_init=_ensure_schema_columns)
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

    @app.patch("/api/v1/auth/superadmin/tenants/{tenant_id}")
    async def superadmin_update_tenant(
        tenant_id: str,
        payload: SuperAdminUpdateTenantRequest,
        actor: CurrentActor = Depends(require_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> dict:
        """SuperAdmin updates tenant commercial name or slug."""
        tenant = await db.scalar(select(Tenant).where(Tenant.id == tenant_id, Tenant.slug != "platform"))
        if tenant is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found.")

        if payload.slug is not None:
            new_slug = payload.slug.strip().lower()
            if new_slug == "platform":
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Reserved slug 'platform'.")
            existing = await db.scalar(
                select(Tenant).where(Tenant.slug == new_slug, Tenant.id != tenant_id)
            )
            if existing is not None:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Slug already in use by another tenant.")
            tenant.slug = new_slug

        if payload.name is not None:
            tenant.name = payload.name.strip()

        await db.commit()
        await audit.record(
            tenant_id=actor.tenant_id,
            service=cfg.service_name,
            action="SUPERADMIN_UPDATED_TENANT",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="tenant",
            resource_id=tenant.id,
            metadata={"name": tenant.name, "slug": tenant.slug},
        )
        return {"id": tenant.id, "name": tenant.name, "slug": tenant.slug, "is_active": tenant.is_active}

    @app.get("/api/v1/auth/superadmin/tenants/{tenant_id}/users")
    async def superadmin_list_tenant_users(
        tenant_id: str,
        actor: CurrentActor = Depends(require_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> list[dict]:
        """SuperAdmin lists all users belonging to a tenant."""
        tenant = await db.scalar(select(Tenant).where(Tenant.id == tenant_id, Tenant.slug != "platform"))
        if tenant is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found.")
        users = (
            await db.scalars(select(User).where(User.tenant_id == tenant_id).order_by(User.created_at.asc()))
        ).all()
        return [
            {
                "id": u.id,
                "tenant_id": u.tenant_id,
                "email": u.email,
                "full_name": u.full_name,
                "role": u.role,
                "is_active": u.is_active,
                "mfa_enabled": u.mfa_enabled,
                "failed_attempts": u.failed_attempts,
                "created_at": u.created_at.isoformat(),
            }
            for u in users
        ]

    @app.post("/api/v1/auth/superadmin/tenants/{tenant_id}/users", status_code=status.HTTP_201_CREATED)
    async def superadmin_create_tenant_user(
        tenant_id: str,
        payload: CreateUserRequest,
        actor: CurrentActor = Depends(require_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> UserSummary:
        """SuperAdmin creates an admin, supervisor, or validator user inside a tenant."""
        tenant = await db.scalar(select(Tenant).where(Tenant.id == tenant_id, Tenant.slug != "platform"))
        if tenant is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found.")
        if payload.role == Role.SUPERADMIN:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot assign SUPERADMIN role to tenant user.")

        existing = await db.scalar(
            select(User).where(User.tenant_id == tenant_id, User.email == payload.email.lower())
        )
        if existing is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User email already exists in tenant.")

        new_user = User(
            tenant_id=tenant_id,
            email=payload.email.lower(),
            full_name=payload.full_name,
            password_hash=hash_password(payload.password),
            role=payload.role.value,
        )
        db.add(new_user)
        await db.commit()
        await audit.record(
            tenant_id=tenant_id,
            service=cfg.service_name,
            action="SUPERADMIN_CREATED_TENANT_USER",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="user",
            resource_id=new_user.id,
            metadata={"assigned_role": payload.role.value, "email": new_user.email},
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

    @app.post("/api/v1/auth/superadmin/tenants/{tenant_id}/users/{user_id}/reset-password")
    async def superadmin_reset_user_password(
        tenant_id: str,
        user_id: str,
        payload: SuperAdminResetPasswordRequest,
        actor: CurrentActor = Depends(require_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, Any]:
        """SuperAdmin changes/resets the password of any tenant administrator or user."""
        tenant = await db.scalar(select(Tenant).where(Tenant.id == tenant_id, Tenant.slug != "platform"))
        if tenant is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found.")

        user = await db.scalar(select(User).where(User.id == user_id, User.tenant_id == tenant_id))
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found in tenant.")

        user.password_hash = hash_password(payload.new_password)
        user.failed_attempts = 0
        user.locked_until = None
        user.is_active = True

        # Invalidate existing active refresh tokens so stale sessions get terminated
        await db.execute(delete(RefreshToken).where(RefreshToken.user_id == user_id))
        await db.commit()

        await audit.record(
            tenant_id=tenant_id,
            service=cfg.service_name,
            action="SUPERADMIN_RESET_USER_PASSWORD",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="user",
            resource_id=user.id,
            metadata={"email": user.email, "role": user.role},
        )
        return {
            "ok": True,
            "message": f"Contraseña actualizada exitosamente para '{user.email}' ({user.full_name}).",
            "user_id": user.id,
            "email": user.email,
        }

    @app.patch("/api/v1/auth/superadmin/tenants/{tenant_id}/users/{user_id}")
    async def superadmin_update_tenant_user(
        tenant_id: str,
        user_id: str,
        payload: SuperAdminUpdateUserRequest,
        actor: CurrentActor = Depends(require_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> UserSummary:
        """SuperAdmin updates user full name, email, role, or active status."""
        tenant = await db.scalar(select(Tenant).where(Tenant.id == tenant_id, Tenant.slug != "platform"))
        if tenant is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found.")

        user = await db.scalar(select(User).where(User.id == user_id, User.tenant_id == tenant_id))
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found in tenant.")

        if payload.email is not None:
            new_email = payload.email.strip().lower()
            existing = await db.scalar(
                select(User).where(User.tenant_id == tenant_id, User.email == new_email, User.id != user_id)
            )
            if existing is not None:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already in use by another user in tenant.")
            user.email = new_email

        if payload.full_name is not None:
            user.full_name = payload.full_name.strip()

        if payload.role is not None:
            if payload.role == Role.SUPERADMIN:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot assign SUPERADMIN to tenant user.")
            user.role = payload.role.value

        if payload.is_active is not None:
            user.is_active = payload.is_active
            if user.is_active:
                user.failed_attempts = 0
                user.locked_until = None

        await db.commit()
        await audit.record(
            tenant_id=tenant_id,
            service=cfg.service_name,
            action="SUPERADMIN_UPDATED_TENANT_USER",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="user",
            resource_id=user.id,
            metadata={"email": user.email, "role": user.role, "is_active": user.is_active},
        )
        return UserSummary(
            id=user.id,
            tenant_id=user.tenant_id,
            email=user.email,
            full_name=user.full_name,
            role=Role(user.role),
            mfa_enabled=user.mfa_enabled,
            is_active=user.is_active,
        )

    @app.delete("/api/v1/auth/superadmin/tenants/{tenant_id}/users/{user_id}")
    async def superadmin_delete_tenant_user(
        tenant_id: str,
        user_id: str,
        actor: CurrentActor = Depends(require_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> dict[str, str]:
        """SuperAdmin deletes an individual tenant user."""
        tenant = await db.scalar(select(Tenant).where(Tenant.id == tenant_id, Tenant.slug != "platform"))
        if tenant is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found.")

        user = await db.scalar(select(User).where(User.id == user_id, User.tenant_id == tenant_id))
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found in tenant.")

        email = user.email
        await db.execute(delete(RefreshToken).where(RefreshToken.user_id == user_id))
        await db.delete(user)
        await db.commit()

        await audit.record(
            tenant_id=tenant_id,
            service=cfg.service_name,
            action="SUPERADMIN_DELETED_TENANT_USER",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="user",
            resource_id=user_id,
            metadata={"email": email},
        )
        return {"deleted": user_id, "email": email}

    # -------------------------------------------------------------------------
    # Domain & SSL Management Endpoints (SuperAdmin Master)
    # -------------------------------------------------------------------------
    @app.get("/api/v1/auth/superadmin/domain-ssl", response_model=PlatformDomainConfigResponse)
    async def get_domain_ssl_status(
        request: Request,
        actor: CurrentActor = Depends(require_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> PlatformDomainConfigResponse:
        """Get current platform domain, DNS check, and SSL status."""
        conf = await _get_or_create_platform_domain_config(db)
        server_ip = await _get_server_public_ip(request)
        current_scheme = request.headers.get("x-forwarded-proto", request.url.scheme)

        days_remaining = None
        if conf.ssl_expires_at:
            delta = _as_utc(conf.ssl_expires_at) - datetime.now(timezone.utc)
            days_remaining = max(0, delta.days)

        return PlatformDomainConfigResponse(
            primary_domain=conf.primary_domain,
            ssl_enabled=conf.ssl_enabled,
            ssl_status=conf.ssl_status,
            ssl_provider=conf.ssl_provider,
            ssl_issued_at=conf.ssl_issued_at,
            ssl_expires_at=conf.ssl_expires_at,
            days_remaining=days_remaining,
            ssl_auto_renew=conf.ssl_auto_renew,
            force_https_redirect=conf.force_https_redirect,
            contact_email=conf.contact_email,
            server_public_ip=server_ip,
            current_scheme=current_scheme,
            last_dns_check_ip=conf.last_dns_check_ip,
            last_dns_check_at=conf.last_dns_check_at,
            last_error=conf.last_error,
            updated_at=conf.updated_at,
        )

    @app.post("/api/v1/auth/superadmin/domain-ssl/check-dns", response_model=CheckDnsResponse)
    async def check_domain_dns(
        payload: CheckDnsRequest,
        request: Request,
        actor: CurrentActor = Depends(require_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> CheckDnsResponse:
        """Validate whether a domain or subdomain resolves to this VPS public IP."""
        clean_domain = payload.domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0].split(":")[0]
        resolved = await _resolve_domain_ips(clean_domain)
        server_ip = await _get_server_public_ip(request, override_ip=payload.override_server_ip)

        is_dev = server_ip in ("127.0.0.1", "localhost")
        match = (server_ip in resolved) or (is_dev and clean_domain in ("localhost", "127.0.0.1"))

        if match:
            msg = f"¡Verificación exitosa! El dominio '{clean_domain}' apunta correctamente a este servidor ({server_ip}). Ya puedes activar el certificado SSL."
        elif not resolved:
            msg = f"El dominio '{clean_domain}' no tiene registros DNS A configurados o aún no se han propagado. Crea un registro tipo A hacia la IP {server_ip} en tu proveedor de DNS (Cloudflare, GoDaddy, Namecheap)."
        else:
            msg = f"El dominio '{clean_domain}' resuelve a {', '.join(resolved)}, pero la IP de este servidor es {server_ip}. Actualiza el registro A en tu proveedor DNS antes de emitir SSL."

        conf = await _get_or_create_platform_domain_config(db)
        conf.last_dns_check_ip = ", ".join(resolved) if resolved else "NO_RECORDS"
        conf.last_dns_check_at = datetime.now(timezone.utc)
        await db.commit()

        return CheckDnsResponse(
            domain=clean_domain,
            resolved_ips=resolved,
            server_ip=server_ip,
            match=match,
            message=msg,
        )

    @app.post("/api/v1/auth/superadmin/domain-ssl/configure", response_model=PlatformDomainConfigResponse)
    async def configure_domain_ssl(
        payload: ConfigureDomainSslRequest,
        request: Request,
        actor: CurrentActor = Depends(require_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> PlatformDomainConfigResponse:
        """Configure platform domain and provision / enable SSL certificate state."""
        clean_domain = payload.primary_domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0].split(":")[0]
        resolved = await _resolve_domain_ips(clean_domain)
        server_ip = await _get_server_public_ip(request, override_ip=payload.override_server_ip)

        is_dev = server_ip in ("127.0.0.1", "localhost")
        dns_match = (server_ip in resolved) or (is_dev and clean_domain in ("localhost", "127.0.0.1"))

        conf = await _get_or_create_platform_domain_config(db)
        conf.primary_domain = clean_domain
        conf.contact_email = payload.contact_email
        conf.force_https_redirect = payload.force_https_redirect
        conf.ssl_auto_renew = payload.ssl_auto_renew
        conf.last_dns_check_ip = ", ".join(resolved) if resolved else "NO_RECORDS"
        conf.last_dns_check_at = datetime.now(timezone.utc)

        if dns_match or payload.force_ssl or is_dev:
            conf.ssl_enabled = True
            conf.ssl_status = "ACTIVE"
            conf.ssl_issued_at = datetime.now(timezone.utc)
            conf.ssl_expires_at = datetime.now(timezone.utc) + timedelta(days=90)
            conf.last_error = ""
        else:
            conf.ssl_enabled = False
            conf.ssl_status = "PENDING_DNS"
            conf.last_error = f"El dominio '{clean_domain}' aún no apunta a la IP pública del VPS ({server_ip})."

        await db.commit()
        await audit.record(
            tenant_id="platform",
            service=cfg.service_name,
            action="PLATFORM_DOMAIN_SSL_CONFIGURED",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="domain_ssl",
            resource_id=conf.id,
            metadata={
                "primary_domain": conf.primary_domain,
                "ssl_status": conf.ssl_status,
                "dns_match": dns_match,
            },
        )
        return await get_domain_ssl_status(request, actor=actor, db=db)

    @app.get("/api/v1/auth/superadmin/tenants/domains", response_model=list[TenantDomainSummary])
    async def list_tenants_domains(
        request: Request,
        actor: CurrentActor = Depends(require_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> list[TenantDomainSummary]:
        """List all registered tenants and their custom domain mapping status."""
        tenants = (await db.scalars(select(Tenant).where(Tenant.slug != "platform").order_by(Tenant.name.asc()))).all()
        server_ip = await _get_server_public_ip(request)
        result = []
        for t in tenants:
            resolved_ip = None
            dns_match = False
            if t.custom_domain:
                ips = await _resolve_domain_ips(t.custom_domain)
                resolved_ip = ips[0] if ips else None
                dns_match = server_ip in ips
            result.append(
                TenantDomainSummary(
                    tenant_id=t.id,
                    name=t.name,
                    slug=t.slug,
                    custom_domain=t.custom_domain,
                    dns_match=dns_match,
                    resolved_ip=resolved_ip,
                )
            )
        return result

    @app.put("/api/v1/auth/superadmin/tenants/{tenant_id}/custom-domain", response_model=TenantDomainSummary)
    async def update_tenant_custom_domain(
        tenant_id: str,
        payload: UpdateTenantCustomDomainRequest,
        request: Request,
        actor: CurrentActor = Depends(require_superadmin),
        db: AsyncSession = Depends(get_db),
    ) -> TenantDomainSummary:
        """Assign or clear a custom domain for a tenant with instant DNS check."""
        tenant = await db.scalar(select(Tenant).where(Tenant.id == tenant_id, Tenant.slug != "platform"))
        if tenant is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found.")

        clean_domain = None
        if payload.custom_domain:
            clean_domain = payload.custom_domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0].split(":")[0]

        tenant.custom_domain = clean_domain
        await db.commit()

        server_ip = await _get_server_public_ip(request)
        resolved_ip = None
        dns_match = False
        if clean_domain:
            ips = await _resolve_domain_ips(clean_domain)
            resolved_ip = ips[0] if ips else None
            dns_match = server_ip in ips

        await audit.record(
            tenant_id=tenant.id,
            service=cfg.service_name,
            action="TENANT_CUSTOM_DOMAIN_UPDATED",
            actor_id=actor.user_id,
            actor_role=actor.role.value,
            resource_type="tenant",
            resource_id=tenant.id,
            metadata={"custom_domain": clean_domain, "dns_match": dns_match},
        )
        return TenantDomainSummary(
            tenant_id=tenant.id,
            name=tenant.name,
            slug=tenant.slug,
            custom_domain=tenant.custom_domain,
            dns_match=dns_match,
            resolved_ip=resolved_ip,
        )

    return app


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(create_auth_app(), host="0.0.0.0", port=8001)
