"""Strict Pydantic v2 schemas for auth-service."""

from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field

from shared_kernel.security import Role


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class TenantRegisterRequest(StrictModel):
    company_name: str = Field(min_length=2, max_length=120)
    company_slug: str = Field(min_length=2, max_length=80, pattern=r"^[a-z0-9-]+$")
    admin_email: str = Field(min_length=5, max_length=255)
    admin_full_name: str = Field(min_length=2, max_length=150)
    admin_password: str = Field(min_length=8, max_length=128)


class LoginRequest(StrictModel):
    tenant_slug: str = Field(min_length=2, max_length=80)
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=8, max_length=128)
    mfa_code: str | None = Field(default=None, min_length=6, max_length=8)
    device_id: str | None = Field(default=None, max_length=120)


class RefreshRequest(StrictModel):
    refresh_token: str = Field(min_length=16, max_length=512)
    device_id: str | None = Field(default=None, max_length=120)


class CreateUserRequest(StrictModel):
    email: str = Field(min_length=5, max_length=255)
    full_name: str = Field(min_length=2, max_length=150)
    password: str = Field(min_length=8, max_length=128)
    role: Role


class EnableMFARequest(StrictModel):
    totp_code: str = Field(min_length=6, max_length=8)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in_seconds: int
    tenant_id: str
    user_id: str
    role: Role


class UserSummary(BaseModel):
    id: str
    tenant_id: str
    email: str
    full_name: str
    role: Role
    mfa_enabled: bool
    is_active: bool


class TenantRegisterResponse(BaseModel):
    tenant_id: str
    company_name: str
    company_slug: str
    user: UserSummary
    tokens: TokenResponse


class SuperAdminSetupRequest(StrictModel):
    full_name: str = Field(default="Platform SuperAdmin", min_length=2, max_length=150)
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=8, max_length=128)


class SuperAdminLoginRequest(StrictModel):
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=8, max_length=128)
    mfa_code: str | None = Field(default=None, min_length=6, max_length=8)


class UpdateTenantStatusRequest(StrictModel):
    is_active: bool


class SuperAdminResetPasswordRequest(StrictModel):
    new_password: str = Field(min_length=8, max_length=128)


class SuperAdminUpdateTenantRequest(StrictModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    slug: str | None = Field(default=None, min_length=2, max_length=80, pattern=r"^[a-z0-9-]+$")


class SuperAdminUpdateUserRequest(StrictModel):
    full_name: str | None = Field(default=None, min_length=2, max_length=150)
    email: str | None = Field(default=None, min_length=5, max_length=255)
    role: Role | None = None
    is_active: bool | None = None


# -----------------------------------------------------------------------------
# Domain & SSL Schemas
# -----------------------------------------------------------------------------
class CheckDnsRequest(StrictModel):
    domain: str = Field(min_length=3, max_length=255)
    override_server_ip: str | None = Field(default=None, max_length=45)


class CheckDnsResponse(BaseModel):
    domain: str
    resolved_ips: list[str]
    server_ip: str
    match: bool
    message: str


class ConfigureDomainSslRequest(StrictModel):
    primary_domain: str = Field(min_length=3, max_length=255)
    contact_email: str = Field(min_length=5, max_length=255)
    ssl_enabled: bool = True
    force_https_redirect: bool = True
    ssl_auto_renew: bool = True
    override_server_ip: str | None = Field(default=None, max_length=45)


class PlatformDomainConfigResponse(BaseModel):
    primary_domain: str
    ssl_enabled: bool
    ssl_status: str
    ssl_provider: str
    ssl_issued_at: datetime | None = None
    ssl_expires_at: datetime | None = None
    days_remaining: int | None = None
    ssl_auto_renew: bool
    force_https_redirect: bool
    contact_email: str
    server_public_ip: str
    current_scheme: str
    last_dns_check_ip: str
    last_dns_check_at: datetime | None = None
    last_error: str = ""
    updated_at: datetime


class UpdateTenantCustomDomainRequest(StrictModel):
    custom_domain: str | None = Field(default=None, max_length=255)


class TenantDomainSummary(BaseModel):
    tenant_id: str
    name: str
    slug: str
    custom_domain: str | None = None
    dns_match: bool = False
    resolved_ip: str | None = None
