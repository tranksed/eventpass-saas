"""Strict Pydantic v2 schemas for auth-service."""

from __future__ import annotations

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
