"""Strict Pydantic v2 schemas for accreditation-service."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class CreateAccreditedCompanyRequest(StrictModel):
    event_id: str = Field(min_length=1, max_length=36)
    company_name: str = Field(min_length=2, max_length=160)
    contact_email: str = Field(min_length=5, max_length=255)
    custom_quota: int | None = Field(default=None, ge=1, le=500)
    event_ends_at: datetime | None = None


class AccreditedCompanyResponse(BaseModel):
    company_id: str
    tenant_id: str
    event_id: str
    company_name: str
    staff_quota: int
    staff_used: int
    invite_url: str | None = None
    invite_token: str | None = None
    link_expires_at: datetime


class UpdateCompanyQuotaRequest(StrictModel):
    staff_quota: int = Field(ge=1, le=500)


class RegisterStaffByInviteRequest(StrictModel):
    dni: str = Field(min_length=6, max_length=20)
    full_name: str = Field(min_length=2, max_length=150)
    role_title: str = Field(min_length=2, max_length=100)


class StaffCredentialResponse(BaseModel):
    staff_id: str
    company_id: str
    company_name: str
    display_name: str
    dni_last4: str
    credential_id: str
    qr_token: str
    short_code: str | None = None
    remaining_quota: int


class IssueInternalCredentialRequest(StrictModel):
    tenant_id: str = Field(min_length=1, max_length=36)
    event_id: str = Field(min_length=1, max_length=36)
    order_id: str | None = Field(default=None, max_length=36)
    holder_type: str = Field(pattern=r"^(PARTICIPANT|STAFF)$")
    holder_ref_id: str = Field(min_length=1, max_length=36)
    display_name: str = Field(min_length=1, max_length=150)
    dni_last4: str = Field(min_length=4, max_length=8)
    short_code: str | None = Field(default=None, max_length=24)
    entitlements: dict[str, int] = Field(min_length=1)
    expires_at: datetime


class CheckInRequest(StrictModel):
    qr_token: str = Field(default="", max_length=4096)
    code: str | None = Field(default=None, max_length=4096)
    entitlement_code: str = Field(default="ENTRY", min_length=1, max_length=40)
    gate_id: str = Field(default="MAIN_GATE", min_length=1, max_length=64)
    device_id: str = Field(default="SCANNER_01", min_length=1, max_length=120)
    client_scan_id: str | None = Field(default=None, max_length=120)


class CredentialLookupRequest(StrictModel):
    code: str = Field(min_length=3, max_length=4096)
    event_id: str | None = Field(default=None, max_length=36)
    gate_id: str | None = Field(default=None, max_length=64)


class CredentialLookupResponse(BaseModel):
    found: bool
    credential_id: str
    qr_token: str
    short_code: str
    display_name: str
    dni_last4: str
    holder_type: str
    company_label: str | None = None
    status: str
    entitlements: dict[str, int]
    redeemed: dict[str, int]
    is_already_redeemed: bool
    can_redeem: bool
    last_scanned_at: str | None = None
    last_gate_id: str | None = None
    item_name: str | None = None


class CheckInResponse(BaseModel):
    outcome: str
    credential_id: str
    holder_type: str
    display_name: str
    company_label: str | None = None
    dni_last4: str
    entitlement_code: str
    remaining_for_code: int
    all_remaining: dict[str, int]
    short_code: str | None = None


class OfflineCredentialSnapshot(BaseModel):
    credential_id: str
    holder_type: str
    display_name: str
    company_label: str | None = None
    dni_last4: str
    status: str
    short_code: str | None = None
    entitlements: dict[str, int]
    redeemed: dict[str, int]


class OfflineBundleResponse(BaseModel):
    tenant_id: str
    event_id: str
    generated_at: datetime
    qr_public_key_pem: str
    credentials: list[OfflineCredentialSnapshot]
    bundle_token: str


class OfflineScanItem(StrictModel):
    client_scan_id: str = Field(min_length=4, max_length=120)
    qr_token: str = Field(min_length=20, max_length=4096)
    entitlement_code: str = Field(default="ENTRY", min_length=1, max_length=40)
    gate_id: str = Field(min_length=1, max_length=64)
    device_id: str = Field(min_length=1, max_length=120)
    scanned_at: datetime


class OfflineSyncBatchRequest(StrictModel):
    scans: list[OfflineScanItem] = Field(min_length=1, max_length=2000)


class OfflineSyncResultItem(BaseModel):
    client_scan_id: str
    credential_id: str | None = None
    outcome: str
    detail: str


class OfflineSyncBatchResponse(BaseModel):
    processed: int
    granted: int
    conflicts: int
    duplicates_ignored: int
    rejected: int
    results: list[OfflineSyncResultItem]
