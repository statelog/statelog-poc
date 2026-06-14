from typing import Literal, Optional

from pydantic import BaseModel, Field, HttpUrl


class TenantCreate(BaseModel):
    tenant_id: str
    name: str
    plan: str = "starter"
    monthly_quota: int = 1000


class ClientCreate(BaseModel):
    tenant_id: str
    client_id: str
    api_key: str


class DeviceCreate(BaseModel):
    tenant_id: str
    device_id: str
    description: str = ""


class AccessRightCreate(BaseModel):
    tenant_id: str
    right_id: str
    owner_id: str
    valid: bool = True


class TokenIssueRequest(BaseModel):
    tenant_id: str
    right_id: str
    user_id: str
    device_id: str
    scope: Literal["access", "ownership_transfer"] = "access"


class AccessRequest(BaseModel):
    token: str
    request_type: Literal["access", "ownership_transfer"]
    device_id: str
    ip_address: str
    country_code: str = Field(default="EE", min_length=2, max_length=8)
    new_owner_id: Optional[str] = None


class WebhookCreate(BaseModel):
    tenant_id: str
    target_url: HttpUrl
    event_type: str
    signing_secret: str


class DecisionResponse(BaseModel):
    allow: bool
    reason: str
    risk_score: int
    trace_id: str
    decision_version: str
    idempotency_key: str
