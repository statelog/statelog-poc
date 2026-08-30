from datetime import datetime
from typing import Annotated, Literal, Optional

from pydantic import BaseModel, Field, HttpUrl


class TenantCreate(BaseModel):
    tenant_id: str
    name: str
    plan: str = "starter"
    monthly_quota: int = 1000

class WorkflowConfigUpdate(BaseModel):
    tenant_id: str
    include_risk_step: bool = True
    include_policy_step: bool = True
    execution_mode: Literal["risk_first", "policy_first"] = "risk_first"

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


class AccessRightRevoke(BaseModel):
    tenant_id: str
    right_id: str

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
    transaction_amount: Optional[float] = None
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
    trust_score: int
    trace_id: str
    decision_version: str
    workflow_version: int = 1
    idempotency_key: str
    policy_matched: bool = False
    policy_name: Optional[str] = None
    risk_signals: list[str] = []
    explanation: dict = {}

class PolicySimulationRequest(BaseModel):
    tenant_id: str = Field(min_length=1, pattern=r".*\S.*")
    request_type: str = Field(min_length=1, pattern=r".*\S.*")
    device_id: str = Field(min_length=1, pattern=r".*\S.*")
    country_code: str = Field(
        min_length=2,
        max_length=8,
        pattern=r".*\S.*",
    )
    risk_score: int = Field(ge=0, le=100)
    trust_score: Optional[int] = Field(default=None, ge=0, le=100)
    transaction_amount: Optional[float] = Field(default=None, ge=0)
    hour: Optional[int] = Field(default=None, ge=0, le=23)

NonBlankStr = Annotated[
    str,
    Field(min_length=1, pattern=r".*\S.*"),
]

class PolicyCreate(BaseModel):
    tenant_id: str
    name: str = Field(min_length=1, pattern=r".*\S.*")
    effect: Literal["allow", "deny"]
    priority: int = 100

    request_types: list[NonBlankStr] = []
    countries: list[NonBlankStr] = []
    device_ids: list[NonBlankStr] = []

    max_risk_score: Optional[int] = Field(default=None, ge=0, le=100)
    min_trust_score: Optional[int] = Field(default=None, ge=0, le=100)
    max_transaction_amount: Optional[float] = Field(default=None, ge=0)
    allowed_start_hour: Optional[int] = Field(default=None, ge=0, le=23)
    allowed_end_hour: Optional[int] = Field(default=None, ge=0, le=23)
    enabled: bool = True
    valid_from: Optional[datetime] = None
    expires_at: Optional[datetime] = None

class PolicyUpdate(BaseModel):
    effect: Optional[Literal["allow", "deny"]] = None
    priority: Optional[int] = None

    request_types: Optional[list[NonBlankStr]] = None
    countries: Optional[list[NonBlankStr]] = None
    device_ids: Optional[list[NonBlankStr]] = None

    max_risk_score: Optional[int] = Field(default=None, ge=0, le=100)
    min_trust_score: Optional[int] = Field(default=None, ge=0, le=100)
    max_transaction_amount: Optional[float] = Field(default=None, ge=0)
    allowed_start_hour: Optional[int] = Field(default=None, ge=0, le=23)
    allowed_end_hour: Optional[int] = Field(default=None, ge=0, le=23)
    enabled: Optional[bool] = None
    valid_from: Optional[datetime] = None
    expires_at: Optional[datetime] = None
