from datetime import datetime

from .time_utils import utcnow_naive

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint

from .database import Base


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    plan: Mapped[str] = mapped_column(String(50), default="starter")
    monthly_quota: Mapped[int] = mapped_column(Integer, default=1000)
    usage_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow_naive)


class ClientCredential(Base):
    __tablename__ = "client_credentials"
    __table_args__ = (UniqueConstraint("tenant_id", "client_id", name="uq_client_per_tenant"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    client_id: Mapped[str] = mapped_column(String(100), index=True)
    api_key_hash: Mapped[str] = mapped_column(String(128))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow_naive)

class WorkflowConfigRecord(Base):
    __tablename__ = "workflow_configs"

    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id"),
        primary_key=True,
    )
    include_risk_step: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
    )
    include_policy_step: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
    )
    execution_mode: Mapped[str] = mapped_column(
        String(32),
        default="risk_first",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=utcnow_naive,
    )

class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("tenant_id", "device_id", name="uq_device_per_tenant"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    device_id: Mapped[str] = mapped_column(String(100), index=True)
    description: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow_naive)


class AccessRight(Base):
    __tablename__ = "access_rights"
    __table_args__ = (UniqueConstraint("tenant_id", "right_id", name="uq_right_per_tenant"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    right_id: Mapped[str] = mapped_column(String(100), index=True)
    owner_id: Mapped[str] = mapped_column(String(100), index=True)
    valid: Mapped[bool] = mapped_column(Boolean, default=True)
    owner_change_count: Mapped[int] = mapped_column(Integer, default=0)
    version: Mapped[int] = mapped_column(Integer, default=1)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow_naive)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow_naive, onupdate=utcnow_naive)


class RequestLog(Base):
    __tablename__ = "request_logs"
    __table_args__ = (UniqueConstraint("tenant_id", "idempotency_key", name="uq_request_idempotency_per_tenant"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    right_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    client_id: Mapped[str] = mapped_column(String(100), index=True)
    source_client: Mapped[str] = mapped_column(String(100), index=True)
    device_id: Mapped[str] = mapped_column(String(100), index=True)
    user_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    ip_hash: Mapped[str] = mapped_column(String(128), index=True)
    country_code: Mapped[str] = mapped_column(String(8), default="ZZ")
    request_type: Mapped[str] = mapped_column(String(50))
    allowed: Mapped[bool] = mapped_column(Boolean)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    reason: Mapped[str] = mapped_column(String(255))
    risk_signals: Mapped[str] = mapped_column(Text, default="")
    policy_matched: Mapped[bool] = mapped_column(Boolean, default=False)
    policy_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    policy_version: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    trace_id: Mapped[str] = mapped_column(String(64), index=True)
    idempotency_key: Mapped[str] = mapped_column(String(128), index=True)
    token_jti: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    request_fingerprint: Mapped[str] = mapped_column(String(128), index=True)
    user_agent: Mapped[str] = mapped_column(String(512), default="")
    decision_version: Mapped[str] = mapped_column(String(32), default="v8")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow_naive, index=True)


class WebhookSubscription(Base):
    __tablename__ = "webhook_subscriptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    target_url: Mapped[str] = mapped_column(Text)
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    signing_secret_hash: Mapped[str] = mapped_column(String(128))
    signing_secret_encrypted: Mapped[str] = mapped_column(Text)
    signing_secret_key_version: Mapped[str] = mapped_column(String(32), default='v1')
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow_naive)


class OutboxEvent(Base):
    __tablename__ = "outbox_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    payload: Mapped[str] = mapped_column(Text)
    delivered: Mapped[bool] = mapped_column(Boolean, default=False)
    dead_lettered: Mapped[bool] = mapped_column(Boolean, default=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow_naive, index=True)
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow_naive)


class WebhookDeliveryAttempt(Base):
    __tablename__ = 'webhook_delivery_attempts'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[int] = mapped_column(ForeignKey('outbox_events.id'), index=True)
    subscription_id: Mapped[int] = mapped_column(ForeignKey('webhook_subscriptions.id'), index=True)
    attempt_number: Mapped[int] = mapped_column(Integer, default=1)
    successful: Mapped[bool] = mapped_column(Boolean, default=False)
    response_status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str | None] = mapped_column(String(500), nullable=True)
    signature_version: Mapped[str] = mapped_column(String(16), default='v1')
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow_naive)

class PolicyRecord(Base):
    __tablename__ = "policies"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_policy_name_per_tenant"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id"),
        index=True,
    )

    name: Mapped[str] = mapped_column(String(100), index=True)
    effect: Mapped[str] = mapped_column(String(16))
    priority: Mapped[int] = mapped_column(Integer, default=100)
    version: Mapped[int] = mapped_column(Integer, default=1)
    
    request_types: Mapped[str] = mapped_column(Text, default="")
    countries: Mapped[str] = mapped_column(Text, default="")
    device_ids: Mapped[str] = mapped_column(Text, default="")

    max_risk_score: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    min_trust_score: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    max_transaction_amount: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    allowed_start_hour: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    allowed_end_hour: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    valid_from: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=utcnow_naive,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=utcnow_naive,
        onupdate=utcnow_naive,
    )

class PolicyHistory(Base):
    __tablename__ = "policy_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    policy_id: Mapped[int] = mapped_column(Integer, index=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id"),
        index=True,
    )

    policy_name: Mapped[str] = mapped_column(String(100))
    version: Mapped[int] = mapped_column(Integer)

    effect: Mapped[str] = mapped_column(String(16))
    priority: Mapped[int] = mapped_column(Integer)

    request_types: Mapped[str] = mapped_column(Text, default="")
    countries: Mapped[str] = mapped_column(Text, default="")
    device_ids: Mapped[str] = mapped_column(Text, default="")

    max_risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    min_trust_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    
    max_transaction_amount: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    allowed_start_hour: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    allowed_end_hour: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    valid_from: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=utcnow_naive,
    )