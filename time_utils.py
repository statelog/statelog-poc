from datetime import datetime

from .time_utils import utcnow_naive

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

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
