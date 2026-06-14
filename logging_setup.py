"""v8 baseline

Revision ID: 0001_v8_baseline
Revises: 
Create Date: 2026-04-16
"""

from alembic import op
import sqlalchemy as sa

revision = "0001_v8_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("plan", sa.String(length=50), nullable=False),
        sa.Column("monthly_quota", sa.Integer(), nullable=False),
        sa.Column("usage_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "client_credentials",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("client_id", sa.String(length=100), nullable=False),
        sa.Column("api_key_hash", sa.String(length=128), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "client_id", name="uq_client_per_tenant"),
    )
    op.create_index(op.f("ix_client_credentials_client_id"), "client_credentials", ["client_id"], unique=False)
    op.create_index(op.f("ix_client_credentials_tenant_id"), "client_credentials", ["tenant_id"], unique=False)
    op.create_table(
        "devices",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("device_id", sa.String(length=100), nullable=False),
        sa.Column("description", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "device_id", name="uq_device_per_tenant"),
    )
    op.create_index(op.f("ix_devices_device_id"), "devices", ["device_id"], unique=False)
    op.create_index(op.f("ix_devices_tenant_id"), "devices", ["tenant_id"], unique=False)
    op.create_table(
        "access_rights",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("right_id", sa.String(length=100), nullable=False),
        sa.Column("owner_id", sa.String(length=100), nullable=False),
        sa.Column("valid", sa.Boolean(), nullable=False),
        sa.Column("owner_change_count", sa.Integer(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "right_id", name="uq_right_per_tenant"),
    )
    op.create_index(op.f("ix_access_rights_owner_id"), "access_rights", ["owner_id"], unique=False)
    op.create_index(op.f("ix_access_rights_right_id"), "access_rights", ["right_id"], unique=False)
    op.create_index(op.f("ix_access_rights_tenant_id"), "access_rights", ["tenant_id"], unique=False)
    op.create_table(
        "request_logs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("right_id", sa.String(length=100), nullable=True),
        sa.Column("client_id", sa.String(length=100), nullable=False),
        sa.Column("source_client", sa.String(length=100), nullable=False),
        sa.Column("device_id", sa.String(length=100), nullable=False),
        sa.Column("user_id", sa.String(length=100), nullable=True),
        sa.Column("ip_hash", sa.String(length=128), nullable=False),
        sa.Column("country_code", sa.String(length=8), nullable=False),
        sa.Column("request_type", sa.String(length=50), nullable=False),
        sa.Column("allowed", sa.Boolean(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("reason", sa.String(length=255), nullable=False),
        sa.Column("trace_id", sa.String(length=64), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("token_jti", sa.String(length=64), nullable=True),
        sa.Column("request_fingerprint", sa.String(length=128), nullable=False),
        sa.Column("user_agent", sa.String(length=512), nullable=False),
        sa.Column("decision_version", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_request_idempotency_per_tenant"),
    )
    for idx in ["tenant_id", "right_id", "client_id", "source_client", "device_id", "ip_hash", "trace_id", "idempotency_key", "token_jti", "request_fingerprint", "created_at"]:
        op.create_index(f"ix_request_logs_{idx}", "request_logs", [idx], unique=False)
    op.create_table(
        "webhook_subscriptions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("target_url", sa.Text(), nullable=False),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("signing_secret_hash", sa.String(length=128), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_webhook_subscriptions_event_type"), "webhook_subscriptions", ["event_type"], unique=False)
    op.create_index(op.f("ix_webhook_subscriptions_tenant_id"), "webhook_subscriptions", ["tenant_id"], unique=False)
    op.create_table(
        "outbox_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("delivered", sa.Boolean(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(), nullable=False),
        sa.Column("last_error", sa.String(length=500), nullable=True),
        sa.Column("delivered_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_outbox_events_event_type"), "outbox_events", ["event_type"], unique=False)
    op.create_index(op.f("ix_outbox_events_next_attempt_at"), "outbox_events", ["next_attempt_at"], unique=False)
    op.create_index(op.f("ix_outbox_events_tenant_id"), "outbox_events", ["tenant_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_outbox_events_tenant_id"), table_name="outbox_events")
    op.drop_index(op.f("ix_outbox_events_next_attempt_at"), table_name="outbox_events")
    op.drop_index(op.f("ix_outbox_events_event_type"), table_name="outbox_events")
    op.drop_table("outbox_events")
    op.drop_index(op.f("ix_webhook_subscriptions_tenant_id"), table_name="webhook_subscriptions")
    op.drop_index(op.f("ix_webhook_subscriptions_event_type"), table_name="webhook_subscriptions")
    op.drop_table("webhook_subscriptions")
    for idx in ["created_at", "request_fingerprint", "token_jti", "idempotency_key", "trace_id", "ip_hash", "device_id", "source_client", "client_id", "right_id", "tenant_id"]:
        op.drop_index(f"ix_request_logs_{idx}", table_name="request_logs")
    op.drop_table("request_logs")
    op.drop_index(op.f("ix_access_rights_tenant_id"), table_name="access_rights")
    op.drop_index(op.f("ix_access_rights_right_id"), table_name="access_rights")
    op.drop_index(op.f("ix_access_rights_owner_id"), table_name="access_rights")
    op.drop_table("access_rights")
    op.drop_index(op.f("ix_devices_tenant_id"), table_name="devices")
    op.drop_index(op.f("ix_devices_device_id"), table_name="devices")
    op.drop_table("devices")
    op.drop_index(op.f("ix_client_credentials_tenant_id"), table_name="client_credentials")
    op.drop_index(op.f("ix_client_credentials_client_id"), table_name="client_credentials")
    op.drop_table("client_credentials")
    op.drop_table("tenants")
