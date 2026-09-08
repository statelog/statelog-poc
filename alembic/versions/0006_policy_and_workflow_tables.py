"""add policy and workflow tables

Revision ID: 0006_policy_and_workflow_tables
Revises: 0005_request_log_policy_fields
Create Date: 2026-09-07
"""

from alembic import op
import sqlalchemy as sa


revision = "0006_policy_and_workflow_tables"
down_revision = "0005_request_log_policy_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "workflow_configs",
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("include_risk_step", sa.Boolean(), nullable=False),
        sa.Column("include_policy_step", sa.Boolean(), nullable=False),
        sa.Column("execution_mode", sa.String(length=32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
        ),
        sa.PrimaryKeyConstraint("tenant_id"),
    )

    op.create_table(
        "workflow_config_history",
        sa.Column(
            "id",
            sa.Integer(),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("include_risk_step", sa.Boolean(), nullable=False),
        sa.Column("include_policy_step", sa.Boolean(), nullable=False),
        sa.Column("execution_mode", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_workflow_config_history_tenant_id"),
        "workflow_config_history",
        ["tenant_id"],
        unique=False,
    )

    op.create_table(
        "policies",
        sa.Column(
            "id",
            sa.Integer(),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("effect", sa.String(length=16), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("request_types", sa.Text(), nullable=False),
        sa.Column("countries", sa.Text(), nullable=False),
        sa.Column("device_ids", sa.Text(), nullable=False),
        sa.Column("max_risk_score", sa.Integer(), nullable=True),
        sa.Column("min_trust_score", sa.Integer(), nullable=True),
        sa.Column("max_transaction_amount", sa.Float(), nullable=True),
        sa.Column("allowed_start_hour", sa.Integer(), nullable=True),
        sa.Column("allowed_end_hour", sa.Integer(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("valid_from", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "name",
            name="uq_policy_name_per_tenant",
        ),
    )
    op.create_index(
        op.f("ix_policies_tenant_id"),
        "policies",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_policies_name"),
        "policies",
        ["name"],
        unique=False,
    )

    op.create_table(
        "policy_history",
        sa.Column(
            "id",
            sa.Integer(),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column("policy_id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("policy_name", sa.String(length=100), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("effect", sa.String(length=16), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("request_types", sa.Text(), nullable=False),
        sa.Column("countries", sa.Text(), nullable=False),
        sa.Column("device_ids", sa.Text(), nullable=False),
        sa.Column("max_risk_score", sa.Integer(), nullable=True),
        sa.Column("min_trust_score", sa.Integer(), nullable=True),
        sa.Column("max_transaction_amount", sa.Float(), nullable=True),
        sa.Column("allowed_start_hour", sa.Integer(), nullable=True),
        sa.Column("allowed_end_hour", sa.Integer(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("valid_from", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_policy_history_policy_id"),
        "policy_history",
        ["policy_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_policy_history_tenant_id"),
        "policy_history",
        ["tenant_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_policy_history_tenant_id"),
        table_name="policy_history",
    )
    op.drop_index(
        op.f("ix_policy_history_policy_id"),
        table_name="policy_history",
    )
    op.drop_table("policy_history")

    op.drop_index(
        op.f("ix_policies_name"),
        table_name="policies",
    )
    op.drop_index(
        op.f("ix_policies_tenant_id"),
        table_name="policies",
    )
    op.drop_table("policies")

    op.drop_index(
        op.f("ix_workflow_config_history_tenant_id"),
        table_name="workflow_config_history",
    )
    op.drop_table("workflow_config_history")

    op.drop_table("workflow_configs")