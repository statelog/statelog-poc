"""add request log policy and workflow fields

Revision ID: 0005_request_log_policy_fields
Revises: 0004_v83
Create Date: 2026-09-07
"""

from alembic import op
import sqlalchemy as sa


revision = "0005_request_log_policy_fields"
down_revision = "0004_v83"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "request_logs",
        sa.Column(
            "transaction_amount",
            sa.Float(),
            nullable=True,
        ),
    )
    op.add_column(
        "request_logs",
        sa.Column(
            "new_owner_id",
            sa.String(length=100),
            nullable=True,
        ),
    )
    op.add_column(
        "request_logs",
        sa.Column(
            "risk_signals",
            sa.Text(),
            nullable=False,
            server_default="",
        ),
    )
    op.add_column(
        "request_logs",
        sa.Column(
            "policy_matched",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "request_logs",
        sa.Column(
            "policy_name",
            sa.String(length=100),
            nullable=True,
        ),
    )
    op.add_column(
        "request_logs",
        sa.Column(
            "policy_id",
            sa.Integer(),
            nullable=True,
        ),
    )
    op.add_column(
        "request_logs",
        sa.Column(
            "policy_version",
            sa.Integer(),
            nullable=True,
        ),
    )
    op.add_column(
        "request_logs",
        sa.Column(
            "workflow_version",
            sa.Integer(),
            nullable=True,
        ),
    )

    op.create_index(
        op.f("ix_request_logs_policy_id"),
        "request_logs",
        ["policy_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_request_logs_policy_id"),
        table_name="request_logs",
    )

    op.drop_column("request_logs", "workflow_version")
    op.drop_column("request_logs", "policy_version")
    op.drop_column("request_logs", "policy_id")
    op.drop_column("request_logs", "policy_name")
    op.drop_column("request_logs", "policy_matched")
    op.drop_column("request_logs", "risk_signals")
    op.drop_column("request_logs", "new_owner_id")
    op.drop_column("request_logs", "transaction_amount")