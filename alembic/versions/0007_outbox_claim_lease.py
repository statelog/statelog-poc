"""add outbox claim lease

Revision ID: 0007_outbox_claim_lease
Revises: 0006_policy_and_workflow_tables
Create Date: 2026-09-12
"""

from alembic import op
import sqlalchemy as sa


revision = "0007_outbox_claim_lease"
down_revision = "0006_policy_and_workflow_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "outbox_events",
        sa.Column("claimed_by", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "outbox_events",
        sa.Column("claim_expires_at", sa.DateTime(), nullable=True),
    )
    op.create_index(
        "ix_outbox_events_claim_expires_at",
        "outbox_events",
        ["claim_expires_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_outbox_events_claim_expires_at",
        table_name="outbox_events",
    )
    op.drop_column("outbox_events", "claim_expires_at")
    op.drop_column("outbox_events", "claimed_by")