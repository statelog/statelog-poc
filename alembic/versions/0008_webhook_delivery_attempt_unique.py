"""add webhook delivery attempt uniqueness

Revision ID: 0008_webhook_delivery_attempt_unique
Revises: 0007_outbox_claim_lease
Create Date: 2026-09-12
"""

from alembic import op


revision = "0008_webhook_delivery_attempt_unique"
down_revision = "0007_outbox_claim_lease"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "uq_webhook_delivery_attempt_event_subscription_attempt",
        "webhook_delivery_attempts",
        ["event_id", "subscription_id", "attempt_number"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(
        "uq_webhook_delivery_attempt_event_subscription_attempt",
        table_name="webhook_delivery_attempts",
    )