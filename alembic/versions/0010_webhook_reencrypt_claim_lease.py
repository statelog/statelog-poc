"""add webhook re-encryption claim lease

Revision ID: 0010_webhook_reencrypt_claim_lease
Revises: 0009_webhook_secret_key_verification
Create Date: 2026-09-14
"""

from alembic import op
import sqlalchemy as sa


revision = "0010_webhook_reencrypt_claim_lease"
down_revision = "0009_webhook_secret_key_verification"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "webhook_subscriptions",
        sa.Column(
            "reencrypt_claimed_by",
            sa.String(length=64),
            nullable=True,
        ),
    )
    op.add_column(
        "webhook_subscriptions",
        sa.Column(
            "reencrypt_claim_expires_at",
            sa.DateTime(),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_webhook_subscriptions_reencrypt_claim_expires_at",
        "webhook_subscriptions",
        ["reencrypt_claim_expires_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_webhook_subscriptions_reencrypt_claim_expires_at",
        table_name="webhook_subscriptions",
    )
    op.drop_column(
        "webhook_subscriptions",
        "reencrypt_claim_expires_at",
    )
    op.drop_column(
        "webhook_subscriptions",
        "reencrypt_claimed_by",
    )