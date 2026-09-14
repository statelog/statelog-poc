"""add webhook secret key verification marker

Revision ID: 0009_webhook_secret_key_verification
Revises: 0008_webhook_delivery_attempt_unique
Create Date: 2026-09-13
"""

from alembic import op
import sqlalchemy as sa


revision = "0009_webhook_secret_key_verification"
down_revision = "0008_webhook_delivery_attempt_unique"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "webhook_subscriptions",
        sa.Column(
            "signing_secret_key_version_verified",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column(
        "webhook_subscriptions",
        "signing_secret_key_version_verified",
    )
