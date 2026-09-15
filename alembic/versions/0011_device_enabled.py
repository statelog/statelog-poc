"""add device enabled state

Revision ID: 0011_device_enabled
Revises: 0010_webhook_reencrypt_claim_lease
Create Date: 2026-09-15
"""

from alembic import op
import sqlalchemy as sa


revision = "0011_device_enabled"
down_revision = "0010_webhook_reencrypt_claim_lease"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "devices",
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
    )


def downgrade() -> None:
    op.drop_column(
        "devices",
        "enabled",
    )