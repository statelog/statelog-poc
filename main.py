"""v8.1 security hardening

Revision ID: 0002_v81_security_hardening
Revises: 0001_v8_baseline
Create Date: 2026-04-16
"""

from alembic import op
import sqlalchemy as sa

revision = "0002_v81_security_hardening"
down_revision = "0001_v8_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass
def downgrade() -> None:
    op.add_column("request_logs", sa.Column("ip_address", sa.String(length=100), nullable=True))
    with op.batch_alter_table("request_logs") as batch_op:
        batch_op.execute("UPDATE request_logs SET ip_address = ip_hash")
        batch_op.drop_index(op.f("ix_request_logs_ip_hash"))
        batch_op.drop_column("ip_hash")
    with op.batch_alter_table("request_logs") as batch_op:
        batch_op.alter_column("ip_address", existing_type=sa.String(length=100), nullable=False)
