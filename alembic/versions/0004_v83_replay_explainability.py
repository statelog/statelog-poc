"""v8.3 persist workflow explainability in request logs

Revision ID: 0004_v83
Revises: 0003_v82
Create Date: 2026-08-31
"""

from alembic import op
import sqlalchemy as sa


revision = "0004_v83"
down_revision = "0003_v82"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "request_logs",
        sa.Column("decision_source", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "request_logs",
        sa.Column("decision_path", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("request_logs", "decision_path")
    op.drop_column("request_logs", "decision_source")