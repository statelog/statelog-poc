"""v8.2 key rotation and robust webhooks

Revision ID: 0003_v82_key_rotation_and_webhooks
Revises: 0002_v81_security_hardening
Create Date: 2026-04-16
"""

from alembic import op
import sqlalchemy as sa


revision = "0003_v82"
down_revision = '0002_v81_security_hardening'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('webhook_subscriptions', sa.Column('signing_secret_encrypted', sa.Text(), nullable=True))
    op.add_column('webhook_subscriptions', sa.Column('signing_secret_key_version', sa.String(length=32), nullable=False, server_default='v1'))
    op.add_column('outbox_events', sa.Column('dead_lettered', sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_table(
        'webhook_delivery_attempts',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('event_id', sa.Integer(), nullable=False),
        sa.Column('subscription_id', sa.Integer(), nullable=False),
        sa.Column('attempt_number', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('successful', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('response_status_code', sa.Integer(), nullable=True),
        sa.Column('error_message', sa.String(length=500), nullable=True),
        sa.Column('signature_version', sa.String(length=16), nullable=False, server_default='v1'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['event_id'], ['outbox_events.id']),
        sa.ForeignKeyConstraint(['subscription_id'], ['webhook_subscriptions.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_webhook_delivery_attempts_event_id'), 'webhook_delivery_attempts', ['event_id'], unique=False)
    op.create_index(op.f('ix_webhook_delivery_attempts_subscription_id'), 'webhook_delivery_attempts', ['subscription_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_webhook_delivery_attempts_subscription_id'), table_name='webhook_delivery_attempts')
    op.drop_index(op.f('ix_webhook_delivery_attempts_event_id'), table_name='webhook_delivery_attempts')
    op.drop_table('webhook_delivery_attempts')
    op.drop_column('outbox_events', 'dead_lettered')
    op.drop_column('webhook_subscriptions', 'signing_secret_key_version')
    op.drop_column('webhook_subscriptions', 'signing_secret_encrypted')
