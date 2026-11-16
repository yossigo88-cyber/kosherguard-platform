"""Short bounded blocked-domain retention. Delete historical allowed records.

Revision ID: 0012
Revises: 0011
"""
from alembic import op
import sqlalchemy as sa
revision = '0012'
down_revision = '0011'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('tenants', sa.Column('blocked_log_retention_days', sa.Integer(), nullable=False, server_default='7'))
    op.execute("DELETE FROM filter_decisions WHERE action != 'block' OR received_at <= CURRENT_TIMESTAMP - INTERVAL '7 days'" if op.get_bind().dialect.name == 'postgresql' else "DELETE FROM filter_decisions WHERE action != 'block' OR received_at <= datetime('now', '-7 days')")
    op.execute("DELETE FROM filter_decisions WHERE domain LIKE '%/%' OR domain LIKE '%?%' OR domain LIKE '%#%' OR domain LIKE '%@%' OR domain LIKE '%:%'")
    # Free-form legacy reasons may contain paths, so do not preserve them.
    op.execute("UPDATE filter_decisions SET rule='blocked', reason='policy blocked domain'")


def downgrade():
    op.drop_column('tenants', 'blocked_log_retention_days')
