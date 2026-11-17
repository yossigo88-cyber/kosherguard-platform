"""Structured exception requests (spec Part 2A customer portal)."""
from alembic import op
import sqlalchemy as sa
revision='0024'
down_revision='0023'
branch_labels=None
depends_on=None


def upgrade():
    op.create_table(
        'exception_requests',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('tenant_id', sa.Integer, sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('requester_user_id', sa.Integer, sa.ForeignKey('users.id'), nullable=False),
        sa.Column('kind', sa.String(30), nullable=False),
        sa.Column('scope_type', sa.String(10), nullable=False),
        sa.Column('device_id', sa.Integer, sa.ForeignKey('devices.id'), nullable=True),
        sa.Column('group_id', sa.Integer, sa.ForeignKey('device_groups.id'), nullable=True),
        sa.Column('domains', sa.Text, nullable=False, server_default='[]'),
        sa.Column('reason', sa.Text, nullable=False),
        sa.Column('duration_minutes', sa.Integer, nullable=False),
        sa.Column('status', sa.String(20), nullable=False, server_default='pending'),
        sa.Column('decided_by_user_id', sa.Integer, sa.ForeignKey('users.id'), nullable=True),
        sa.Column('decided_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('exception_id', sa.Integer, sa.ForeignKey('policy_exceptions.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_exception_requests_tenant_id', 'exception_requests', ['tenant_id'])


def downgrade():
    op.drop_index('ix_exception_requests_tenant_id', table_name='exception_requests')
    op.drop_table('exception_requests')
