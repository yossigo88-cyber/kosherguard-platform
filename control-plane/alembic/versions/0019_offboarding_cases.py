"""Offboarding cases (Answer 24).

Documented, verified offboarding process records: kind, ownership
verification, attested external steps, data-retention date and
completion state.
"""
from alembic import op
import sqlalchemy as sa
revision='0019'
down_revision='0018'
branch_labels=None
depends_on=None


def upgrade():
    op.create_table(
        'offboarding_cases',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('tenant_id', sa.Integer, sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('device_id', sa.Integer, sa.ForeignKey('devices.id'), nullable=True),
        sa.Column('kind', sa.String(30), nullable=False),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('created_by_user_id', sa.Integer, sa.ForeignKey('users.id'), nullable=False),
        sa.Column('verified_by_user_id', sa.Integer, sa.ForeignKey('users.id'), nullable=True),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('activation_lock_attested_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('abm_release_attested_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('data_retention_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('notes', sa.Text, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_offboarding_cases_tenant_id', 'offboarding_cases', ['tenant_id'])
    op.create_index('ix_offboarding_cases_device_id', 'offboarding_cases', ['device_id'])


def downgrade():
    op.drop_index('ix_offboarding_cases_device_id', 'offboarding_cases')
    op.drop_index('ix_offboarding_cases_tenant_id', 'offboarding_cases')
    op.drop_table('offboarding_cases')
