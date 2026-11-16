"""Tenant groups, single-group membership, optional tighten-only policy."""
from alembic import op
import sqlalchemy as sa
revision='0013'
down_revision='0012'
branch_labels=None
depends_on=None


def upgrade():
    op.create_table('device_groups',sa.Column('id',sa.Integer(),primary_key=True),
        sa.Column('tenant_id',sa.Integer(),sa.ForeignKey('tenants.id'),nullable=False),
        sa.Column('name',sa.String(120),nullable=False),
        sa.Column('policy_id',sa.Integer(),sa.ForeignKey('policies.id'),nullable=True),
        sa.Column('created_at',sa.DateTime(timezone=True),nullable=False),
        sa.UniqueConstraint('tenant_id','name'))
    op.create_index('ix_device_groups_tenant_id','device_groups',['tenant_id'])
    op.create_table('group_memberships',sa.Column('id',sa.Integer(),primary_key=True),
        sa.Column('tenant_id',sa.Integer(),sa.ForeignKey('tenants.id'),nullable=False),
        sa.Column('group_id',sa.Integer(),sa.ForeignKey('device_groups.id'),nullable=False),
        sa.Column('device_id',sa.Integer(),sa.ForeignKey('devices.id'),nullable=False),
        sa.UniqueConstraint('device_id'))
    op.create_index('ix_group_memberships_tenant_id','group_memberships',['tenant_id'])


def downgrade():
    op.drop_table('group_memberships');op.drop_table('device_groups')
