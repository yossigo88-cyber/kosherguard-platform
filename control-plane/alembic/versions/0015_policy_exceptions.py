"""Time-limited scoped policy exceptions."""
from alembic import op
import sqlalchemy as sa
revision='0015'
down_revision='0014'
branch_labels=None
depends_on=None


def upgrade():
    op.create_table(
        'policy_exceptions',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('tenant_id', sa.Integer(), sa.ForeignKey('tenants.id'),
                  nullable=False, index=True),
        sa.Column('kind', sa.String(30), nullable=False),
        sa.Column('scope_type', sa.String(10), nullable=False),
        sa.Column('device_id', sa.Integer(), sa.ForeignKey('devices.id'),
                  nullable=True),
        sa.Column('group_id', sa.Integer(), sa.ForeignKey('device_groups.id'),
                  nullable=True),
        sa.Column('domains', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('approver_user_id', sa.Integer(),
                  sa.ForeignKey('users.id'), nullable=False),
        sa.Column('starts_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_by', sa.Integer(), sa.ForeignKey('users.id'),
                  nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False))


def downgrade():
    op.drop_table('policy_exceptions')
