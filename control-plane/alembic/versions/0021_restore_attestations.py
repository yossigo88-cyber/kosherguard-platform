"""Restore attestations (Answer 26)."""
from alembic import op
import sqlalchemy as sa
revision='0021'
down_revision='0020'
branch_labels=None
depends_on=None


def upgrade():
    op.create_table(
        'restore_attestations',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('tenant_id', sa.Integer, sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('device_id', sa.Integer, sa.ForeignKey('devices.id'), nullable=False),
        sa.Column('attested_by_user_id', sa.Integer, sa.ForeignKey('users.id'), nullable=False),
        sa.Column('attested_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_restore_attestations_tenant_id', 'restore_attestations', ['tenant_id'])
    op.create_index('ix_restore_attestations_device_id', 'restore_attestations', ['device_id'])


def downgrade():
    op.drop_index('ix_restore_attestations_device_id', 'restore_attestations')
    op.drop_index('ix_restore_attestations_tenant_id', 'restore_attestations')
    op.drop_table('restore_attestations')
