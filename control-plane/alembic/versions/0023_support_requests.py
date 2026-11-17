"""Support requests (Answer 34)."""
from alembic import op
import sqlalchemy as sa
revision='0023'
down_revision='0022'
branch_labels=None
depends_on=None


def upgrade():
    op.create_table(
        'support_requests',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('tenant_id', sa.Integer, sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('user_id', sa.Integer, sa.ForeignKey('users.id'), nullable=True),
        sa.Column('kind', sa.String(40), nullable=False),
        sa.Column('subject', sa.String(200), nullable=False),
        sa.Column('body', sa.Text, nullable=False),
        sa.Column('channel', sa.String(20), nullable=False, server_default='in_product'),
        sa.Column('status', sa.String(20), nullable=False, server_default='open'),
        sa.Column('escalated', sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column('resolution_notes', sa.Text, nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_support_requests_tenant_id', 'support_requests', ['tenant_id'])


def downgrade():
    op.drop_index('ix_support_requests_tenant_id', table_name='support_requests')
    op.drop_table('support_requests')
