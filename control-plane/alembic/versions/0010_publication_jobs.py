"""Durable publication outbox."""
import sqlalchemy as sa
from alembic import op
revision = '0010'
down_revision = '0009'

def upgrade():
    op.create_table('publication_jobs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('tenant_id', sa.Integer(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('actor_user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('actor_email', sa.String(320), nullable=False),
        sa.Column('request_key', sa.String(100), nullable=False),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('attempts', sa.Integer(), nullable=False),
        sa.Column('available_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('result', sa.Text(), nullable=True),
        sa.Column('last_error', sa.String(200), nullable=True),
        sa.UniqueConstraint('tenant_id', 'request_key'))
    op.create_index('ix_publication_jobs_tenant_id', 'publication_jobs', ['tenant_id'])
    op.create_index('ix_publication_jobs_status', 'publication_jobs', ['status'])

def downgrade():
    op.drop_table('publication_jobs')
