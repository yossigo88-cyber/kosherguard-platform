"""Require verified MFA on privileged sessions; old sessions are restricted.

Revision ID: 0011
Revises: 0010
"""
from alembic import op
import sqlalchemy as sa
revision = '0011'
down_revision = '0010'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('auth_sessions', sa.Column('mfa_verified', sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade():
    op.drop_column('auth_sessions', 'mfa_verified')
