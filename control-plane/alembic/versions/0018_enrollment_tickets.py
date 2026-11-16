"""Enrollment tickets and device-identity provenance (Answer 28).

Short-lived single-use tickets binding tenant+device, and the
certificate fingerprint/status recorded when a ticket is redeemed.
"""
from alembic import op
import sqlalchemy as sa
revision='0018'
down_revision='0017'
branch_labels=None
depends_on=None


def upgrade():
    op.create_table(
        'enrollment_tickets',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('tenant_id', sa.Integer, sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('device_id', sa.Integer, sa.ForeignKey('devices.id'), nullable=False),
        sa.Column('token_hash', sa.String(64), nullable=False),
        sa.Column('created_by_user_id', sa.Integer, sa.ForeignKey('users.id'), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_enrollment_tickets_tenant_id', 'enrollment_tickets', ['tenant_id'])
    op.create_index('ix_enrollment_tickets_device_id', 'enrollment_tickets', ['device_id'])
    op.create_index('ix_enrollment_tickets_token_hash', 'enrollment_tickets', ['token_hash'], unique=True)
    with op.batch_alter_table('mdm_enrollments') as batch_op:
        batch_op.add_column(sa.Column('enrollment_ticket_id', sa.Integer, sa.ForeignKey('enrollment_tickets.id', name='fk_mdm_enrollments_enrollment_ticket_id'), nullable=True))
        batch_op.add_column(sa.Column('identity_cert_sha256', sa.String(64), nullable=True))
        batch_op.add_column(sa.Column('identity_cert_status', sa.String(30), nullable=True))


def downgrade():
    with op.batch_alter_table('mdm_enrollments') as batch_op:
        batch_op.drop_column('identity_cert_status')
        batch_op.drop_column('identity_cert_sha256')
        batch_op.drop_column('enrollment_ticket_id')
    op.drop_index('ix_enrollment_tickets_token_hash', 'enrollment_tickets')
    op.drop_index('ix_enrollment_tickets_device_id', 'enrollment_tickets')
    op.drop_index('ix_enrollment_tickets_tenant_id', 'enrollment_tickets')
    op.drop_table('enrollment_tickets')
