"""Five-role staff model and two-person sensitive-command approvals.

Adds users.staff_role (owner/security_admin/support_admin/read_only per
Answer 29; legacy rows with BOTH is_platform_admin and tenant role
'owner' become staff owner - a bare flag never elevated a guardian
before, so the migration must not elevate one now) and the
sensitive_command_approvals table for Answer 25's two-person approval
of especially destructive operations.
"""
from alembic import op
import sqlalchemy as sa
revision='0017'
down_revision='0016'
branch_labels=None
depends_on=None


def upgrade():
    op.add_column('users', sa.Column('staff_role', sa.String(30), nullable=True))
    op.execute("UPDATE users SET staff_role='owner' WHERE is_platform_admin AND role='owner'")
    op.create_table(
        'sensitive_command_approvals',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('tenant_id', sa.Integer, sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('enrollment_pk', sa.Integer, sa.ForeignKey('mdm_enrollments.id'), nullable=True),
        sa.Column('operation', sa.String(60), nullable=False),
        sa.Column('payload', sa.Text, nullable=False),
        sa.Column('reason', sa.Text, nullable=False),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('requested_by_user_id', sa.Integer, sa.ForeignKey('users.id'), nullable=False),
        sa.Column('decided_by_user_id', sa.Integer, sa.ForeignKey('users.id'), nullable=True),
        sa.Column('decision_detail', sa.Text, nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('decided_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_sensitive_command_approvals_tenant_id',
                    'sensitive_command_approvals', ['tenant_id'])


def downgrade():
    op.drop_index('ix_sensitive_command_approvals_tenant_id',
                  'sensitive_command_approvals')
    op.drop_table('sensitive_command_approvals')
    op.drop_column('users', 'staff_role')
