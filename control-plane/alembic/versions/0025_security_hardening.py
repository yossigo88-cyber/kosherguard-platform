"""Security hardening: restore-attestation enrollment binding,
credential pending-cleanup marker, one-current-enrollment and
one-active-invite partial unique indexes, wider approval status."""
from alembic import op
import sqlalchemy as sa

revision = '0025'
down_revision = '0024'
branch_labels = None
depends_on = None


def upgrade():
    # Wider approval status: 'approved_manual_action_required' (31).
    # Batch mode keeps every change working on SQLite as well as
    # PostgreSQL (copy-and-move instead of unsupported ALTERs).
    with op.batch_alter_table('sensitive_command_approvals') as batch:
        batch.alter_column('status', type_=sa.String(40),
                           existing_type=sa.String(20),
                           existing_nullable=False)
    with op.batch_alter_table('restore_attestations') as batch:
        batch.add_column(sa.Column(
            'enrollment_pk', sa.Integer,
            sa.ForeignKey('mdm_enrollments.id',
                          name='fk_restore_attestations_enrollment_pk'),
            nullable=True))
        batch.add_column(sa.Column(
            'attestation_kind', sa.String(30), nullable=False,
            server_default='manual_guardian'))
    with op.batch_alter_table('credential_artifacts') as batch:
        batch.add_column(sa.Column(
            'pending_cleanup_path', sa.String(500), nullable=True))
    op.create_index(
        'uq_mdm_enrollments_current_device', 'mdm_enrollments',
        ['device_id'], unique=True,
        postgresql_where=sa.text("state IN ('pending','enrolled')"),
        sqlite_where=sa.text("state IN ('pending','enrolled')"))
    op.create_index(
        'uq_invite_tokens_active_email', 'invite_tokens',
        ['tenant_id', 'email'], unique=True,
        postgresql_where=sa.text('used_at IS NULL'),
        sqlite_where=sa.text('used_at IS NULL'))


def downgrade():
    op.drop_index('uq_invite_tokens_active_email',
                  table_name='invite_tokens')
    op.drop_index('uq_mdm_enrollments_current_device',
                  table_name='mdm_enrollments')
    with op.batch_alter_table('credential_artifacts') as batch:
        batch.drop_column('pending_cleanup_path')
    with op.batch_alter_table('restore_attestations') as batch:
        batch.drop_column('attestation_kind')
        batch.drop_column('enrollment_pk')
    with op.batch_alter_table('sensitive_command_approvals') as batch:
        batch.alter_column('status', type_=sa.String(20),
                           existing_type=sa.String(40),
                           existing_nullable=False)
