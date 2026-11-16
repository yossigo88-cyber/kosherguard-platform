"""Category source registry and update history (Answer 22)."""
from alembic import op
import sqlalchemy as sa
revision='0020'
down_revision='0019'
branch_labels=None
depends_on=None


def upgrade():
    op.create_table(
        'category_sources',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('name', sa.String(200), nullable=False),
        sa.Column('license_name', sa.String(300), nullable=False),
        sa.Column('attribution', sa.Text, nullable=False),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('notes', sa.Text, nullable=False),
        sa.Column('created_by_user_id', sa.Integer, sa.ForeignKey('users.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_category_sources_name', 'category_sources', ['name'], unique=True)
    op.create_table(
        'category_source_updates',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('source_id', sa.Integer, sa.ForeignKey('category_sources.id'), nullable=False),
        sa.Column('version', sa.String(120), nullable=False),
        sa.Column('sha256', sa.String(64), nullable=False),
        sa.Column('category_mapping', sa.Text, nullable=False),
        sa.Column('validation_results', sa.Text, nullable=False),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('imported_by_user_id', sa.Integer, sa.ForeignKey('users.id'), nullable=True),
        sa.Column('imported_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('reviewed_by_user_id', sa.Integer, sa.ForeignKey('users.id'), nullable=True),
        sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('review_notes', sa.Text, nullable=False),
    )
    op.create_index('ix_category_source_updates_source_id', 'category_source_updates', ['source_id'])


def downgrade():
    op.drop_index('ix_category_source_updates_source_id', 'category_source_updates')
    op.drop_table('category_source_updates')
    op.drop_index('ix_category_sources_name', 'category_sources')
    op.drop_table('category_sources')
