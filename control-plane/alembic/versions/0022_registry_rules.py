"""Registry ingestion: rules payload on updates, rule->update binding."""
from alembic import op
import sqlalchemy as sa
revision='0022'
down_revision='0021'
branch_labels=None
depends_on=None


def upgrade():
    with op.batch_alter_table('category_source_updates') as batch_op:
        batch_op.add_column(sa.Column('rules_json', sa.Text, nullable=False, server_default='[]'))
    with op.batch_alter_table('category_rules') as batch_op:
        batch_op.add_column(sa.Column('source_update_id', sa.Integer, sa.ForeignKey('category_source_updates.id', name='fk_category_rules_source_update_id'), nullable=True))


def downgrade():
    with op.batch_alter_table('category_rules') as batch_op:
        batch_op.drop_column('source_update_id')
    with op.batch_alter_table('category_source_updates') as batch_op:
        batch_op.drop_column('rules_json')
