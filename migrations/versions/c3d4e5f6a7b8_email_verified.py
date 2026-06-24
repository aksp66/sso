"""Inscription self-service : ajout de email_verified sur users

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-06-24 18:40:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = 'c3d4e5f6a7b8'
down_revision = 'b2c3d4e5f6a7'
branch_labels = None
depends_on = None


def _column_exists(table, column):
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    return column in {c['name'] for c in inspector.get_columns(table)}


def upgrade():
    if not _column_exists('users', 'email_verified'):
        with op.batch_alter_table('users', schema=None) as batch_op:
            batch_op.add_column(
                sa.Column(
                    'email_verified',
                    sa.Boolean(),
                    server_default=sa.text('true'),
                    nullable=False,
                )
            )


def downgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('email_verified')
