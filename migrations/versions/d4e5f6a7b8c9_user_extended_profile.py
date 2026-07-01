"""user extended profile fields

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-07-01 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = 'd4e5f6a7b8c9'
down_revision = 'c3d4e5f6a7b8'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('users', sa.Column('full_name',  sa.String(120), nullable=True))
    op.add_column('users', sa.Column('phone',      sa.String(30),  nullable=True))
    op.add_column('users', sa.Column('birth_date', sa.Date(),      nullable=True))
    op.add_column('users', sa.Column('gender',     sa.String(20),  nullable=True))
    op.add_column('users', sa.Column('address',    sa.Text(),      nullable=True))
    op.add_column('users', sa.Column('avatar',     sa.Text(),      nullable=True))


def downgrade():
    op.drop_column('users', 'avatar')
    op.drop_column('users', 'address')
    op.drop_column('users', 'gender')
    op.drop_column('users', 'birth_date')
    op.drop_column('users', 'phone')
    op.drop_column('users', 'full_name')
