"""Demandes d'enregistrement de client OAuth2 (self-service)

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-06-24 17:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'b2c3d4e5f6a7'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    if inspector.has_table('client_requests'):
        return

    op.create_table(
        'client_requests',
        sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('client_name', sa.String(length=128), nullable=False),
        sa.Column('organization', sa.String(length=128), nullable=True),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('redirect_uris', postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column('requested_scopes', postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column('is_confidential', sa.Boolean(), nullable=False),
        sa.Column('contact_name', sa.String(length=128), nullable=False),
        sa.Column('contact_email', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=16), server_default=sa.text("'pending'"), nullable=False),
        sa.Column('submitted_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('reviewed_by', sa.UUID(), nullable=True),
        sa.Column('rejection_reason', sa.Text(), nullable=True),
        sa.Column('created_client_id', sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(['reviewed_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('client_requests', schema=None) as batch_op:
        batch_op.create_index('ix_client_requests_contact_email', ['contact_email'], unique=False)
        batch_op.create_index('ix_client_requests_status', ['status'], unique=False)


def downgrade():
    with op.batch_alter_table('client_requests', schema=None) as batch_op:
        batch_op.drop_index('ix_client_requests_status')
        batch_op.drop_index('ix_client_requests_contact_email')
    op.drop_table('client_requests')
