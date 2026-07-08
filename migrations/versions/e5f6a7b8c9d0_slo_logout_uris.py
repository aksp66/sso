"""SSO SLO — backchannel_logout_uri / frontchannel_logout_uri sur oauth2_clients

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-07-08 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = 'e5f6a7b8c9d0'
down_revision = 'd4e5f6a7b8c9'
branch_labels = None
depends_on = None


def _column_exists(table: str, column: str) -> bool:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    return column in {c['name'] for c in inspector.get_columns(table)}


def upgrade():
    with op.batch_alter_table('oauth2_clients', schema=None) as batch_op:
        if not _column_exists('oauth2_clients', 'backchannel_logout_uri'):
            batch_op.add_column(
                sa.Column(
                    'backchannel_logout_uri',
                    sa.Text(),
                    nullable=True,
                    comment='URI de déconnexion back-channel (OIDC SLO — RFC 9470)',
                )
            )
        if not _column_exists('oauth2_clients', 'frontchannel_logout_uri'):
            batch_op.add_column(
                sa.Column(
                    'frontchannel_logout_uri',
                    sa.Text(),
                    nullable=True,
                    comment='URI de déconnexion front-channel (OIDC SLO)',
                )
            )


def downgrade():
    with op.batch_alter_table('oauth2_clients', schema=None) as batch_op:
        batch_op.drop_column('frontchannel_logout_uri')
        batch_op.drop_column('backchannel_logout_uri')
