"""Sprint 8 - security hardening

Revision ID: a1b2c3d4e5f6
Revises: 7fc5b6e27875
Create Date: 2026-06-16 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'a1b2c3d4e5f6'
down_revision = '7fc5b6e27875'
branch_labels = None
depends_on = None


def _column_exists(table, column):
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    return column in {c['name'] for c in inspector.get_columns(table)}


def _index_exists(table, index_name):
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    return any(i['name'] == index_name for i in inspector.get_indexes(table))


def upgrade():
    # H1 — state stocké dans le code d'autorisation (RFC 6749 §10.12)
    if not _column_exists('oauth2_authorization_codes', 'state'):
        with op.batch_alter_table('oauth2_authorization_codes', schema=None) as batch_op:
            batch_op.add_column(sa.Column('state', sa.String(length=512), nullable=True))

    # H4 — index SHA256 sur les refresh tokens pour lookup O(1)
    if not _column_exists('oauth2_tokens', 'token_sha256'):
        with op.batch_alter_table('oauth2_tokens', schema=None) as batch_op:
            batch_op.add_column(
                sa.Column(
                    'token_sha256',
                    sa.String(length=64),
                    nullable=True,
                    comment='SHA256 hex du refresh token brut (lookup rapide avant bcrypt verify)',
                )
            )
    if not _index_exists('oauth2_tokens', 'ix_oauth2_tokens_token_sha256'):
        with op.batch_alter_table('oauth2_tokens', schema=None) as batch_op:
            batch_op.create_index('ix_oauth2_tokens_token_sha256', ['token_sha256'], unique=False)

    # H8 — table de consentement OAuth2 (GDPR Article 7)
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    if not inspector.has_table('oauth2_consents'):
        op.create_table(
            'oauth2_consents',
            sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
            sa.Column('user_id', sa.UUID(), nullable=False),
            sa.Column('client_id', sa.String(length=64), nullable=False),
            sa.Column('scopes', postgresql.ARRAY(sa.Text()), nullable=False,
                      comment='Scopes consentis par l\'utilisateur'),
            sa.Column('granted_at', sa.DateTime(timezone=True),
                      server_default=sa.text('now()'), nullable=False),
            sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(['client_id'], ['oauth2_clients.client_id'], ondelete='CASCADE'),
            sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('user_id', 'client_id', name='uq_consent_user_client'),
        )
        with op.batch_alter_table('oauth2_consents', schema=None) as batch_op:
            batch_op.create_index('ix_oauth2_consents_client_id', ['client_id'], unique=False)
            batch_op.create_index('ix_oauth2_consents_user_id', ['user_id'], unique=False)


def downgrade():
    with op.batch_alter_table('oauth2_consents', schema=None) as batch_op:
        batch_op.drop_index('ix_oauth2_consents_user_id')
        batch_op.drop_index('ix_oauth2_consents_client_id')
    op.drop_table('oauth2_consents')

    with op.batch_alter_table('oauth2_tokens', schema=None) as batch_op:
        batch_op.drop_index('ix_oauth2_tokens_token_sha256')
        batch_op.drop_column('token_sha256')

    with op.batch_alter_table('oauth2_authorization_codes', schema=None) as batch_op:
        batch_op.drop_column('state')
