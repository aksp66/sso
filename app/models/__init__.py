"""
Package models — importe tous les modèles pour Flask-Migrate.
L'import dans app/__init__.py garantit que Alembic les détecte.
"""

from .audit_log import AuditLog
from .oauth2_client import OAuth2Client
from .oauth2_code import OAuth2AuthorizationCode
from .oauth2_consent import OAuth2Consent
from .oauth2_token import OAuth2Token
from .rs256_key import RS256Key
from .user import User

__all__ = [
    "User",
    "OAuth2Client",
    "OAuth2AuthorizationCode",
    "OAuth2Consent",
    "OAuth2Token",
    "RS256Key",
    "AuditLog",
]
