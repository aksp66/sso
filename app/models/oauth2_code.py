"""
Modèle OAuth2AuthorizationCode — table `oauth2_authorization_codes`

Conforme au cahier des charges §3.3 et RFC 6749 §4.1.2.
Les codes sont à usage unique et expirent après 120 secondes.
PKCE (RFC 7636) : code_challenge stocké pour vérification côté /token.
"""

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, DateTime, String, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db

if TYPE_CHECKING:
    from .oauth2_client import OAuth2Client
    from .user import User


class OAuth2AuthorizationCode(db.Model):
    """
    Code d'autorisation OAuth2 (RFC 6749 §4.1).

    Cycle de vie :
    1. Généré par /authorize après authentification + consentement
    2. Stocké en BDD avec TTL 120s
    3. Échangé contre des tokens via POST /token
    4. Marqué `used_at` à la consommation (usage unique garanti)

    PKCE (RFC 7636) :
    - code_challenge = BASE64URL(SHA256(code_verifier))
    - code_challenge_method = "S256" uniquement (plain est interdit)
    """

    __tablename__ = "oauth2_authorization_codes"

    # ── Identité ───────────────────────────────────────────────────────────
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
        nullable=False,
    )
    # Code opaque transmis au client (128 bits d'entropie minimum)
    code: Mapped[str] = mapped_column(
        String(128), unique=True, nullable=False, index=True
    )

    # ── Liens ──────────────────────────────────────────────────────────────
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Référence par client_id (VARCHAR) et non par UUID interne
    client_id: Mapped[str] = mapped_column(
        String(64),
        db.ForeignKey("oauth2_clients.client_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ── Paramètres OAuth2 ──────────────────────────────────────────────────
    redirect_uri: Mapped[str] = mapped_column(Text, nullable=False)
    scope: Mapped[str] = mapped_column(Text, nullable=False)
    # Nonce OpenID Connect (protection replay attack sur id_token)
    nonce: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    # ── PKCE (RFC 7636) ────────────────────────────────────────────────────
    code_challenge: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        comment="BASE64URL(SHA256(code_verifier))",
    )
    code_challenge_method: Mapped[Optional[str]] = mapped_column(
        String(16),
        nullable=True,
        comment="Toujours S256 — plain est refusé",
    )

    # ── Cycle de vie ───────────────────────────────────────────────────────
    # TTL : 120 secondes (RFC 6749 §4.1.2)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    # Marqué quand le code est consommé (garantit l'usage unique)
    used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=text("now()"),
        nullable=False,
    )

    # ── Relations ──────────────────────────────────────────────────────────
    user: Mapped["User"] = relationship("User", back_populates="auth_codes")
    client: Mapped["OAuth2Client"] = relationship(
        "OAuth2Client",
        back_populates="auth_codes",
        foreign_keys=[client_id],
    )

    def is_expired(self) -> bool:
        """Vérifie si le code a expiré (TTL 120s)."""
        return datetime.now(timezone.utc) > self.expires_at

    def is_used(self) -> bool:
        """Vérifie si le code a déjà été consommé."""
        return self.used_at is not None

    def is_valid(self) -> bool:
        """Le code est valide s'il n'est ni expiré ni déjà utilisé."""
        return not self.is_expired() and not self.is_used()

    def __repr__(self) -> str:
        return f"<AuthCode {self.code[:8]}... user={self.user_id}>"
