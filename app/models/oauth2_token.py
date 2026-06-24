"""
Modèle OAuth2Token — table `oauth2_tokens` (Refresh Tokens)

Conforme au cahier des charges §3.4.
Les refresh tokens sont stockés hachés en bcrypt.
Le JTI (JWT ID) permet la révocation via la blacklist Redis.

Rotation automatique : chaque utilisation d'un refresh token
émet un nouveau token et révoque l'ancien (RFC 6749 §10.4).
"""

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from sqlalchemy import DateTime, String, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db

if TYPE_CHECKING:
    from .oauth2_client import OAuth2Client
    from .user import User


class OAuth2Token(db.Model):
    """
    Refresh Token OAuth2 persisté en base de données.

    Le token brut n'est JAMAIS stocké en clair :
    - La valeur réelle est transmise une seule fois au client
    - En BDD, on conserve uniquement le hash bcrypt (token_hash)
    - La révocation utilise le JTI stocké dans la blacklist Redis

    Access tokens : JWT RS256, durée 1h, NON stockés en BDD
    (vérification stateless via signature + blacklist Redis par JTI).
    """

    __tablename__ = "oauth2_tokens"

    # ── Identité ───────────────────────────────────────────────────────────
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
        nullable=False,
    )
    # JWT ID unique — utilisé pour la blacklist Redis
    jti: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
        comment="JWT ID (identifiant unique du token, pour blacklist Redis)",
    )

    # ── Liens ──────────────────────────────────────────────────────────────
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    client_id: Mapped[str] = mapped_column(
        String(64),
        db.ForeignKey("oauth2_clients.client_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ── Sécurité ───────────────────────────────────────────────────────────
    # bcrypt hash du refresh token brut (jamais la valeur en clair)
    token_hash: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment="bcrypt hash du refresh token",
    )
    # SHA256 hex du refresh token — index de recherche O(1) (pas de valeur en clair)
    token_sha256: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
        comment="SHA256 hex du refresh token brut (lookup rapide avant bcrypt verify)",
    )
    scope: Mapped[str] = mapped_column(Text, nullable=False)
    # JTI du dernier access token émis avec ce refresh token
    access_token_jti: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )

    # ── Cycle de vie ───────────────────────────────────────────────────────
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=text("now()"),
        nullable=False,
    )
    # Durée par défaut : 30 jours (configurable via REFRESH_TOKEN_EXPIRE_SECONDS)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    # Renseigné lors de la révocation (POST /revoke ou rotation)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ── Relations ──────────────────────────────────────────────────────────
    user: Mapped["User"] = relationship("User", back_populates="tokens")
    client: Mapped["OAuth2Client"] = relationship(
        "OAuth2Client",
        back_populates="tokens",
        foreign_keys=[client_id],
    )

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at

    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    def is_active(self) -> bool:
        return not self.is_expired() and not self.is_revoked()

    def __repr__(self) -> str:
        return f"<OAuth2Token jti={self.jti[:8]}... user={self.user_id}>"
