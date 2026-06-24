"""
Modèle OAuth2Client — table `oauth2_clients`

Conforme au cahier des charges §3.2.
Représente une application cliente enregistrée auprès du SSO
(ex: webapp_projects, chat mobile).
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, String, Text, text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db

if TYPE_CHECKING:
    # Import models for type checking / linters to recognize forward refs
    from .oauth2_token import OAuth2Token  # pragma: no cover
    from .oauth2_code import OAuth2AuthorizationCode  # pragma: no cover


class OAuth2Client(db.Model):
    """
    Application cliente OAuth2 enregistrée.

    - client_id : identifiant public (transmis dans les requêtes OAuth2)
    - client_secret_hash : bcrypt du secret (jamais le secret en clair)
    - redirect_uris : liste blanche stricte des URIs de redirection (RFC 6819)
    - allowed_scopes : scopes que ce client peut demander
    - is_confidential : True = serveur web, False = SPA/mobile (PKCE obligatoire)
    """

    __tablename__ = "oauth2_clients"

    # ── Identité ───────────────────────────────────────────────────────────
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
        nullable=False,
    )
    client_id: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    client_secret_hash: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment="bcrypt hash du secret client",
    )
    client_name: Mapped[str] = mapped_column(String(128), nullable=False)

    # ── Configuration OAuth2 ───────────────────────────────────────────────
    # Liste blanche stricte : validation exact-match (RFC 6819 §5.2.3.5)
    redirect_uris: Mapped[list] = mapped_column(
        ARRAY(Text),
        nullable=False,
        comment="URIs de redirection autorisées (exact match obligatoire)",
    )
    # Scopes autorisés pour ce client
    allowed_scopes: Mapped[list] = mapped_column(
        ARRAY(Text),
        default=lambda: ["openid", "profile", "email"],
        server_default=text("ARRAY['openid','profile','email']::text[]"),
        nullable=False,
    )
    # Grant types autorisés
    grant_types: Mapped[list] = mapped_column(
        ARRAY(Text),
        default=lambda: ["authorization_code", "refresh_token"],
        nullable=False,
    )

    # ── Type de client ─────────────────────────────────────────────────────
    # Confidentiel (serveur) = peut garder un secret
    # Public (SPA/mobile) = PKCE obligatoire, pas de secret
    is_confidential: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # ── Métadonnées ────────────────────────────────────────────────────────
    logo_uri: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="URL du logo (page de consentement)"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=text("now()"),
        nullable=False,
    )

    # ── Relations ──────────────────────────────────────────────────────────
    tokens: Mapped[list["OAuth2Token"]] = relationship(
        "OAuth2Token",
        back_populates="client",
        cascade="all, delete-orphan",
        lazy="select",
    )
    auth_codes: Mapped[list["OAuth2AuthorizationCode"]] = relationship(
        "OAuth2AuthorizationCode",
        back_populates="client",
        cascade="all, delete-orphan",
        lazy="select",
        foreign_keys="OAuth2AuthorizationCode.client_id",
    )

    def has_redirect_uri(self, uri: str) -> bool:
        """Valide qu'une redirect_uri est exactement dans la liste blanche."""
        return uri in (self.redirect_uris or [])

    def has_scope(self, scope: str) -> bool:
        """Vérifie que tous les scopes demandés sont autorisés pour ce client."""
        requested = set(scope.split())
        allowed = set(self.allowed_scopes or [])
        return requested.issubset(allowed)

    def __repr__(self) -> str:
        return f"<OAuth2Client {self.client_id} confidentiel={self.is_confidential}>"
