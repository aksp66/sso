"""
Modèle OAuth2Consent — table `oauth2_consents`

Enregistre les consentements explicites des utilisateurs par client+scopes.
Permet la révocation de l'accès et satisfait GDPR Article 7.
"""

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from sqlalchemy import DateTime, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db

if TYPE_CHECKING:
    from .oauth2_client import OAuth2Client
    from .user import User


class OAuth2Consent(db.Model):
    """Consentement d'un utilisateur pour un client donné."""

    __tablename__ = "oauth2_consents"
    __table_args__ = (
        UniqueConstraint("user_id", "client_id", name="uq_consent_user_client"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
        nullable=False,
    )
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
    scopes: Mapped[list] = mapped_column(
        ARRAY(Text),
        nullable=False,
        comment="Scopes consentis par l'utilisateur",
    )
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=text("now()"),
        nullable=False,
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    user: Mapped["User"] = relationship("User")
    client: Mapped["OAuth2Client"] = relationship("OAuth2Client")

    def is_active(self) -> bool:
        return self.revoked_at is None

    def __repr__(self) -> str:
        return f"<OAuth2Consent user={self.user_id} client={self.client_id}>"
