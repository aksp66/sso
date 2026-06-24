"""
Modèle ClientRequest — table `client_requests`

Demande d'enregistrement d'une application cliente OAuth2, soumise par un
développeur depuis le site public. Revue manuellement par un administrateur
avant création effective du client OAuth2 (voir app/routes/admin.py).
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, String, Text, text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db

if TYPE_CHECKING:
    from .user import User

STATUS_PENDING = "pending"
STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"


class ClientRequest(db.Model):
    """Demande d'accès OAuth2 en attente de revue par un administrateur."""

    __tablename__ = "client_requests"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
        nullable=False,
    )

    # ── Informations sur l'application demandée ─────────────────────────────
    client_name: Mapped[str] = mapped_column(String(128), nullable=False)
    organization: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    redirect_uris: Mapped[list] = mapped_column(ARRAY(Text), nullable=False)
    requested_scopes: Mapped[list] = mapped_column(
        ARRAY(Text),
        default=lambda: ["openid"],
        nullable=False,
    )
    is_confidential: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # ── Contact (destinataire des credentials par e-mail) ──────────────────
    contact_name: Mapped[str] = mapped_column(String(128), nullable=False)
    contact_email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # ── Cycle de vie de la revue ─────────────────────────────────────────────
    status: Mapped[str] = mapped_column(
        String(16), default=STATUS_PENDING, server_default=text("'pending'"),
        nullable=False, index=True,
    )
    submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=text("now()"),
        nullable=False,
    )
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewed_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    rejection_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # client_id du client OAuth2 effectivement créé après approbation
    created_client_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    reviewer: Mapped[Optional["User"]] = relationship("User")

    def is_pending(self) -> bool:
        return self.status == STATUS_PENDING

    def __repr__(self) -> str:
        return f"<ClientRequest {self.client_name} status={self.status}>"
