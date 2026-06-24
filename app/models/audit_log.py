"""
Modèle AuditLog — table `audit_logs`

Conforme au cahier des charges §3.6 et §5.7.
Journal d'audit immuable de tous les événements de sécurité.

Tous les événements sont loggés : succès ET échecs.
Jamais de mots de passe ni de secrets dans les `details`.
"""

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from sqlalchemy import DateTime, Index, String, Text, text
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db

if TYPE_CHECKING:
    from .user import User

# Constantes pour les types d'événements (évite les fautes de frappe)
EVENT_LOGIN_SUCCESS = "login_success"
EVENT_LOGIN_FAILURE = "login_failure"
EVENT_LOGOUT = "logout"
EVENT_2FA_ENABLED = "2fa_enabled"
EVENT_2FA_DISABLED = "2fa_disabled"
EVENT_2FA_FAILURE = "2fa_failure"
EVENT_BACKUP_CODE_USED = "backup_code_used"
EVENT_TOKEN_ISSUED = "token_issued"
EVENT_TOKEN_REVOKED = "token_revoked"
EVENT_TOKEN_REFRESH = "token_refresh"
EVENT_ACCOUNT_LOCKED = "account_locked"
EVENT_ACCOUNT_UNLOCKED = "account_unlocked"
EVENT_PASSWORD_CHANGED = "password_changed"
EVENT_PASSWORD_RESET_REQUEST = "password_reset_request"
EVENT_KEY_ROTATED = "key_rotated"
EVENT_CLIENT_REGISTERED = "client_registered"
EVENT_CLIENT_UPDATED = "client_updated"
EVENT_CONSENT_GRANTED = "consent_granted"
EVENT_ADMIN_USER_CREATED = "admin_user_created"
EVENT_ADMIN_USER_UPDATED = "admin_user_updated"
EVENT_ADMIN_USER_DELETED = "admin_user_deleted"


class AuditLog(db.Model):
    """
    Entrée du journal d'audit.

    Immuable par design : pas de méthode de mise à jour.
    Toujours créé via AuditLog.log() pour garantir la cohérence.
    """

    __tablename__ = "audit_logs"

    # ── Identité ───────────────────────────────────────────────────────────
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
        nullable=False,
    )

    # ── Type d'événement ───────────────────────────────────────────────────
    event_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        comment="Type d'événement (login_success, token_revoked, ...)",
    )

    # ── Acteurs ────────────────────────────────────────────────────────────
    # Nullable : les tentatives de connexion avec email inconnu n'ont pas de user_id
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    # Client OAuth2 concerné (si applicable)
    client_id: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True, index=True
    )

    # ── Contexte réseau ────────────────────────────────────────────────────
    ip_address: Mapped[str] = mapped_column(
        INET,
        nullable=False,
        comment="Adresse IP de l'action",
    )
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # ── Métadonnées ────────────────────────────────────────────────────────
    # JSONB pour les données complémentaires (scope demandé, kid, etc.)
    # JAMAIS de mots de passe, secrets ou données sensibles ici
    details: Mapped[Optional[dict]] = mapped_column(
        JSONB,
        nullable=True,
        comment="Métadonnées JSONB (sans données sensibles)",
    )

    # ── Horodatage ─────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=text("now()"),
        nullable=False,
        index=True,
    )

    # ── Relation ───────────────────────────────────────────────────────────
    user: Mapped[Optional["User"]] = relationship(
        "User", back_populates="audit_logs"
    )

    # ── Index composites pour les requêtes fréquentes ──────────────────────
    __table_args__ = (
        Index("ix_audit_logs_user_event", "user_id", "event_type"),
        Index("ix_audit_logs_created_event", "created_at", "event_type"),
    )

    @classmethod
    def log(
        cls,
        event_type: str,
        ip_address: str,
        user_id: Optional[uuid.UUID] = None,
        client_id: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> "AuditLog":
        """
        Crée et persiste une entrée d'audit.

        Usage :
            AuditLog.log(
                event_type=EVENT_LOGIN_SUCCESS,
                ip_address=request.remote_addr,
                user_id=user.id,
                user_agent=request.user_agent.string,
                details={"2fa_method": "totp"},
            )
            db.session.commit()
        """
        entry = cls(
            event_type=event_type,
            ip_address=ip_address,
            user_id=user_id,
            client_id=client_id,
            user_agent=user_agent,
            details=details or {},
        )
        db.session.add(entry)
        return entry

    def __repr__(self) -> str:
        return (
            f"<AuditLog {self.event_type} user={self.user_id} "
            f"ip={self.ip_address} at={self.created_at}>"
        )
