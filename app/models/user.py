"""
Modèle User — table `users`

Conforme au cahier des charges §3.1.
Colonnes clés : UUID PK, bcrypt password, TOTP chiffré AES, lockout.
"""

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, DateTime, SmallInteger, String, Text, text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db

if TYPE_CHECKING:
    from .audit_log import AuditLog
    from .oauth2_code import OAuth2AuthorizationCode
    from .oauth2_token import OAuth2Token


class User(db.Model):
    """
    Compte utilisateur du SSO.

    - is_admin : accès au panneau d'administration (2FA obligatoire)
    - totp_secret : clé secrète TOTP chiffrée en AES-256-GCM (jamais en clair)
    - backup_codes : 10 codes de secours hachés individuellement en bcrypt
    - locked_until : verrouillage temporaire après 10 échecs consécutifs
    """

    __tablename__ = "users"

    # ── Identité ───────────────────────────────────────────────────────────
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
        nullable=False,
    )
    username: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True
    )
    password_hash: Mapped[str] = mapped_column(String(128), nullable=False)

    # ── Rôles & statut ─────────────────────────────────────────────────────
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # ── 2FA TOTP (RFC 6238) ────────────────────────────────────────────────
    # La clé secrète est chiffrée en AES-256-GCM avant stockage
    totp_secret: Mapped[Optional[str]] = mapped_column(
        String(512), nullable=True, comment="Clé TOTP chiffrée AES-256-GCM"
    )
    totp_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    # 10 codes de secours hachés individuellement en bcrypt
    backup_codes: Mapped[Optional[list]] = mapped_column(
        ARRAY(Text), nullable=True, comment="Codes de secours hachés bcrypt"
    )

    # ── Horodatages ────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=text("now()"),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        server_default=text("now()"),
        nullable=False,
    )
    last_login_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ── Protection contre brute-force ──────────────────────────────────────
    failed_login_count: Mapped[int] = mapped_column(
        SmallInteger, default=0, nullable=False
    )
    locked_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Verrouillage temporaire (10 échecs consécutifs)",
    )

    # ── Relations ──────────────────────────────────────────────────────────
    tokens: Mapped[list["OAuth2Token"]] = relationship(
        "OAuth2Token",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )
    auth_codes: Mapped[list["OAuth2AuthorizationCode"]] = relationship(
        "OAuth2AuthorizationCode",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship(
        "AuditLog",
        back_populates="user",
        lazy="dynamic",
    )

    def is_locked(self) -> bool:
        """Vérifie si le compte est actuellement verrouillé."""
        if self.locked_until is None:
            return False
        return datetime.now(timezone.utc) < self.locked_until

    def __repr__(self) -> str:
        return f"<User {self.email} admin={self.is_admin}>"
