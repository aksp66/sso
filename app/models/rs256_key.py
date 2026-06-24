"""
Modèle RS256Key — table `rs256_keys`

Conforme au cahier des charges §3.5 et §5.6.
Gère la rotation automatique des paires de clés RSA 2048 bits.

Règles de rotation :
- Durée de vie : 90 jours
- La clé privée est chiffrée en AES-256-GCM avant stockage
- /jwks.json expose TOUTES les clés actives + 30 jours post-expiration
  (pour que les anciens tokens restent vérifiables pendant leur durée de vie)
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, String, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.extensions import db


class RS256Key(db.Model):
    """
    Paire de clés RSA 2048 bits pour la signature JWT RS256.

    - kid (Key ID) : inclus dans le header JWT et dans /jwks.json
    - private_key_encrypted : clé privée PEM chiffrée AES-256-GCM
    - public_key_pem : clé publique PEM exposée via /jwks.json
    - is_active : True = utilisée pour signer les nouveaux tokens
                  False = conservée pour vérifier les anciens tokens
    """

    __tablename__ = "rs256_keys"

    # ── Identité ───────────────────────────────────────────────────────────
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
        nullable=False,
    )
    # Key ID — format : key-YYYY-QN (ex: key-2026-Q2)
    kid: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
        comment="Key ID inclus dans le header JWT et exposé dans /jwks.json",
    )

    # ── Clés cryptographiques ──────────────────────────────────────────────
    # Clé privée chiffrée en AES-256-GCM (base64 : nonce || ciphertext)
    private_key_encrypted: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Clé privée RSA 2048 bits chiffrée AES-256-GCM",
    )
    # Clé publique en PEM — exposée librement dans /jwks.json
    public_key_pem: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Clé publique RSA (format PEM) — exposée via /jwks.json",
    )
    algorithm: Mapped[str] = mapped_column(
        String(16), default="RS256", server_default=text("'RS256'"), nullable=False
    )

    # ── Statut ─────────────────────────────────────────────────────────────
    # Une seule clé is_active=True à la fois (pour signer les nouveaux tokens)
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        index=True,
        comment="True = utilisée pour signer. False = conservée pour vérifier.",
    )

    # ── Cycle de vie ───────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=text("now()"),
        nullable=False,
    )
    # Durée de vie : 90 jours après création
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="created_at + 90 jours",
    )

    def is_expired(self) -> bool:
        """La clé a dépassé sa durée de vie de 90 jours."""
        return datetime.now(timezone.utc) > self.expires_at

    def days_until_expiry(self) -> int:
        """Nombre de jours avant expiration (négatif si déjà expirée)."""
        delta = self.expires_at - datetime.now(timezone.utc)
        return delta.days

    def __repr__(self) -> str:
        return (
            f"<RS256Key kid={self.kid} active={self.is_active} "
            f"expires={self.expires_at.date()}>"
        )
