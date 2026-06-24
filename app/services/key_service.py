import os
import base64
import time
from datetime import datetime, timedelta, timezone
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app
from sqlalchemy.exc import IntegrityError, OperationalError
from app.extensions import db
from app.models.rs256_key import RS256Key

class KeyService:
    @staticmethod
    def generate_keypair():
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def encrypt_private_key(private_key, aes_key: bytes) -> str:
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, pem, None)
        return base64.b64encode(nonce + ciphertext).decode('utf-8')

    @staticmethod
    def decrypt_private_key(encrypted_b64: str, aes_key: bytes):
        data = base64.b64decode(encrypted_b64)
        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(aes_key)
        pem = aesgcm.decrypt(nonce, ciphertext, None)
        return serialization.load_pem_private_key(pem, password=None)

    @staticmethod
    def get_active_key() -> RS256Key:
        # Vérifier l'existence de la table
        try:
            key = RS256Key.query.filter_by(is_active=True).first()
            if key and key.expires_at > datetime.now(timezone.utc):
                return key
        except OperationalError:
            current_app.logger.info("Table rs256_keys inexistante, création lors de la rotation")
            return KeyService.rotate_keys()
        # Aucune clé active ou expirée → rotation
        return KeyService.rotate_keys()

    @staticmethod
    def rotate_if_needed(warning_days: int = 7) -> Optional[RS256Key]:
        """Effectue une rotation seulement si la clé active est absente,
        expirée, ou expire dans moins de `warning_days` jours.

        Appelé quotidiennement par le scheduler (cron 2h) — sans ce garde-fou,
        une rotation serait déclenchée à chaque exécution du job.
        """
        key = RS256Key.query.filter_by(is_active=True).first()
        if key and key.days_until_expiry() > warning_days:
            return None
        return KeyService.rotate_keys()

    @staticmethod
    def rotate_keys() -> RS256Key:
        # Désactiver l'ancienne clé active (si elle existe)
        try:
            RS256Key.query.filter_by(is_active=True).update({"is_active": False})
            db.session.commit()
        except Exception:
            db.session.rollback()

        # Générer nouvelle paire
        priv, pub = KeyService.generate_keypair()
        aes_key = current_app.config['AES_ENCRYPTION_KEY']
        encrypted_priv = KeyService.encrypt_private_key(priv, aes_key)
        pub_pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        kid = f"key-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        new_key = RS256Key(
            kid=kid,
            private_key_encrypted=encrypted_priv,
            public_key_pem=pub_pem,
            algorithm='RS256',
            is_active=True,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=90)
        )
        try:
            db.session.add(new_key)
            db.session.commit()
            return new_key
        except IntegrityError:
            db.session.rollback()
            current_app.logger.warning("Conflit de clé duplicata – récupération de la clé active existante")
            key = RS256Key.query.filter_by(is_active=True).first()
            if key:
                return key
            # Fallback : ajouter un microsecond timestamp
            time.sleep(0.1)
            kid = f"key-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
            new_key.kid = kid
            db.session.add(new_key)
            db.session.commit()
            return new_key