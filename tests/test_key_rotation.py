"""
Tests de rotation des clés RS256
"""

import pytest
from datetime import datetime, timedelta, timezone
from app.services.key_service import KeyService
from app.models.rs256_key import RS256Key
from app.extensions import db


def test_rotate_keys(db):
    """Vérifie qu'une rotation désactive l'ancienne clé et en crée une nouvelle."""
    # Nettoyer la table
    RS256Key.query.delete()
    db.session.commit()

    # Première rotation : crée une clé active
    key1 = KeyService.rotate_keys()
    assert key1.is_active is True
    assert key1.kid.startswith('key-')

    # Deuxième rotation : la première clé devient inactive, la nouvelle est active
    key2 = KeyService.rotate_keys()
    assert key2.is_active is True
    assert key2.kid != key1.kid

    # Recharger key1 depuis la BDD
    db.session.refresh(key1)
    assert key1.is_active is False

    # Il ne doit y avoir qu'une seule clé active
    active_keys = RS256Key.query.filter_by(is_active=True).all()
    assert len(active_keys) == 1
    assert active_keys[0].kid == key2.kid


def test_get_active_key_auto_rotation(db):
    """Si aucune clé active n'existe, get_active_key en crée une."""
    RS256Key.query.delete()
    db.session.commit()

    key = KeyService.get_active_key()
    assert key is not None
    assert key.is_active is True
    assert key.expires_at > datetime.now(timezone.utc)


def test_get_active_key_returns_existing_valid_key(db):
    """Si une clé active et non expirée existe, elle est retournée."""
    RS256Key.query.delete()
    db.session.commit()

    key1 = KeyService.rotate_keys()
    key2 = KeyService.get_active_key()

    assert key2.id == key1.id
    assert key2.is_active is True


def test_jwks_exposes_only_non_expired_keys(client, db):
    """L'endpoint /jwks.json ne doit exposer que les clés non expirées (actives ou non)."""
    # Nettoyer
    RS256Key.query.delete()
    db.session.commit()

    # Créer une clé active
    active_key = KeyService.rotate_keys()
    # Créer une clé expirée (désactivée)
    expired_key = KeyService.rotate_keys()
    expired_key.is_active = False
    expired_key.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    db.session.commit()

    resp = client.get('/jwks.json')
    assert resp.status_code == 200
    data = resp.get_json()
    keys = data['keys']

    # La clé expirée ne doit pas apparaître (même si elle est dans la BDD)
    kid_list = [k['kid'] for k in keys]
    assert active_key.kid in kid_list
    assert expired_key.kid not in kid_list

    # Une seule clé exposée (la clé active)
    assert len(keys) == 1


def test_key_encryption_decryption():
    """Vérifie le chiffrement/déchiffrement de la clé privée."""
    from app.services.key_service import KeyService
    from cryptography.hazmat.primitives.asymmetric import rsa
    import base64

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    aes_key = b'01234567890123456789012345678901'  # 32 bytes

    encrypted = KeyService.encrypt_private_key(private_key, aes_key)
    decrypted = KeyService.decrypt_private_key(encrypted, aes_key)

    # Comparer les clés privées en PEM
    from cryptography.hazmat.primitives import serialization
    original_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    decrypted_pem = decrypted.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    assert original_pem == decrypted_pem