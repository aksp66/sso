"""
Tests de la double authentification (TOTP)
"""

import pytest
from unittest.mock import patch
from app.services.totp_service import TOTPService
from app.models.user import User
from app.extensions import db
import pyotp



def test_totp_service_generate_secret():
    secret = TOTPService.generate_secret()
    assert len(secret) == 32  # base32 length
    assert secret.isalnum() or '=' in secret


def test_totp_service_encrypt_decrypt():
    secret = "JBSWY3DPEHPK3PXP"
    aes_key = b"01234567890123456789012345678901"  # 32 bytes
    encrypted = TOTPService.encrypt_secret(secret, aes_key)
    assert encrypted != secret
    decrypted = TOTPService.decrypt_secret(encrypted, aes_key)
    assert decrypted == secret


def test_totp_verify_correct_code():
    secret = TOTPService.generate_secret()
    totp = pyotp.TOTP(secret)
    code = totp.now()
    assert TOTPService.verify_code(secret, code) is True


def test_totp_verify_wrong_code():
    secret = TOTPService.generate_secret()
    assert TOTPService.verify_code(secret, "123456") is False


def test_generate_backup_codes():
    codes = TOTPService.generate_backup_codes(5)
    assert len(codes) == 5
    for code in codes:
        assert len(code) >= 12


def test_hash_backup_codes():
    codes = ["abc123", "def456"]
    hashed = TOTPService.hash_backup_codes(codes)
    assert len(hashed) == 2
    assert hashed[0] != codes[0]
    # Vérification bcrypt approximative (le hash commence par $2b$)
    assert hashed[0].startswith('$2b$')


def test_enroll_2fa(client, test_user):
    with client:
        # Connexion – suivre toutes les redirections
        login_resp = client.post('/login', data={
            'email': test_user.email,
            'password': 'password123'
        }, follow_redirects=True)
        # Vérifier que la session est active (on est sur le profil)
        assert b'Mon profil' in login_resp.data

        # GET /2fa/setup (doit renvoyer 200)
        resp = client.get('/2fa/setup')
        assert resp.status_code == 200
        assert b'QR Code' in resp.data or b'QR' in resp.data

        with patch('app.services.totp_service.TOTPService.verify_code', return_value=True):
            resp2 = client.post('/2fa/enroll', data={'code': '123456'}, follow_redirects=True)
            text = resp2.get_data(as_text=True)
            assert 'Codes de secours' in text or 'Continuer' in text

def test_2fa_verification_during_login(client, test_user, db, app):
    with app.app_context():
        aes_key = app.config['AES_ENCRYPTION_KEY']
        secret = TOTPService.generate_secret()
        test_user.totp_secret = TOTPService.encrypt_secret(secret, aes_key)
        test_user.totp_enabled = True
        db.session.commit()

    with client:
        # Tentative de login (redirige vers /2fa/verify)
        resp = client.post('/login', data={
            'email': test_user.email,
            'password': 'password123'
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert '/2fa/verify' in resp.headers['Location']

        # GET sur la page de vérification
        resp2 = client.get('/2fa/verify-page')
        # decode to text to allow non-ascii characters in assertions
        text = resp2.get_data(as_text=True)
        assert 'Vérification en deux étapes' in text

        # Simuler un code correct et soumettre
        with patch('app.services.totp_service.TOTPService.verify_code', return_value=True):
            resp3 = client.post('/2fa/verify', data={'totp_code': '654321'}, follow_redirects=True)
            # Après vérification, on est redirigé vers finalize_login puis profil
            assert resp3.status_code == 200
            assert b'Mon profil' in resp3.data