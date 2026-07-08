import os
import pyotp
import qrcode
from io import BytesIO
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app

class TOTPService:
    @staticmethod
    def generate_secret() -> str:
        """Génère une nouvelle clé secrète TOTP (base32)."""
        return pyotp.random_base32()

    @staticmethod
    def encrypt_secret(secret: str, aes_key: bytes) -> str:
        """Chiffre le secret TOTP avec AES-256-GCM."""
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, secret.encode(), None)
        return base64.b64encode(nonce + ciphertext).decode('utf-8')

    @staticmethod
    def decrypt_secret(encrypted_b64: str, aes_key: bytes) -> str:
        data = base64.b64decode(encrypted_b64)
        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(aes_key)
        return aesgcm.decrypt(nonce, ciphertext, None).decode()

    @staticmethod
    def get_totp_uri(secret: str, email: str, issuer: str = "SSO") -> str:
        return pyotp.totp.TOTP(secret).provisioning_uri(email, issuer_name=issuer)

    @staticmethod
    def get_qr_data_uri(uri: str) -> str:
        qr = qrcode.QRCode(box_size=10, border=4)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        b64 = base64.b64encode(buffered.getvalue()).decode()
        return f"data:image/png;base64,{b64}"

    @staticmethod
    def verify_code(secret: str, code: str, valid_window: int = 1) -> bool:
        return pyotp.TOTP(secret).verify(code, valid_window=valid_window)

    @staticmethod
    def generate_backup_codes(count: int = 10) -> list:
        import secrets
        return [secrets.token_urlsafe(12) for _ in range(count)]

    @staticmethod
    def hash_backup_codes(codes: list) -> list:
        # Backup codes have 96-bit entropy — brute-force is infeasible regardless
        # of bcrypt rounds, so we use rounds=4 to avoid gunicorn timeouts on
        # slow shared CPUs (10× rounds=12 hashes can exceed the 30s worker timeout).
        import bcrypt as _bcrypt
        return [
            _bcrypt.hashpw(code.encode(), _bcrypt.gensalt(rounds=4)).decode('utf-8')
            for code in codes
        ]