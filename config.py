import base64
import os

from dotenv import load_dotenv

load_dotenv()


class Config:
    # ── Flask ─────────────────────────────────────────────────────────────
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "dev-secret-change-in-production")
    DEBUG: bool = False
    TESTING: bool = False

    # ── Base de données ───────────────────────────────────────────────────
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "DATABASE_URL", "postgresql://sso_user:sso_pass@localhost:5432/sso_db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    SQLALCHEMY_ENGINE_OPTIONS: dict = {
        "pool_size": 10,
        "max_overflow": 20,
        "pool_pre_ping": True,  # Vérifie la connexion avant usage
        "pool_recycle": 300,
    }

    # ── Redis ─────────────────────────────────────────────────────────────
    REDIS_URL: str = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

    # ── Flask-Limiter (rate limiting via Redis) ───────────────────────────
    RATELIMIT_STORAGE_URI: str = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    RATELIMIT_STRATEGY: str = "fixed-window"
    RATELIMIT_HEADERS_ENABLED: bool = True

    # ── Sécurité ──────────────────────────────────────────────────────────
    BCRYPT_LOG_ROUNDS: int = int(os.environ.get("BCRYPT_LOG_ROUNDS", "12"))
    WTF_CSRF_ENABLED: bool = True
    WTF_CSRF_TIME_LIMIT: int = 3600  # secondes

    # ── Chiffrement AES-256-GCM ───────────────────────────────────────────
    AES_ENCRYPTION_KEY: bytes = base64.b64decode(
        os.environ.get("AES_ENCRYPTION_KEY", "")
    ) if os.environ.get("AES_ENCRYPTION_KEY") else b"dev-aes-256-key-do-not-use-prod!"

    # ── SSO / OAuth2 ──────────────────────────────────────────────────────
    SSO_ISSUER: str = os.environ.get("SSO_ISSUER", "http://localhost:8000")
    ACCESS_TOKEN_EXPIRE_SECONDS: int = int(
        os.environ.get("ACCESS_TOKEN_EXPIRE_SECONDS", "3600")
    )
    REFRESH_TOKEN_EXPIRE_SECONDS: int = int(
        os.environ.get("REFRESH_TOKEN_EXPIRE_SECONDS", "2592000")  # 30 jours
    )
    SESSION_TTL_SECONDS: int = int(os.environ.get("SESSION_TTL_SECONDS", "3600"))

    # ── SMTP (reset mot de passe) ─────────────────────────────────────────
    SMTP_HOST: str = os.environ.get("SMTP_HOST", "localhost")
    SMTP_PORT: int = int(os.environ.get("SMTP_PORT", "587"))
    SMTP_USER: str = os.environ.get("SMTP_USER", "")
    SMTP_PASS: str = os.environ.get("SMTP_PASS", "")
    SMTP_FROM: str = os.environ.get("SMTP_FROM", "no-reply@sso.local")

    AUTHORIZATION_CODE_EXPIRE_SECONDS: int = int(
        os.environ.get("AUTHORIZATION_CODE_EXPIRE_SECONDS", "300")
    )


class DevelopmentConfig(Config):
    DEBUG = True
    BCRYPT_LOG_ROUNDS = 4  # Plus rapide en dev


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "postgresql://sso_user:sso_pass@db:5432/sso_test"
    )
    BCRYPT_LOG_ROUNDS = 4
    WTF_CSRF_ENABLED = False


class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        **Config.SQLALCHEMY_ENGINE_OPTIONS,
        "pool_size": 20,
        "max_overflow": 40,
    }


config = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
