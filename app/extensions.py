"""
Extensions Flask — initialisées ici sans référence à l'app.
Chaque extension est liée à l'app dans create_app() via .init_app().
"""

import redis as redis_lib
from apscheduler.schedulers.background import BackgroundScheduler
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

# ORM principal
db = SQLAlchemy()

# Migrations Alembic
migrate = Migrate()

# Hachage bcrypt des mots de passe
bcrypt = Bcrypt()

# Protection CSRF des formulaires
csrf = CSRFProtect()

# Rate limiting (backend Redis configuré via RATELIMIT_STORAGE_URI)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],  # Les limites sont définies route par route
)

# Scheduler APScheduler (rotation des clés RS256 toutes les 90 jours)
scheduler = BackgroundScheduler(daemon=True)

# Client Redis global (sessions, blacklist tokens, Pub/Sub)
_redis_client: redis_lib.Redis | None = None


def get_redis() -> redis_lib.Redis:
    """
    Retourne le client Redis global.
    Doit être appelé après init_redis().
    """
    if _redis_client is None:
        raise RuntimeError(
            "Redis n'est pas initialisé. Appelez init_redis() dans create_app()."
        )
    return _redis_client


def init_redis(redis_url: str) -> redis_lib.Redis:
    """Initialise le client Redis global à partir de l'URL de config."""
    global _redis_client
    _redis_client = redis_lib.from_url(
        redis_url,
        decode_responses=True,  # Les valeurs sont renvoyées comme str (pas bytes)
        socket_connect_timeout=5,
        socket_timeout=5,
        retry_on_timeout=True,
    )
    return _redis_client
