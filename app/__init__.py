import os
from flask import Flask
from config import config
from .extensions import (
    bcrypt,
    csrf,
    db,
    init_redis,
    limiter,
    migrate,
)

def create_app(config_name: str | None = None) -> Flask:
    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "development")

    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # ── Initialisation des extensions ──────────────────────────────────────
    db.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # ── Import des modèles (OBLIGATOIRE pour SQLAlchemy) ───────────────────
    with app.app_context():
        from .models.audit_log import AuditLog
        from .models.oauth2_client import OAuth2Client
        from .models.oauth2_code import OAuth2AuthorizationCode
        from .models.oauth2_token import OAuth2Token
        from .models.rs256_key import RS256Key
        from .models.user import User

    # ── Client Redis ───────────────────────────────────────────────────────
    init_redis(app.config["REDIS_URL"])

    # ── Enregistrement des Blueprints ──────────────────────────────────────
    from .routes.health import health_bp
    app.register_blueprint(health_bp)

    return app
