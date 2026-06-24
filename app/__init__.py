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
    scheduler,
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
        from .models.oauth2_consent import OAuth2Consent
        from .models.oauth2_token import OAuth2Token
        from .models.rs256_key import RS256Key
        from .models.user import User

    # ── Client Redis ───────────────────────────────────────────────────────
    init_redis(app.config["REDIS_URL"])

    # ── Initialisation de la clé RS256 (après que les modèles sont chargés) ─
    if not app.config.get('TESTING'):
        with app.app_context():
            from app.services.key_service import KeyService
            try:
                KeyService.get_active_key()
            except Exception as e:
                app.logger.warning(f"Erreur initialisation clé RS256 : {e}")

    # ── Enregistrement des Blueprints ──────────────────────────────────────
    from .routes.health import health_bp
    app.register_blueprint(health_bp)

    from .routes.auth import auth_bp
    app.register_blueprint(auth_bp)

    from .routes.oauth2 import oauth2_bp
    app.register_blueprint(oauth2_bp)

    from .routes.twofa import twofa_bp
    app.register_blueprint(twofa_bp)

    from .routes.admin import admin_bp
    app.register_blueprint(admin_bp)

    # ── Scheduler (rotation des clés RS256) ───────────────────────────────
    if not app.config.get("TESTING") and not scheduler.running:
        _register_scheduled_tasks(app)
        scheduler.start()

    return app

def _register_scheduled_tasks(app: Flask) -> None:
    def rotate_rs256_keys() -> None:
        with app.app_context():
            try:
                from .services.key_service import KeyService
                KeyService.rotate_if_needed()
            except Exception as exc:
                app.logger.error(f"Erreur rotation clés RS256 : {exc}")

    scheduler.add_job(
        rotate_rs256_keys,
        trigger="cron",
        hour=2,
        minute=0,
        id="rs256_key_rotation",
        replace_existing=True,
    )
