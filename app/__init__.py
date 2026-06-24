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

# CSP : autorise les CDN utilisés dans les templates (Tailwind, Alpine.js, Font Awesome, Google Fonts)
# unsafe-inline/unsafe-eval sont requis par Alpine.js v3 CDN et les event handlers inline existants
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' "
        "https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' "
        "https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
    "font-src 'self' "
        "https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none';"
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

    from .routes.public import public_bp
    app.register_blueprint(public_bp)

    from .routes.auth import auth_bp
    app.register_blueprint(auth_bp)

    from .routes.oauth2 import oauth2_bp
    app.register_blueprint(oauth2_bp)

    from .routes.twofa import twofa_bp
    app.register_blueprint(twofa_bp)

    from .routes.admin import admin_bp
    app.register_blueprint(admin_bp)

    # ── En-têtes de sécurité HTTP ─────────────────────────────────────────
    _configure_security_headers(app)

    # ── Scheduler (rotation des clés RS256) ───────────────────────────────
    if not app.config.get("TESTING") and not scheduler.running:
        _register_scheduled_tasks(app)
        scheduler.start()

    return app

def _configure_security_headers(app: Flask) -> None:
    @app.after_request
    def add_security_headers(response):
        # HSTS : uniquement en production (nécessite HTTPS)
        if not app.config.get('TESTING') and not app.config.get('DEBUG'):
            response.headers.setdefault(
                'Strict-Transport-Security',
                'max-age=31536000; includeSubDomains'
            )
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '0'  # désactive l'auditor XSS legacy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        response.headers.setdefault('Content-Security-Policy', _CSP)
        return response

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
