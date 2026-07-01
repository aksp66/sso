import os
from flask import Flask, jsonify, render_template, request
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

    # ── Application des migrations ──────────────────────────────────────────
    # Filet de sécurité indépendant de entrypoint.sh : certains hébergeurs
    # (ex. Render avec une commande de démarrage personnalisée) contournent
    # l'ENTRYPOINT du Dockerfile et lancent gunicorn directement, sans jamais
    # exécuter "flask db upgrade". En l'appliquant ici, les migrations sont
    # garanties à chaque démarrage de l'app, quel que soit le mécanisme de
    # lancement du conteneur. Idempotent : sans effet si déjà à jour.
    if not app.config.get('TESTING'):
        with app.app_context():
            from flask_migrate import upgrade as apply_migrations
            try:
                apply_migrations()
            except Exception as e:
                app.logger.error(f"Erreur application des migrations : {e}")

    # ── Import des modèles (OBLIGATOIRE pour SQLAlchemy) ───────────────────
    with app.app_context():
        from .models.audit_log import AuditLog
        from .models.client_request import ClientRequest
        from .models.oauth2_client import OAuth2Client
        from .models.oauth2_code import OAuth2AuthorizationCode
        from .models.oauth2_consent import OAuth2Consent
        from .models.oauth2_token import OAuth2Token
        from .models.rs256_key import RS256Key
        from .models.user import User

    # ── Bootstrap admin (premier démarrage) ───────────────────────────────
    if not app.config.get('TESTING'):
        _bootstrap_admin(app)

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

    # ── Pages d'erreur ─────────────────────────────────────────────────────
    _configure_error_handlers(app)

    # ── Scheduler (rotation des clés RS256) ───────────────────────────────
    if not app.config.get("TESTING") and not scheduler.running:
        _register_scheduled_tasks(app)
        scheduler.start()

    return app

def _bootstrap_admin(app: Flask) -> None:
    """Crée le premier compte admin si ADMIN_BOOTSTRAP_EMAIL et
    ADMIN_BOOTSTRAP_PASSWORD sont définis ET qu'aucun admin n'existe."""
    email    = app.config.get("ADMIN_BOOTSTRAP_EMAIL",    "").strip()
    password = app.config.get("ADMIN_BOOTSTRAP_PASSWORD", "").strip()
    username = app.config.get("ADMIN_BOOTSTRAP_USERNAME", "admin").strip() or "admin"

    if not email or not password:
        return  # Variables non configurées → rien à faire

    with app.app_context():
        from .models.user import User
        from .extensions import bcrypt, db

        if User.query.filter_by(is_admin=True).first():
            return  # Au moins un admin existe déjà → on ne touche à rien

        existing = User.query.filter(
            (User.email == email) | (User.username == username)
        ).first()
        if existing:
            # Le compte existe mais n'est pas encore admin → on le promeut
            existing.is_admin = True
            existing.is_active = True
            existing.email_verified = True
            db.session.commit()
            app.logger.info(f"Bootstrap : compte existant promu admin ({email})")
            return

        admin = User(
            username=username,
            email=email,
            password_hash=bcrypt.generate_password_hash(password).decode('utf-8'),
            is_admin=True,
            is_active=True,
            email_verified=True,
        )
        db.session.add(admin)
        db.session.commit()
        app.logger.info(f"Bootstrap : compte admin créé ({email})")


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

def _wants_json() -> bool:
    """Les endpoints OAuth2 répondent toujours en JSON (RFC 6749 §5.2),
    sauf /authorize qui est navigué par un navigateur et doit afficher
    une page HTML lisible (RFC 6749 §4.1.2.1 — erreurs avant redirection)."""
    if request.blueprint == 'oauth2' and request.endpoint != 'oauth2.authorize':
        return True
    best = request.accept_mimetypes.best_match(['application/json', 'text/html'])
    return best == 'application/json'


def _configure_error_handlers(app: Flask) -> None:
    @app.errorhandler(400)
    def handle_400(e):
        if _wants_json():
            return jsonify({'error': 'invalid_request', 'error_description': str(e.description)}), 400
        return render_template('errors/400.html'), 400

    @app.errorhandler(401)
    def handle_401(e):
        if _wants_json():
            return jsonify({'error': 'invalid_token', 'error_description': str(e.description)}), 401
        return render_template('errors/401.html'), 401

    @app.errorhandler(403)
    def handle_403(e):
        if _wants_json():
            return jsonify({'error': 'access_denied', 'error_description': str(e.description)}), 403
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def handle_404(e):
        if _wants_json():
            return jsonify({'error': 'not_found'}), 404
        return render_template('errors/404.html'), 404

    @app.errorhandler(429)
    def handle_429(e):
        if _wants_json():
            return jsonify({'error': 'rate_limit_exceeded', 'error_description': str(e.description)}), 429
        return render_template('errors/429.html'), 429

    @app.errorhandler(500)
    def handle_500(e):
        app.logger.error(f"Erreur serveur non gérée : {e}")
        if _wants_json():
            return jsonify({'error': 'server_error'}), 500
        return render_template('errors/500.html'), 500


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
