from datetime import datetime, timezone, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, current_app
from app.extensions import bcrypt, db, limiter, get_redis
from app.models.user import User
from app.models.oauth2_token import OAuth2Token
from app.models.oauth2_client import OAuth2Client
from app.models.audit_log import (
    AuditLog,
    EVENT_LOGIN_SUCCESS,
    EVENT_LOGIN_FAILURE,
    EVENT_ACCOUNT_LOCKED,
    EVENT_LOGOUT,
    EVENT_TOKEN_REVOKED,
)
from app.services.session_service import create_user_session
from app.services.email_service import send_password_reset_email
import uuid
import secrets

auth_bp = Blueprint('auth', __name__)

_LOCKOUT_THRESHOLD = 10
_LOCKOUT_DURATION_MINUTES = 15

@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        # Vérifier le verrouillage avant toute autre opération
        if user and user.is_locked():
            flash('Compte verrouillé. Veuillez réessayer plus tard.', 'danger')
            return render_template('login.html')

        if user and bcrypt.check_password_hash(user.password_hash, password):
            # Réinitialiser le compteur d'échecs
            user.failed_login_count = 0
            user.locked_until = None
            db.session.commit()
            # Si 2FA activée, rediriger vers la page de vérification
            if user.totp_enabled:
                session['pending_2fa_user'] = str(user.id)
                return redirect(url_for('twofa.verify_page'))
            # Sinon, finaliser directement
            session['user_id'] = str(user.id)
            return redirect(url_for('auth.finalize_login'))
        else:
            if user:
                user.failed_login_count += 1
                if user.failed_login_count >= _LOCKOUT_THRESHOLD:
                    user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=_LOCKOUT_DURATION_MINUTES)
                    AuditLog.log(
                        event_type=EVENT_ACCOUNT_LOCKED,
                        ip_address=request.remote_addr,
                        user_id=user.id,
                        user_agent=request.user_agent.string,
                        details={"failed_count": user.failed_login_count},
                    )
                AuditLog.log(
                    event_type=EVENT_LOGIN_FAILURE,
                    ip_address=request.remote_addr,
                    user_id=user.id,
                    user_agent=request.user_agent.string,
                )
            else:
                AuditLog.log(
                    event_type=EVENT_LOGIN_FAILURE,
                    ip_address=request.remote_addr,
                    user_agent=request.user_agent.string,
                )
            db.session.commit()
            flash('Email ou mot de passe incorrect', 'danger')
            return render_template('login.html')
    return render_template('login.html')

@auth_bp.route('/finalize-login')
def finalize_login():
    user_id = session.pop('pending_2fa_user', None) or session.get('user_id')
    if not user_id:
        return redirect(url_for('auth.login'))
    user = User.query.get(uuid.UUID(user_id))
    if not user:
        return redirect(url_for('auth.login'))
    # Créer la session Redis
    session_id = create_user_session(user.id, request.remote_addr, request.user_agent.string)
    session['user_id'] = str(user.id)
    session['session_id'] = session_id
    AuditLog.log(
        event_type=EVENT_LOGIN_SUCCESS,
        ip_address=request.remote_addr,
        user_id=user.id,
        user_agent=request.user_agent.string,
        details={"2fa": user.totp_enabled},
    )
    db.session.commit()
    # Rediriger vers la page demandée ou /profile par défaut
    next_url = session.pop('next_url', url_for('auth.profile'))
    return redirect(next_url)

@auth_bp.route('/2fa-verify')
def verify_page():
    """Affiche le formulaire de saisie du code TOTP."""
    if 'pending_2fa_user' not in session:
        return redirect(url_for('auth.login'))
    return render_template('2fa_verify.html')

@auth_bp.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Veuillez vous connecter.', 'warning')
        return redirect(url_for('auth.login'))
    user = User.query.get(uuid.UUID(session['user_id']))
    if not user:
        session.clear()
        return redirect(url_for('auth.login'))
    # UC-05 : applications connectées (tokens actifs groupés par client)
    now = datetime.now(timezone.utc)
    active_tokens = (
        OAuth2Token.query
        .filter_by(user_id=user.id)
        .filter(OAuth2Token.revoked_at.is_(None))
        .filter(OAuth2Token.expires_at > now)
        .order_by(OAuth2Token.issued_at.desc())
        .all()
    )
    seen_clients: dict = {}
    for token in active_tokens:
        if token.client_id not in seen_clients:
            client = OAuth2Client.query.filter_by(client_id=token.client_id).first()
            if client:
                seen_clients[token.client_id] = {
                    'client': client,
                    'scope': token.scope,
                    'issued_at': token.issued_at,
                }
    connected_apps = list(seen_clients.values())
    return render_template('profile.html', user=user, connected_apps=connected_apps)


@auth_bp.route('/profile/revoke-app', methods=['POST'])
def revoke_app():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    user = User.query.get(uuid.UUID(session['user_id']))
    if not user:
        session.clear()
        return redirect(url_for('auth.login'))
    client_id = request.form.get('client_id')
    if not client_id:
        flash('Client ID manquant.', 'danger')
        return redirect(url_for('auth.profile'))
    now = datetime.now(timezone.utc)
    tokens = (
        OAuth2Token.query
        .filter_by(user_id=user.id, client_id=client_id)
        .filter(OAuth2Token.revoked_at.is_(None))
        .filter(OAuth2Token.expires_at > now)
        .all()
    )
    redis = get_redis()
    for token in tokens:
        token.revoked_at = now
        # Invalider aussi le dernier access token lié
        if token.access_token_jti:
            redis.setex(f'blacklist:{token.access_token_jti}', 3600, '1')
    AuditLog.log(
        event_type=EVENT_TOKEN_REVOKED,
        ip_address=request.remote_addr,
        user_id=user.id,
        client_id=client_id,
        user_agent=request.user_agent.string,
        details={'token_type': 'user_initiated_revoke', 'count': len(tokens)},
    )
    db.session.commit()
    flash('Accès de l\'application révoqué avec succès.', 'success')
    return redirect(url_for('auth.profile'))

_RESET_TTL = 3600  # 1 heure

@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("5 per hour")
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        user = User.query.filter_by(email=email).first()
        if user and user.is_active:
            token = secrets.token_urlsafe(32)
            redis = get_redis()
            redis.setex(f'pwd_reset:{token}', _RESET_TTL, str(user.id))
            reset_link = url_for('auth.reset_password', token=token, _external=True)
            try:
                send_password_reset_email(user.email, reset_link)
            except Exception as exc:
                current_app.logger.error(f"Envoi email reset échoué pour {email}: {exc}")
        # Toujours afficher le même message (anti-énumération d'e-mails)
        flash('Si cet e-mail est enregistré, un lien vous a été envoyé.', 'info')
        return redirect(url_for('auth.login'))
    return render_template('forgot_password.html')


@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token: str):
    redis = get_redis()
    user_id_bytes = redis.get(f'pwd_reset:{token}')
    if not user_id_bytes:
        flash('Lien invalide ou expiré.', 'danger')
        return redirect(url_for('auth.forgot_password'))
    user = User.query.get(uuid.UUID(user_id_bytes.decode()))
    if not user:
        flash('Utilisateur introuvable.', 'danger')
        return redirect(url_for('auth.forgot_password'))
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        if len(password) < 8:
            flash('Le mot de passe doit comporter au moins 8 caractères.', 'danger')
            return render_template('reset_password.html', token=token)
        if password != confirm:
            flash('Les mots de passe ne correspondent pas.', 'danger')
            return render_template('reset_password.html', token=token)
        user.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        # Invalider le token de reset
        redis.delete(f'pwd_reset:{token}')
        AuditLog.log(
            event_type='password_reset',
            ip_address=request.remote_addr,
            user_id=user.id,
            user_agent=request.user_agent.string,
        )
        db.session.commit()
        flash('Mot de passe réinitialisé. Vous pouvez vous connecter.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('reset_password.html', token=token)


@auth_bp.route('/logout')
def logout():
    user_id_str = session.get('user_id')
    session_id = session.pop('session_id', None)
    if session_id:
        redis = get_redis()
        redis.delete(f'session:{session_id}')
    user_id_for_log = None
    if user_id_str:
        try:
            user_id_for_log = uuid.UUID(user_id_str)
        except ValueError:
            pass
    AuditLog.log(
        event_type=EVENT_LOGOUT,
        ip_address=request.remote_addr,
        user_id=user_id_for_log,
        user_agent=request.user_agent.string,
    )
    db.session.commit()
    session.clear()
    flash('Vous êtes déconnecté.', 'info')
    return redirect(url_for('auth.login'))
