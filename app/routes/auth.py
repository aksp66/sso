from datetime import datetime, timezone, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, current_app
from app.extensions import bcrypt, db, limiter, get_redis
from app.models.user import User
from app.services.session_service import create_user_session
import uuid

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
    return render_template('profile.html', user=user)

@auth_bp.route('/logout')
def logout():
    session_id = session.pop('session_id', None)
    if session_id:
        redis = get_redis()
        redis.delete(f'session:{session_id}')
    session.clear()
    flash('Vous êtes déconnecté.', 'info')
    return redirect(url_for('auth.login'))
