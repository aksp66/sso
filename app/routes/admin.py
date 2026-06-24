from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from app.extensions import db, limiter
from app.models.user import User
from app.models.oauth2_client import OAuth2Client
from app.models.audit_log import AuditLog
from app.services.totp_service import TOTPService  # pour reset 2FA
import uuid
from functools import wraps

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Veuillez vous connecter.', 'warning')
            return redirect(url_for('auth.login'))
        user = User.query.get(uuid.UUID(session['user_id']))
        if not user or not user.is_admin:
            flash('Accès interdit.', 'danger')
            return redirect(url_for('auth.profile'))
        if not user.totp_enabled:
            flash('Les administrateurs doivent activer la 2FA.', 'danger')
            return redirect(url_for('twofa.setup'))
        return f(*args, **kwargs)
    return decorated

@admin_bp.route('/users')
@admin_required
@limiter.limit("30 per minute")
def users():
    page = request.args.get('page', 1, type=int)
    pagination = User.query.paginate(page=page, per_page=20)
    return render_template('admin/users.html', users=pagination.items, pagination=pagination)

@admin_bp.route('/users/<uuid:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form.get('username')
        user.email = request.form.get('email')
        user.is_admin = 'is_admin' in request.form
        user.is_active = 'is_active' in request.form
        db.session.commit()
        flash('Utilisateur mis à jour.', 'success')
        return redirect(url_for('admin.users'))
    return render_template('admin/user_form.html', user=user)

@admin_bp.route('/users/<uuid:user_id>/reset-2fa', methods=['POST'])
@admin_required
def reset_2fa(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == session['user_id']:
        flash('Vous ne pouvez pas réinitialiser votre propre 2FA.', 'danger')
        return redirect(url_for('admin.users'))
    user.totp_enabled = False
    user.totp_secret = None
    user.backup_codes = None
    db.session.commit()
    flash(f'2FA réinitialisée pour {user.email}.', 'success')
    return redirect(url_for('admin.users'))

@admin_bp.route('/clients')
@admin_required
def clients():
    clients = OAuth2Client.query.all()
    return render_template('admin/clients.html', clients=clients)

@admin_bp.route('/clients/new', methods=['GET', 'POST'])
@admin_required
def new_client():
    from app.extensions import bcrypt
    import secrets
    if request.method == 'POST':
        client_id = secrets.token_urlsafe(16)
        client_secret = secrets.token_urlsafe(32) if request.form.get('confidential') else None
        client = OAuth2Client(
            client_id=client_id,
            client_secret_hash=bcrypt.generate_password_hash(client_secret).decode('utf-8') if client_secret else '',
            client_name=request.form.get('client_name'),
            redirect_uris=[uri.strip() for uri in request.form.get('redirect_uris', '').split('\n') if uri.strip()],
            allowed_scopes=request.form.getlist('scopes'),
            grant_types=['authorization_code', 'refresh_token'],
            is_confidential=bool(request.form.get('confidential')),
            is_active=True
        )
        db.session.add(client)
        db.session.commit()
        flash(f'Client créé. client_id : {client_id} / secret : {client_secret}', 'info')
        return redirect(url_for('admin.clients'))
    return render_template('admin/client_form.html')

@admin_bp.route('/audit-logs')
@admin_required
def audit_logs():
    page = request.args.get('page', 1, type=int)
    pagination = AuditLog.query.order_by(AuditLog.created_at.desc()).paginate(page=page, per_page=50)
    return render_template('admin/audit_logs.html', logs=pagination.items, pagination=pagination)