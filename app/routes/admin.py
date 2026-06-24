from datetime import datetime, timezone
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, current_app
from app.extensions import db, limiter
from app.models.user import User
from app.models.oauth2_client import OAuth2Client
from app.models.client_request import ClientRequest, STATUS_PENDING, STATUS_APPROVED, STATUS_REJECTED
from app.models.audit_log import AuditLog, EVENT_CLIENT_REGISTERED
from app.services.totp_service import TOTPService  # pour reset 2FA
from app.services.email_service import send_client_credentials_email, send_client_request_rejected_email
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

@admin_bp.route('/client-requests')
@admin_required
def client_requests():
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', STATUS_PENDING)
    query = ClientRequest.query
    if status_filter in (STATUS_PENDING, STATUS_APPROVED, STATUS_REJECTED):
        query = query.filter_by(status=status_filter)
    pagination = query.order_by(ClientRequest.submitted_at.desc()).paginate(page=page, per_page=20)
    return render_template(
        'admin/client_requests.html',
        requests=pagination.items,
        pagination=pagination,
        status_filter=status_filter,
    )


@admin_bp.route('/client-requests/<uuid:request_id>/approve', methods=['POST'])
@admin_required
def approve_client_request(request_id):
    from app.extensions import bcrypt
    import secrets

    req = ClientRequest.query.get_or_404(request_id)
    if not req.is_pending():
        flash('Cette demande a déjà été traitée.', 'danger')
        return redirect(url_for('admin.client_requests'))

    client_id = secrets.token_urlsafe(16)
    client_secret = secrets.token_urlsafe(32) if req.is_confidential else None
    client = OAuth2Client(
        client_id=client_id,
        client_secret_hash=bcrypt.generate_password_hash(client_secret).decode('utf-8') if client_secret else '',
        client_name=req.client_name,
        redirect_uris=req.redirect_uris,
        allowed_scopes=req.requested_scopes,
        grant_types=['authorization_code', 'refresh_token'],
        is_confidential=req.is_confidential,
        is_active=True,
    )
    db.session.add(client)

    req.status = STATUS_APPROVED
    req.reviewed_at = datetime.now(timezone.utc)
    req.reviewed_by = uuid.UUID(session['user_id'])
    req.created_client_id = client_id

    AuditLog.log(
        event_type=EVENT_CLIENT_REGISTERED,
        ip_address=request.remote_addr,
        user_id=req.reviewed_by,
        client_id=client_id,
        user_agent=request.user_agent.string,
        details={'source': 'self_service_request', 'request_id': str(req.id)},
    )
    db.session.commit()

    try:
        send_client_credentials_email(req.contact_email, req.client_name, client_id, client_secret)
        flash(f'Client « {req.client_name} » créé et identifiants envoyés par e-mail.', 'success')
    except Exception as exc:
        current_app.logger.error(f"Envoi email credentials échoué pour {req.contact_email}: {exc}")
        flash(
            f'Client créé (client_id : {client_id}) mais l\'envoi de l\'e-mail a échoué — '
            f'transmettez les identifiants manuellement.',
            'warning',
        )
    return redirect(url_for('admin.client_requests'))


@admin_bp.route('/client-requests/<uuid:request_id>/reject', methods=['POST'])
@admin_required
def reject_client_request(request_id):
    req = ClientRequest.query.get_or_404(request_id)
    if not req.is_pending():
        flash('Cette demande a déjà été traitée.', 'danger')
        return redirect(url_for('admin.client_requests'))

    reason = request.form.get('reason', '').strip() or None
    req.status = STATUS_REJECTED
    req.reviewed_at = datetime.now(timezone.utc)
    req.reviewed_by = uuid.UUID(session['user_id'])
    req.rejection_reason = reason
    db.session.commit()

    try:
        send_client_request_rejected_email(req.contact_email, req.client_name, reason)
    except Exception as exc:
        current_app.logger.error(f"Envoi email refus échoué pour {req.contact_email}: {exc}")

    flash(f'Demande « {req.client_name} » refusée.', 'info')
    return redirect(url_for('admin.client_requests'))


@admin_bp.route('/audit-logs')
@admin_required
def audit_logs():
    page = request.args.get('page', 1, type=int)
    pagination = AuditLog.query.order_by(AuditLog.created_at.desc()).paginate(page=page, per_page=50)
    return render_template('admin/audit_logs.html', logs=pagination.items, pagination=pagination)