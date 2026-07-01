from flask import Blueprint, render_template, request, redirect, url_for, session, flash, current_app
from app.extensions import db, csrf, limiter, bcrypt
from app.models.user import User
from app.models.audit_log import (
    AuditLog,
    EVENT_2FA_ENABLED,
    EVENT_2FA_FAILURE,
    EVENT_BACKUP_CODE_USED,
)
from app.services.totp_service import TOTPService
import uuid

twofa_bp = Blueprint('twofa', __name__, url_prefix='/2fa')

@twofa_bp.route('/setup')
def setup():
    """Page de configuration 2FA (QR code et formulaire de vérification)."""
    if 'user_id' not in session:
        flash('Veuillez vous connecter d\'abord.', 'warning')
        return redirect(url_for('auth.login'))
    user = User.query.get(uuid.UUID(session['user_id']))
    if not user:
        session.clear()
        return redirect(url_for('auth.login'))
    if user.totp_enabled:
        flash('La 2FA est déjà activée pour ce compte.', 'info')
        return redirect(url_for('auth.profile'))
    # Générer un secret temporaire (non encore chiffré en BDD)
    secret = TOTPService.generate_secret()
    # Stocker en session (ou en cache Redis) le secret pour la validation
    session['totp_temp_secret'] = secret
    uri = TOTPService.get_totp_uri(secret, user.email, current_app.config['SSO_ISSUER'])
    qr_data_uri = TOTPService.get_qr_data_uri(uri)
    return render_template('2fa_enroll.html', qr_data_uri=qr_data_uri, secret=secret)

@twofa_bp.route('/enroll', methods=['POST'])
@limiter.limit("10 per minute")
def enroll():
    if 'user_id' not in session:
        flash('Session expirée.', 'danger')
        return redirect(url_for('auth.login'))
    user = User.query.get(uuid.UUID(session['user_id']))
    if not user or user.totp_enabled:
        flash('Action impossible.', 'danger')
        return redirect(url_for('auth.login'))
    code = request.form.get('code')
    secret = session.get('totp_temp_secret')
    if not secret or not TOTPService.verify_code(secret, code):
        flash('Code TOTP invalide.', 'danger')
        return redirect(url_for('twofa.setup'))
    # Activer 2FA
    aes_key = current_app.config['AES_ENCRYPTION_KEY']
    encrypted_secret = TOTPService.encrypt_secret(secret, aes_key)
    user.totp_secret = encrypted_secret
    user.totp_enabled = True
    # Générer et stocker les codes de secours hachés
    backup_codes = TOTPService.generate_backup_codes()
    hashed_backup = TOTPService.hash_backup_codes(backup_codes)
    user.backup_codes = hashed_backup
    AuditLog.log(
        event_type=EVENT_2FA_ENABLED,
        ip_address=request.remote_addr,
        user_id=user.id,
        user_agent=request.user_agent.string,
    )
    db.session.commit()
    # Afficher les codes de secours une seule fois
    session['backup_codes'] = backup_codes
    session.pop('totp_temp_secret', None)
    flash('2FA activée avec succès !', 'success')
    return redirect(url_for('twofa.show_backup_codes'))

@twofa_bp.route('/backup-codes')
def show_backup_codes():
    codes = session.pop('backup_codes', None)
    if not codes:
        flash('Aucun nouveau code de secours à afficher.', 'info')
        return redirect(url_for('auth.profile'))
    return render_template('backup_codes.html', codes=codes)

@twofa_bp.route('/verify', methods=['POST'])
def verify():
    """Vérifie le code TOTP pendant la connexion."""
    # Cette route sera appelée par le flux de login
    code = request.form.get('totp_code')
    backup = request.form.get('backup_code')
    user_id = session.get('pending_2fa_user')
    if not user_id:
        flash('Session invalide.', 'danger')
        return redirect(url_for('auth.login'))
    user = db.session.get(User, uuid.UUID(user_id))
    if not user:
        return redirect(url_for('auth.login'))
    if code:
        # Vérifier TOTP
        aes_key = current_app.config['AES_ENCRYPTION_KEY']
        secret = TOTPService.decrypt_secret(user.totp_secret, aes_key)
        if TOTPService.verify_code(secret, code):
            # Succès : finaliser la connexion
            return redirect(url_for('auth.finalize_login'))
        else:
            AuditLog.log(
                event_type=EVENT_2FA_FAILURE,
                ip_address=request.remote_addr,
                user_id=user.id,
                user_agent=request.user_agent.string,
                details={"method": "totp"},
            )
            db.session.commit()
            flash('Code TOTP invalide.', 'danger')
            return redirect(request.referrer or url_for('auth.login'))
    elif backup:
        # Vérifier backup code (haché)
        # Vérifier dans user.backup_codes (liste de hachages)
        for idx, hashed in enumerate(user.backup_codes or []):
            if bcrypt.check_password_hash(hashed, backup):
                # Supprimer ce code de secours utilisé
                del user.backup_codes[idx]
                AuditLog.log(
                    event_type=EVENT_BACKUP_CODE_USED,
                    ip_address=request.remote_addr,
                    user_id=user.id,
                    user_agent=request.user_agent.string,
                    details={"codes_remaining": len(user.backup_codes)},
                )
                db.session.commit()
                # Finaliser connexion
                return redirect(url_for('auth.finalize_login'))
        AuditLog.log(
            event_type=EVENT_2FA_FAILURE,
            ip_address=request.remote_addr,
            user_id=user.id,
            user_agent=request.user_agent.string,
            details={"method": "backup_code"},
        )
        db.session.commit()
        flash('Code de secours invalide.', 'danger')
        return redirect(request.referrer or url_for('auth.login'))
    flash('Veuillez fournir un code TOTP ou un code de secours.', 'danger')
    return redirect(request.referrer or url_for('auth.login'))

@twofa_bp.route('/verify-page')
def verify_page():
    """Affiche le formulaire de saisie du code TOTP."""
    if 'pending_2fa_user' not in session:
        return redirect(url_for('auth.login'))
    return render_template('2fa_verify.html')
