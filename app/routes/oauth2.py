import os
import time
import hashlib
import base64
import uuid
import urllib.request as _urlreq
from urllib.parse import urlencode, urljoin
from datetime import datetime, timedelta, timezone
from flask import Blueprint, request, redirect, render_template, session, current_app, jsonify, abort
from werkzeug.exceptions import BadRequest
from cryptography.hazmat.primitives import serialization
from app.extensions import db, bcrypt, limiter, get_redis, csrf
from app.models.user import User
from app.models.oauth2_client import OAuth2Client
from app.models.oauth2_code import OAuth2AuthorizationCode
from app.models.oauth2_token import OAuth2Token
from app.models.rs256_key import RS256Key
from app.models.oauth2_consent import OAuth2Consent
from app.models.audit_log import (
    AuditLog,
    EVENT_TOKEN_ISSUED,
    EVENT_TOKEN_REVOKED,
    EVENT_TOKEN_REFRESH,
    EVENT_CONSENT_GRANTED,
    EVENT_LOGOUT,
    EVENT_SLO_LOGOUT,
)
from app.services.key_service import KeyService
from app.services.session_service import create_user_session, delete_user_session
import jwt

oauth2_bp = Blueprint('oauth2', __name__)

# ----------------------------------------------------------------------
# Utilitaires JWT
# ----------------------------------------------------------------------
def _sign_jwt(payload: dict, expires_in: int, token_type: str = 'access') -> str:
    """Signe un JWT avec la clé RS256 active."""
    key = KeyService.get_active_key()
    private_key = KeyService.decrypt_private_key(key.private_key_encrypted, current_app.config['AES_ENCRYPTION_KEY'])
    now = datetime.now(timezone.utc)
    iat = int(now.timestamp())
    exp = iat + expires_in
    payload.update({
        'iss': current_app.config['SSO_ISSUER'],
        'iat': iat,
        'exp': exp,
        'jti': str(uuid.uuid4())
    })
    token = jwt.encode(payload, private_key, algorithm='RS256', headers={'kid': key.kid})
    return token

def _verify_bearer_token(token_str: str) -> dict:
    """Vérifie un access token JWT (signature, expiration, blacklist)."""
    try:
        # Récupérer l'en-tête pour obtenir le kid
        header = jwt.get_unverified_header(token_str)
        kid = header.get('kid')
        if not kid:
            raise jwt.InvalidTokenError('No kid in header')

        # Charger la clé publique correspondante
        key = RS256Key.query.filter_by(kid=kid).first()
        if not key:
            raise jwt.InvalidTokenError(f'Unknown kid: {kid}')

        public_key = serialization.load_pem_public_key(key.public_key_pem.encode())

        # Décoder et vérifier la signature
        payload = jwt.decode(
            token_str,
            public_key,
            algorithms=['RS256'],
            options={
             'require': ['exp', 'iat', 'jti'],
             'verify_aud': False
             }
        )

        # Vérifier la blacklist Redis
        redis = get_redis()
        if redis.exists(f'blacklist:{payload["jti"]}'):
            raise jwt.InvalidTokenError('Token revoked')

        return payload
    except jwt.InvalidTokenError as e:
        raise BadRequest(f'Invalid token: {str(e)}')

# ----------------------------------------------------------------------
# OpenID Connect Discovery
# ----------------------------------------------------------------------
@oauth2_bp.route('/.well-known/openid-configuration')
def openid_config():
    issuer = current_app.config['SSO_ISSUER']
    return jsonify({
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "userinfo_endpoint": f"{issuer}/userinfo",
        "jwks_uri": f"{issuer}/jwks.json",
        "revocation_endpoint": f"{issuer}/revoke",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]
    })

@oauth2_bp.route('/jwks.json')
def jwks():
    keys = RS256Key.query.filter(RS256Key.expires_at > datetime.now(timezone.utc)).all()
    jwks_keys = []
    for k in keys:
        public_key = serialization.load_pem_public_key(k.public_key_pem.encode())
        numbers = public_key.public_numbers()
        n = base64.urlsafe_b64encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, 'big')).decode().rstrip('=')
        e = base64.urlsafe_b64encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, 'big')).decode().rstrip('=')
        jwks_keys.append({
            "kty": "RSA",
            "use": "sig",
            "alg": k.algorithm,
            "kid": k.kid,
            "n": n,
            "e": e
        })
    return jsonify({"keys": jwks_keys})

# ----------------------------------------------------------------------
# /authorize (GET - formulaire de login/consent)
# ----------------------------------------------------------------------
@oauth2_bp.route('/authorize', methods=['GET', 'POST'])
@limiter.limit("50 per minute")
def authorize():
    # Récupération des paramètres OAuth2
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    response_type = request.args.get('response_type', '')
    scope = request.args.get('scope', '')
    state = request.args.get('state')
    nonce = request.args.get('nonce')
    code_challenge = request.args.get('code_challenge')
    code_challenge_method = request.args.get('code_challenge_method', '')
    prompt = request.args.get('prompt', '')
    max_age_param = request.args.get('max_age')
    if response_type != 'code':
        abort(400, description='response_type must be code')
    # Validation client
    client = OAuth2Client.query.filter_by(client_id=client_id, is_active=True).first()
    if not client or not client.has_redirect_uri(redirect_uri):
        abort(400, description='Invalid client or redirect_uri')
    if not client.has_scope(scope):
        abort(400, description='Requested scope not allowed')
    if code_challenge and code_challenge_method != 'S256':
        abort(400, description='Only S256 code_challenge_method is allowed')
    # PKCE obligatoire pour les clients publics (RFC 7636 §4.1)
    if not client.is_confidential and not code_challenge:
        abort(400, description='PKCE required for public clients')
    # ── prompt / max_age (OIDC Core §3.1.2.1) ────────────────────────────
    user_id = session.get('user_id')

    # prompt=login → forcer une re-authentification même si déjà connecté
    if prompt == 'login' and user_id:
        session.pop('user_id', None)
        session.pop('session_id', None)
        session.pop('session_created_at', None)
        session.pop('last_activity', None)
        user_id = None

    # prompt=none → ne pas interagir avec l'utilisateur, erreur si non connecté
    if prompt == 'none' and not user_id:
        err_params = {'error': 'login_required', 'error_description': 'User is not authenticated'}
        if state:
            err_params['state'] = state
        return redirect(f"{redirect_uri}?{urlencode(err_params)}")

    # max_age → si la session est plus ancienne que max_age secondes, forcer re-auth
    if max_age_param and user_id:
        try:
            max_age_s = int(max_age_param)
            session_start = session.get('session_created_at', 0)
            if time.time() - session_start > max_age_s:
                session.pop('user_id', None)
                session.pop('session_id', None)
                session.pop('session_created_at', None)
                session.pop('last_activity', None)
                user_id = None
        except (ValueError, TypeError):
            pass

    if not user_id:
        # Non connecté : afficher login
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            user = User.query.filter_by(email=email, is_active=True).first()
            if user and bcrypt.check_password_hash(user.password_hash, password) and not user.email_verified:
                return render_template(
                    'login.html',
                    error="Veuillez confirmer votre adresse e-mail avant de vous connecter",
                    **request.args,
                )
            if user and bcrypt.check_password_hash(user.password_hash, password):
                # Créer session Redis + timestamps IdP
                import time as _time
                session_id = create_user_session(user.id, request.remote_addr, request.user_agent.string)
                _now = _time.time()
                session['user_id'] = str(user.id)
                session['session_id'] = session_id
                session['session_created_at'] = _now
                session['last_activity'] = _now
                # Rediriger vers GET /authorize avec les mêmes params
                return redirect(request.url)
            else:
                return render_template('login.html', error='Email ou mot de passe incorrect', **request.args)
        return render_template('login.html', **request.args)
    # Utilisateur déjà connecté
    user = User.query.get(uuid.UUID(user_id))
    if not user:
        session.clear()
        return redirect(request.url)
    # Vérifier si un consentement actif couvre déjà les scopes demandés
    requested_scopes = list(set(scope.split()))
    consent = OAuth2Consent.query.filter_by(
        user_id=user.id, client_id=client.client_id
    ).first()
    needs_consent = (
        not consent
        or not consent.is_active()
        or not set(requested_scopes).issubset(set(consent.scopes or []))
    )
    if needs_consent:
        if request.method == 'POST' and request.form.get('step') == 'consent':
            if request.form.get('action') == 'deny':
                params = {'error': 'access_denied', 'error_description': "L'utilisateur a refusé l'accès"}
                if state:
                    params['state'] = state
                return redirect(f"{redirect_uri}?{urlencode(params)}")
            # action == 'authorize' → enregistrer et continuer ci-dessous
        else:
            # Afficher la page de consentement (GET ou POST login)
            _SCOPE_META = {
                'openid':  {'label': 'Identité',  'desc': 'Accéder à votre identifiant unique', 'icon': 'fa-fingerprint'},
                'email':   {'label': 'E-mail',    'desc': 'Lire votre adresse e-mail',          'icon': 'fa-envelope'},
                'profile': {'label': 'Profil',    'desc': 'Lire votre nom et identifiant',      'icon': 'fa-user'},
            }
            scopes_display = [
                {**_SCOPE_META.get(s, {'label': s, 'desc': f'Accéder à la ressource : {s}', 'icon': 'fa-key'}), 'scope': s}
                for s in requested_scopes
            ]
            return render_template(
                'consent.html',
                client=client,
                user=user,
                scopes_display=scopes_display,
            )
    # Enregistrer / mettre à jour le consentement (GDPR Article 7)
    if consent and consent.is_active():
        existing = set(consent.scopes or [])
        new_scopes = set(requested_scopes)
        if not new_scopes.issubset(existing):
            consent.scopes = list(existing | new_scopes)
            consent.granted_at = datetime.now(timezone.utc)
            db.session.flush()
            AuditLog.log(
                event_type=EVENT_CONSENT_GRANTED,
                ip_address=request.remote_addr,
                user_id=user.id,
                client_id=client.client_id,
                user_agent=request.user_agent.string,
                details={"scopes": list(new_scopes - existing), "action": "scope_expanded"},
            )
    else:
        consent = OAuth2Consent(
            user_id=user.id,
            client_id=client.client_id,
            scopes=requested_scopes,
        )
        db.session.add(consent)
        db.session.flush()
        AuditLog.log(
            event_type=EVENT_CONSENT_GRANTED,
            ip_address=request.remote_addr,
            user_id=user.id,
            client_id=client.client_id,
            user_agent=request.user_agent.string,
            details={"scopes": requested_scopes, "action": "new_consent"},
        )
    # Générer le code d'autorisation
    code = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')
    expires_in = current_app.config.get('AUTHORIZATION_CODE_EXPIRE_SECONDS', 300)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    auth_code = OAuth2AuthorizationCode(
        code=code,
        user_id=user.id,
        client_id=client.client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        nonce=nonce,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        expires_at=expires_at
    )
    db.session.add(auth_code)
    db.session.commit()
    # Redirection — state repris depuis l'enregistrement (pas directement depuis la requête)
    params = {'code': code}
    if auth_code.state:
        params['state'] = auth_code.state
    return redirect(f"{redirect_uri}?{urlencode(params)}")

# ----------------------------------------------------------------------
# /token
# ----------------------------------------------------------------------
@oauth2_bp.route('/token', methods=['POST'])
@csrf.exempt
@limiter.limit("100 per minute")
def token():
    # Authentification client (Basic ou POST)
    auth = request.authorization
    client_id = None
    client_secret = None
    if auth:
        client_id = auth.username
        client_secret = auth.password
    else:
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
    if not client_id:
        return jsonify({'error': 'invalid_client'}), 401
    client = OAuth2Client.query.filter_by(client_id=client_id, is_active=True).first()
    if not client:
        return jsonify({'error': 'invalid_client'}), 401
    if client.is_confidential:
        if not client_secret or not bcrypt.check_password_hash(client.client_secret_hash, client_secret):
            return jsonify({'error': 'invalid_client'}), 401
    grant_type = request.form.get('grant_type')
    if grant_type == 'authorization_code':
        code = request.form.get('code')
        redirect_uri = request.form.get('redirect_uri')
        code_verifier = request.form.get('code_verifier')
        auth_code = OAuth2AuthorizationCode.query.filter_by(code=code, client_id=client.client_id).first()
        if not auth_code or auth_code.is_expired() or auth_code.is_used():
            return jsonify({'error': 'invalid_grant'}), 400
        if auth_code.redirect_uri != redirect_uri:
            return jsonify({'error': 'invalid_grant'}), 400
        if auth_code.code_challenge:
            if not code_verifier:
                return jsonify({'error': 'invalid_grant'}), 400
            # RFC 7636 : 43 ≤ len(code_verifier) ≤ 128
            if not (43 <= len(code_verifier) <= 128):
                return jsonify({'error': 'invalid_grant'}), 400
            # Vérifier PKCE S256
            expected = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode().rstrip('=')
            if expected != auth_code.code_challenge:
                return jsonify({'error': 'invalid_grant'}), 400
        # Marquer code utilisé
        auth_code.used_at = datetime.now(timezone.utc)
        db.session.commit()
        # Générer tokens
        user = User.query.get(auth_code.user_id)
        if not user:
            return jsonify({'error': 'invalid_grant'}), 400
        # Access token JWT
        access_payload = {
            'sub': str(user.id),
            'aud': client.client_id,
            'scope': auth_code.scope,
            'email': user.email,
            'name': user.username,
            'is_admin': user.is_admin
        }
        access_token = _sign_jwt(access_payload, current_app.config['ACCESS_TOKEN_EXPIRE_SECONDS'], 'access')
        # Refresh token (opaque, stocké hashé)
        refresh_jti = str(uuid.uuid4())
        refresh_token_value = base64.urlsafe_b64encode(os.urandom(40)).decode().rstrip('=')
        refresh_hash = bcrypt.generate_password_hash(refresh_token_value).decode('utf-8')
        refresh_sha256 = hashlib.sha256(refresh_token_value.encode()).hexdigest()
        refresh_exp = datetime.now(timezone.utc) + timedelta(seconds=current_app.config['REFRESH_TOKEN_EXPIRE_SECONDS'])
        refresh_token = OAuth2Token(
            jti=refresh_jti,
            user_id=user.id,
            client_id=client.client_id,
            token_hash=refresh_hash,
            token_sha256=refresh_sha256,
            scope=auth_code.scope,
            access_token_jti=jwt.decode(access_token, options={'verify_signature': False})['jti'],
            issued_at=datetime.now(timezone.utc),
            expires_at=refresh_exp
        )
        db.session.add(refresh_token)
        AuditLog.log(
            event_type=EVENT_TOKEN_ISSUED,
            ip_address=request.remote_addr,
            user_id=user.id,
            client_id=client.client_id,
            user_agent=request.user_agent.string,
            details={"grant_type": "authorization_code", "scope": auth_code.scope},
        )
        db.session.commit()
        # id_token (OpenID)
        id_payload = {
            'sub': str(user.id),
            'email': user.email,
            'email_verified': True,
            'name': user.username,
            'preferred_username': user.username,
            'updated_at': int(user.updated_at.timestamp()) if user.updated_at else 0,
            'nonce': auth_code.nonce
        }
        id_token = _sign_jwt(id_payload, current_app.config['ACCESS_TOKEN_EXPIRE_SECONDS'], 'id')
        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': current_app.config['ACCESS_TOKEN_EXPIRE_SECONDS'],
            'refresh_token': refresh_token_value,
            'scope': auth_code.scope,
            'id_token': id_token
        })
    elif grant_type == 'refresh_token':
        refresh_token_value = request.form.get('refresh_token')
        if not refresh_token_value:
            return jsonify({'error': 'invalid_request'}), 400
        # Lookup O(1) par SHA256, puis vérification bcrypt sur l'unique candidat
        lookup_sha256 = hashlib.sha256(refresh_token_value.encode()).hexdigest()
        found = OAuth2Token.query.filter_by(
            client_id=client.client_id, token_sha256=lookup_sha256
        ).first()
        if found and not bcrypt.check_password_hash(found.token_hash, refresh_token_value):
            found = None
        if not found or not found.is_active():
            return jsonify({'error': 'invalid_grant'}), 400
        # Rotation : révoquer l'ancien et créer un nouveau
        found.revoked_at = datetime.now(timezone.utc)
        user = User.query.get(found.user_id)
        new_access_payload = {
            'sub': str(user.id),
            'aud': client.client_id,
            'scope': found.scope,
            'email': user.email,
            'name': user.username,
            'is_admin': user.is_admin
        }
        new_access_token = _sign_jwt(new_access_payload, current_app.config['ACCESS_TOKEN_EXPIRE_SECONDS'], 'access')
        new_refresh_jti = str(uuid.uuid4())
        new_refresh_value = base64.urlsafe_b64encode(os.urandom(40)).decode().rstrip('=')
        new_refresh_hash = bcrypt.generate_password_hash(new_refresh_value).decode('utf-8')
        new_refresh_sha256 = hashlib.sha256(new_refresh_value.encode()).hexdigest()
        new_refresh = OAuth2Token(
            jti=new_refresh_jti,
            user_id=user.id,
            client_id=client.client_id,
            token_hash=new_refresh_hash,
            token_sha256=new_refresh_sha256,
            scope=found.scope,
            access_token_jti=jwt.decode(new_access_token, options={'verify_signature': False})['jti'],
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=current_app.config['REFRESH_TOKEN_EXPIRE_SECONDS'])
        )
        db.session.add(new_refresh)
        AuditLog.log(
            event_type=EVENT_TOKEN_REFRESH,
            ip_address=request.remote_addr,
            user_id=user.id,
            client_id=client.client_id,
            user_agent=request.user_agent.string,
            details={"scope": found.scope},
        )
        db.session.commit()
        return jsonify({
            'access_token': new_access_token,
            'token_type': 'Bearer',
            'expires_in': current_app.config['ACCESS_TOKEN_EXPIRE_SECONDS'],
            'refresh_token': new_refresh_value,
            'scope': found.scope
        })
    else:
        return jsonify({'error': 'unsupported_grant_type'}), 400

# ----------------------------------------------------------------------
# /userinfo
# ----------------------------------------------------------------------
@oauth2_bp.route('/userinfo')
@limiter.limit("100 per minute")
def userinfo():
    auth = request.headers.get('Authorization')
    if not auth or not auth.startswith('Bearer '):
        return jsonify({'error': 'invalid_token'}), 401
    token = auth.split(' ')[1]
    try:
        payload = _verify_bearer_token(token)
    except BadRequest as e:
        return jsonify({'error': 'invalid_token', 'description': str(e)}), 400
    user = User.query.get(uuid.UUID(payload['sub']))
    if not user:
        return jsonify({'error': 'invalid_token'}), 401
    # OIDC Core §5.4 : retourner uniquement les claims correspondant aux scopes accordés
    scope_set = set(payload.get('scope', '').split())
    claims = {'sub': str(user.id)}
    if 'email' in scope_set:
        claims['email'] = user.email
        claims['email_verified'] = True
    if 'profile' in scope_set:
        claims['name'] = user.username
        claims['preferred_username'] = user.username
        claims['updated_at'] = int(user.updated_at.timestamp()) if user.updated_at else 0
    return jsonify(claims)

# ----------------------------------------------------------------------
# /revoke
# ----------------------------------------------------------------------
@oauth2_bp.route('/revoke', methods=['POST'])
def revoke():
    # Authentification client (Basic ou POST) similaire à /token
    auth = request.authorization
    client_id = None
    client_secret = None
    if auth:
        client_id = auth.username
        client_secret = auth.password
    else:
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
    if not client_id:
        return jsonify({}), 200  # RFC 7009 : toujours 200 même en cas d'erreur
    client = OAuth2Client.query.filter_by(client_id=client_id, is_active=True).first()
    if client and client.is_confidential:
        if not client_secret or not bcrypt.check_password_hash(client.client_secret_hash, client_secret):
            return jsonify({}), 200
    token = request.form.get('token')
    token_type_hint = request.form.get('token_type_hint', 'access_token')
    if token_type_hint in ('access_token', 'refresh_token'):
        if token_type_hint == 'access_token':
            try:
                payload = jwt.decode(token, options={'verify_signature': False})
                jti = payload.get('jti')
                if jti:
                    redis = get_redis()
                    # TTL = durée restante du token (pas hardcodé à 3600s)
                    now_ts = int(datetime.now(timezone.utc).timestamp())
                    ttl = max(payload.get('exp', now_ts) - now_ts, 1)
                    redis.setex(f'blacklist:{jti}', ttl, '1')
                    sub = payload.get('sub')
                    uid_for_log = uuid.UUID(sub) if sub else None
                    AuditLog.log(
                        event_type=EVENT_TOKEN_REVOKED,
                        ip_address=request.remote_addr,
                        user_id=uid_for_log,
                        client_id=client_id,
                        user_agent=request.user_agent.string,
                        details={"token_type": "access_token", "jti": jti},
                    )
                    db.session.commit()
            except (jwt.DecodeError, KeyError):
                pass
        else:  # refresh_token
            revoke_sha256 = hashlib.sha256(token.encode()).hexdigest()
            rt = OAuth2Token.query.filter_by(
                client_id=client.client_id, token_sha256=revoke_sha256
            ).first()
            if rt and bcrypt.check_password_hash(rt.token_hash, token):
                rt.revoked_at = datetime.now(timezone.utc)
                AuditLog.log(
                    event_type=EVENT_TOKEN_REVOKED,
                    ip_address=request.remote_addr,
                    user_id=rt.user_id,
                    client_id=client.client_id,
                    user_agent=request.user_agent.string,
                    details={"token_type": "refresh_token"},
                )
                db.session.commit()
    return jsonify({}), 200

# ----------------------------------------------------------------------
# /connect/end_session  (OIDC RP-Initiated Logout — RFC 9470 §4)
# ----------------------------------------------------------------------
@oauth2_bp.route('/connect/end_session', methods=['GET', 'POST'])
@csrf.exempt
@limiter.limit("30 per minute")
def end_session():
    """Point de déconnexion global (SLO — Single Log-Out).

    Paramètres OIDC reconnus :
      - id_token_hint        : JWT de l'ID token (optionnel, sert à identifier le client)
      - post_logout_redirect_uri : URI de retour après déconnexion
      - state                : repris dans la redirection finale
    """
    id_token_hint           = request.values.get('id_token_hint')
    post_logout_redirect_uri = request.values.get('post_logout_redirect_uri')
    state                   = request.values.get('state')

    user_id = session.get('user_id')
    user = None
    if user_id:
        try:
            user = User.query.get(uuid.UUID(user_id))
        except Exception:
            pass

    if user:
        # 1. Back-channel logout vers tous les clients actifs
        _broadcast_backchannel_logout(user)

        # 2. Révoquer tous les refresh tokens actifs
        now_utc = datetime.now(timezone.utc)
        OAuth2Token.query.filter(
            OAuth2Token.user_id == user.id,
            OAuth2Token.revoked_at.is_(None),
        ).update({'revoked_at': now_utc})
        db.session.commit()

        # 3. Supprimer la session Redis
        sid = session.get('session_id')
        if sid:
            try:
                delete_user_session(sid)
            except Exception:
                pass

        # 4. Audit
        AuditLog.log(
            event_type=EVENT_SLO_LOGOUT,
            ip_address=request.remote_addr,
            user_id=user.id,
            user_agent=request.user_agent.string,
            details={'id_token_hint_present': bool(id_token_hint)},
        )

    session.clear()

    # Validation de l'URI de retour : doit correspondre à une redirect_uri enregistrée
    if post_logout_redirect_uri and _is_valid_post_logout_uri(post_logout_redirect_uri):
        params = {}
        if state:
            params['state'] = state
        dest = post_logout_redirect_uri
        if params:
            dest += ('&' if '?' in dest else '?') + urlencode(params)
        return redirect(dest)

    # Pas d'URI fournie ou invalide : page de confirmation de déconnexion
    return render_template('logged_out.html')


def _broadcast_backchannel_logout(user: 'User') -> None:
    """Envoie un logout token (JWT signé) à chaque client ayant une session active.

    Best-effort : les erreurs réseau ne font pas échouer la déconnexion.
    Conforme à OIDC Back-Channel Logout 1.0 §2.4.
    """
    active_tokens = OAuth2Token.query.filter(
        OAuth2Token.user_id == user.id,
        OAuth2Token.revoked_at.is_(None),
    ).all()
    notified_clients: set = set()
    sid = session.get('session_id', str(uuid.uuid4()))

    for token in active_tokens:
        if token.client_id in notified_clients:
            continue
        client = OAuth2Client.query.filter_by(client_id=token.client_id).first()
        if not client or not client.backchannel_logout_uri:
            notified_clients.add(token.client_id)
            continue
        notified_clients.add(token.client_id)
        try:
            logout_token = _sign_jwt(
                {
                    'sub': str(user.id),
                    'aud': client.client_id,
                    'sid': sid,
                    'events': {
                        'http://schemas.openid.net/event/backchannel-logout': {}
                    },
                },
                expires_in=60,
            )
            body = urlencode({'logout_token': logout_token}).encode()
            req = _urlreq.Request(
                client.backchannel_logout_uri,
                data=body,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                method='POST',
            )
            _urlreq.urlopen(req, timeout=5)
        except Exception:
            pass  # Best-effort, ne pas bloquer la déconnexion


def _is_valid_post_logout_uri(uri: str) -> bool:
    """Valide qu'une URI de retour est enregistrée chez au moins un client actif."""
    if not uri:
        return False
    norm = OAuth2Client._normalize_uri(uri)
    for client in OAuth2Client.query.filter_by(is_active=True).all():
        for r in (client.redirect_uris or []):
            if OAuth2Client._normalize_uri(r) == norm:
                return True
    return False


@oauth2_bp.route('/callback')
def debug_callback():
    """Route temporaire pour afficher le code d'autorisation lors des tests."""
    code = request.args.get('code')
    state = request.args.get('state')
    return f"<h1>Code d'autorisation</h1><p><strong>code:</strong> {code}</p><p><strong>state:</strong> {state}</p><p>Copiez ce code pour l'échanger contre des tokens.</p>"
