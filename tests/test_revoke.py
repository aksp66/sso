import hashlib
import jwt
from datetime import datetime, timezone, timedelta
from app.extensions import bcrypt

def test_revoke_access_token(client, test_user, test_client, app):
    with app.app_context():
        from app.extensions import get_redis
        get_redis().delete('blacklist:test-jti-123')

        from app.services.key_service import KeyService
        key = KeyService.get_active_key()
        private_key = KeyService.decrypt_private_key(key.private_key_encrypted, app.config['AES_ENCRYPTION_KEY'])
        payload = {
            'sub': str(test_user.id),
            'aud': test_client.client_id,
            'scope': 'openid email',
            'jti': 'test-jti-123',
            'iat': int(datetime.now(timezone.utc).timestamp()),
            'exp': int((datetime.now(timezone.utc) + timedelta(seconds=3600)).timestamp())
        }
        token = jwt.encode(payload, private_key, algorithm='RS256', headers={'kid': key.kid})

        resp = client.get('/userinfo', headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200

        # Révocation
        revoke_resp = client.post('/revoke', data={
            'token': token,
            'token_type_hint': 'access_token'
        }, headers={'Authorization': 'Basic dGVzdF9jbGllbnQ6c2VjcmV0'})
        assert revoke_resp.status_code == 200

        from app.extensions import get_redis
        redis = get_redis()
        assert redis.exists('blacklist:test-jti-123') == 1

        # Utiliser le token révoqué
        resp2 = client.get('/userinfo', headers={'Authorization': f'Bearer {token}'})
        assert resp2.status_code == 400
        assert 'invalid_token' in resp2.get_json().get('error')

def test_revoke_refresh_token(client, test_user, test_client, db, app):
    from app.models.oauth2_token import OAuth2Token
    import uuid

    refresh_token_value = "test-refresh-123"
    refresh_hash = bcrypt.generate_password_hash(refresh_token_value).decode('utf-8')
    refresh_sha256 = hashlib.sha256(refresh_token_value.encode()).hexdigest()
    rt = OAuth2Token(
        jti=str(uuid.uuid4()),
        user_id=test_user.id,
        client_id=test_client.client_id,
        token_hash=refresh_hash,
        token_sha256=refresh_sha256,
        scope="openid email",
        access_token_jti="test-at-jti",
        expires_at=datetime.now(timezone.utc) + timedelta(days=30)
    )
    db.session.add(rt)
    db.session.commit()

    # Tenter d'utiliser le refresh token révoqué
    revoke_resp = client.post('/revoke', data={
        'token': refresh_token_value,
        'token_type_hint': 'refresh_token'
    }, headers={'Authorization': 'Basic dGVzdF9jbGllbnQ6c2VjcmV0'})
    assert revoke_resp.status_code == 200

    db.session.refresh(rt)
    assert rt.revoked_at is not None

    token_resp = client.post('/token', data={
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token_value
    }, headers={'Authorization': 'Basic dGVzdF9jbGllbnQ6c2VjcmV0'})
    assert token_resp.status_code == 400
    assert 'invalid_grant' in token_resp.get_json().get('error')
