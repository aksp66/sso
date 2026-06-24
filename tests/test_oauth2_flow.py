import hashlib
import base64
import pytest
from flask import session

def test_authorize_redirect_to_login(client, test_client):
    resp = client.get('/authorize?response_type=code&client_id=test_client&redirect_uri=http://localhost/callback&scope=openid%20email')
    assert resp.status_code == 200
    # Le template login contient soit "Connexion" soit "Authentification SSO"
    assert b'Connexion' in resp.data or b'Authentification' in resp.data

def test_login_and_authorize(client, test_user, test_client):
    with client:
        # Connexion
        login_resp = client.post('/login', data={
            'email': test_user.email,
            'password': 'password123'
        }, follow_redirects=True)
        assert b'Mon profil' in login_resp.data  # session active

        code_verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
        code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode().rstrip('=')

        authorize_url = (
            f'/authorize?response_type=code&client_id=test_client'
            f'&redirect_uri=http://localhost/callback&scope=openid%20email'
            f'&code_challenge={code_challenge}&code_challenge_method=S256&state=xyz'
        )

        # Première visite : page de consentement
        resp2 = client.get(authorize_url)
        assert resp2.status_code == 200
        assert b'Autoriser' in resp2.data

        # L'utilisateur clique "Autoriser"
        resp2b = client.post(authorize_url, data={'step': 'consent', 'action': 'authorize'})
        assert resp2b.status_code == 302  # redirection vers callback avec code
        location = resp2b.headers['Location']
        assert 'code=' in location

        from urllib.parse import urlparse, parse_qs
        qs = parse_qs(urlparse(location).query)
        auth_code = qs['code'][0]

        # Échange token
        resp3 = client.post('/token', data={
            'grant_type': 'authorization_code',
            'code': auth_code,
            'redirect_uri': 'http://localhost/callback',
            'code_verifier': code_verifier
        }, headers={'Authorization': 'Basic dGVzdF9jbGllbnQ6c2VjcmV0'})
        assert resp3.status_code == 200
        json_data = resp3.get_json()
        assert 'access_token' in json_data

        # Userinfo
        access_token = json_data['access_token']
        resp4 = client.get('/userinfo', headers={'Authorization': f'Bearer {access_token}'})
        assert resp4.status_code == 200
        userinfo = resp4.get_json()
        assert userinfo['sub'] == str(test_user.id)
