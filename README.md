# Nexus — SSO OAuth2 / OpenID Connect

Serveur d'authentification unique (Single Sign-On) conforme OAuth 2.0, OpenID Connect et PKCE, développé en Flask 3.x avec PostgreSQL, Redis et RS256 JWT.

**Auteurs :** AKSP, KOYE Leleda Mabelle
**Superviseur :** M. TCHAYE (<tchaye59@gmail.com>)
**Lieu / date :** Sanguéra, Togo — Juin 2026

---

## Sommaire

1. [Architecture](#architecture)
2. [Prérequis](#prérequis)
3. [Démarrage rapide (Docker)](#démarrage-rapide-docker)
4. [Développement local](#développement-local)
5. [Variables d'environnement](#variables-denvironnement)
6. [Référence API](#référence-api)
7. [Flux d'authentification](#flux-dauthentification)
8. [Sécurité](#sécurité)
9. [Administration](#administration)
10. [Tests](#tests)
11. [Déploiement en production](#déploiement-en-production)
12. [Monitoring](#monitoring)

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                     Client (navigateur)                  │
└───────────────────────────┬──────────────────────────────┘
                            │ HTTPS
┌───────────────────────────▼──────────────────────────────┐
│                   Flask 3.x (Gunicorn)                   │
│                                                          │
│  /authorize  /token  /userinfo  /revoke  /jwks.json      │
│  /.well-known/openid-configuration  /health              │
│  /login  /2fa/*  /admin/*  /profile                      │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ Auth routes  │  │ OAuth2 routes│  │  Admin routes  │  │
│  └──────┬───────┘  └──────┬───────┘  └───────┬────────┘  │
│         │                 │                  │           │
│  ┌──────▼─────────────────▼──────────────────▼────────┐  │
│  │              Services (KeyService, TOTPService,     │  │
│  │               EmailService, SessionService)         │  │
│  └──────────────────────────┬─────────────────────────┘  │
└─────────────────────────────┼────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
       PostgreSQL 17      Redis 7.4      (SMTP)
       - users           - sessions     - reset pwd
       - oauth2_*        - blacklist    - alertes
       - audit_logs      - rate limit
       - rs256_keys      - pwd_reset
```

### Composants principaux

| Composant | Rôle |
|---|---|
| `app/routes/auth.py` | Login, logout, profil, reset mot de passe |
| `app/routes/oauth2.py` | Flux OAuth2 : `/authorize`, `/token`, `/userinfo`, `/revoke`, `/jwks.json` |
| `app/routes/twofa.py` | Enrollment TOTP, vérification, codes de secours |
| `app/routes/admin.py` | CRUD utilisateurs, clients OAuth2, journal d'audit |
| `app/routes/health.py` | `/health` et `/` |
| `app/services/key_service.py` | Génération / rotation RS256, chiffrement AES-256-GCM |
| `app/services/totp_service.py` | TOTP RFC 6238, QR code, backup codes bcrypt |
| `app/services/email_service.py` | Envoi SMTP (reset mot de passe) |
| `app/models/` | SQLAlchemy 2.0 : User, OAuth2Client, OAuth2Token, AuditLog, RS256Key, OAuth2Consent |

---

## Prérequis

- Docker ≥ 24 et Docker Compose v2
- Python 3.12+ (développement local uniquement)
- Un serveur SMTP (reset mot de passe)

---

## Démarrage rapide (Docker)

```bash
# 1. Cloner et configurer
git clone <repo>
cd sso-project
cp .env.example .env          # Remplir les variables (voir section Variables)

# 2. Générer les clés de sécurité
python -c "import secrets, base64; print('SECRET_KEY=' + secrets.token_hex(32))"
python -c "import secrets, base64; print('AES_ENCRYPTION_KEY=' + base64.b64encode(secrets.token_bytes(32)).decode())"

# 3. Lancer
docker compose up --build

# 4. Migrations (premier démarrage — l'entrypoint les exécute automatiquement)
# Si nécessaire manuellement :
docker compose exec web flask db upgrade

# 5. Créer un compte administrateur
docker compose exec web python -c "
from app import create_app
from app.extensions import db, bcrypt
from app.models.user import User
app = create_app()
with app.app_context():
    u = User(username='admin', email='admin@example.com',
             password_hash=bcrypt.generate_password_hash('ChangeMe123!').decode(),
             is_admin=True, is_active=True)
    db.session.add(u)
    db.session.commit()
    print('Admin créé')
"
```

L'application est disponible sur **<http://localhost:8000>**.

---

## Développement local

```bash
python -m venv .venv
source .venv/bin/activate        # Windows : .venv\Scripts\activate
pip install -r requirements.txt

# PostgreSQL et Redis doivent tourner (via Docker ou en natif)
export DATABASE_URL=postgresql://sso_user:sso_pass@localhost:5432/sso_db
export REDIS_URL=redis://localhost:6379/0
export FLASK_APP=wsgi:app
export FLASK_ENV=development

flask db upgrade
flask run --port 8000
```

---

## Variables d'environnement

| Variable | Obligatoire en prod | Description | Exemple |
|---|---|---|---|
| `SECRET_KEY` | ✅ | Clé de signature des sessions Flask | `secrets.token_hex(32)` |
| `AES_ENCRYPTION_KEY` | ✅ | Clé AES-256-GCM (32 octets, base64) | voir commande ci-dessus |
| `DATABASE_URL` | ✅ | URI PostgreSQL | `postgresql://user:pass@host/db` |
| `REDIS_URL` | ✅ | URI Redis | `redis://localhost:6379/0` |
| `SSO_ISSUER` | ✅ | URL publique du SSO (dans les JWT) | `https://sso.example.com` |
| `FLASK_ENV` | — | `production` / `development` / `testing` | `production` |
| `SMTP_HOST` | — | Hôte SMTP (reset mot de passe) | `smtp.sendgrid.net` |
| `SMTP_PORT` | — | Port SMTP | `587` |
| `SMTP_USER` | — | Identifiant SMTP | `apikey` |
| `SMTP_PASS` | — | Mot de passe SMTP | `SG.xxx` |
| `SMTP_FROM` | — | Adresse d'expédition | `no-reply@sso.example.com` |
| `BCRYPT_LOG_ROUNDS` | — | Coût bcrypt (défaut : 12) | `12` |
| `ACCESS_TOKEN_EXPIRE_SECONDS` | — | Durée de vie access token (défaut : 3600) | `3600` |
| `REFRESH_TOKEN_EXPIRE_SECONDS` | — | Durée de vie refresh token (défaut : 30 jours) | `2592000` |

> **Production :** `SECRET_KEY` et `AES_ENCRYPTION_KEY` doivent être définies. L'application lève une `RuntimeError` au démarrage sinon.

---

## Référence API

### Discovery

#### `GET /.well-known/openid-configuration`

Métadonnées OpenID Connect (issuer, endpoints, algorithmes supportés).

```json
{
  "issuer": "https://sso.example.com",
  "authorization_endpoint": "https://sso.example.com/authorize",
  "token_endpoint": "https://sso.example.com/token",
  "userinfo_endpoint": "https://sso.example.com/userinfo",
  "jwks_uri": "https://sso.example.com/jwks.json",
  "revocation_endpoint": "https://sso.example.com/revoke",
  "response_types_supported": ["code"],
  "id_token_signing_alg_values_supported": ["RS256"]
}
```

#### `GET /jwks.json`

Clés publiques RS256 actives au format JWK Set.

---

### Autorisation

#### `GET /authorize`

| Paramètre | Requis | Description |
|---|---|---|
| `response_type` | ✅ | Doit être `code` |
| `client_id` | ✅ | Identifiant du client OAuth2 |
| `redirect_uri` | ✅ | URI de redirection enregistrée |
| `scope` | ✅ | Scopes demandés (`openid`, `email`, `profile`) |
| `state` | Recommandé | Valeur aléatoire (protection CSRF, RFC 6749 §10.12) |
| `code_challenge` | Requis pour clients publics | Hash PKCE SHA-256 (RFC 7636) |
| `code_challenge_method` | Si PKCE | Doit être `S256` |
| `nonce` | — | Protection replay pour l'ID token |

**Réponse (succès) :** redirection vers `redirect_uri?code=<code>&state=<state>`  
**Réponse (refus) :** redirection vers `redirect_uri?error=access_denied`

---

### Token

#### `POST /token`

Authentification client : `Authorization: Basic base64(client_id:client_secret)` ou paramètres POST.

**Grant `authorization_code` :**

```
grant_type=authorization_code
&code=<code>
&redirect_uri=<uri>
&code_verifier=<verifier>   # Requis si PKCE utilisé
```

**Grant `refresh_token` :**

```
grant_type=refresh_token
&refresh_token=<token>
```

**Réponse 200 :**

```json
{
  "access_token": "<JWT RS256>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "<opaque>",
  "scope": "openid email",
  "id_token": "<JWT RS256>"
}
```

---

### UserInfo

#### `GET /userinfo`

```
Authorization: Bearer <access_token>
```

**Réponse 200 (claims filtrés par scope) :**

```json
{
  "sub": "uuid-utilisateur",
  "email": "user@example.com",
  "email_verified": true,
  "name": "Alice",
  "preferred_username": "alice"
}
```

**Erreurs :**

- `400` — token invalide, expiré ou révoqué
- `401` — header Authorization absent

---

### Révocation

#### `POST /revoke`

Révocation RFC 7009 — retourne toujours `200` (même si le token est inconnu).

```
token=<valeur>
&token_type_hint=access_token|refresh_token
```

---

### Santé

#### `GET /health`

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "components": {
    "database": { "status": "up", "latency_ms": 3.2 },
    "redis":    { "status": "up", "latency_ms": 0.8 },
    "rs256_key": { "status": "active", "kid": "...", "expires_in_days": 47 }
  },
  "timestamp": "2026-06-16T10:00:00+00:00"
}
```

HTTP 200 si tous les composants sont opérationnels, 503 sinon.

---

## Flux d'authentification

### Flux complet (Authorization Code + PKCE)

```
Application          Navigateur           SSO Server
    │                    │                    │
    │── 1. Générer ──────►│                    │
    │   code_verifier     │                    │
    │   code_challenge    │                    │
    │                    │─── GET /authorize ──►│
    │                    │    + code_challenge  │
    │                    │◄── Page de login ───│
    │                    │─── POST login ──────►│
    │                    │◄── Page consentement│
    │                    │─── POST authorize ──►│
    │                    │◄── 302 ?code= ──────│
    │◄── 2. code ────────│                    │
    │─── 3. POST /token ──────────────────────►│
    │       + code_verifier                   │
    │◄────── access_token + refresh_token ────│
    │─── 4. GET /userinfo ────────────────────►│
    │◄────── claims ──────────────────────────│
```

### Flux avec 2FA

Après validation du mot de passe, si `totp_enabled = true` :

1. `session['pending_2fa_user']` est positionné
2. Redirection vers `/2fa/verify` (onglets : code TOTP / code de secours)
3. Après vérification → `/finalize-login` → session active

---

## Sécurité

### Mesures implémentées

| Domaine | Mécanisme |
|---|---|
| Mots de passe | bcrypt (coût 12) |
| Secrets TOTP | AES-256-GCM (clé depuis `AES_ENCRYPTION_KEY`) |
| Sessions | Redis, ID = `secrets.token_urlsafe(32)` |
| JWT | RS256, rotation 90 jours, blacklist Redis (JTI) |
| Refresh tokens | bcrypt hash + SHA-256 index O(1) |
| Brute-force | Lockout après 10 échecs, durée 15 min |
| Rate limiting | Flask-Limiter (Redis backend) |
| CSRF | Flask-WTF (tous les formulaires) |
| PKCE | Obligatoire pour clients publics (S256 uniquement) |
| Consentement | Table `oauth2_consents` (RGPD Art. 7) |
| Headers HTTP | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| Audit | Table `audit_logs` — tous les événements de sécurité |
| URI redirect | Normalisation `urlparse` (évite les contournements) |

### Journal d'audit

Les événements suivants sont automatiquement enregistrés dans `audit_logs` :

`login_success`, `login_failure`, `account_locked`, `logout`, `2fa_enabled`, `2fa_failure`, `backup_code_used`, `token_issued`, `token_refresh`, `token_revoked`, `consent_granted`, `password_reset`

---

## Administration

Accès : `/admin` — réservé aux utilisateurs `is_admin = true` avec 2FA obligatoirement activée.

| Route | Description |
|---|---|
| `GET /admin/users` | Liste paginée des utilisateurs |
| `GET/POST /admin/users/<id>/edit` | Modifier un compte (rôle, statut) |
| `POST /admin/users/<id>/reset-2fa` | Réinitialiser la 2FA d'un utilisateur |
| `GET /admin/clients` | Liste des clients OAuth2 |
| `GET/POST /admin/clients/new` | Enregistrer un nouveau client |
| `GET /admin/audit-logs` | Journal d'audit paginé |

---

## Tests

```bash
# Lancer tous les tests
pytest tests/ -v

# Avec couverture
pip install pytest-cov
pytest tests/ -v --cov=app --cov-report=term-missing
```

**Suite de tests (17 tests) :**

| Fichier | Couverture |
|---|---|
| `test_2fa.py` | Service TOTP, enrollment, vérification |
| `test_key_rotation.py` | Génération RS256, rotation, JWKS, chiffrement |
| `test_oauth2_flow.py` | Flux complet avec PKCE et consentement |
| `test_revoke.py` | Révocation access token (Redis) et refresh token (DB) |

La configuration `TestingConfig` désactive le rate limiting Redis (`RATELIMIT_ENABLED = False`) et utilise `NullPool` pour éviter les fuites de connexions entre les tests.

---

## Déploiement en production

### Docker Compose (recommandé)

```bash
# Variables obligatoires dans .env
SECRET_KEY=<token_hex(32)>
AES_ENCRYPTION_KEY=<base64(token_bytes(32))>
SSO_ISSUER=https://sso.example.com
FLASK_ENV=production
DATABASE_URL=postgresql://...
REDIS_URL=redis://...

docker compose up -d
```

### Render (hébergement gratuit)

Render déploie directement le `Dockerfile` existant comme un service web qui reste actif en continu
(contrairement à un hébergeur serverless comme Vercel, incompatible avec notre planificateur
APScheduler). Sur Render, **aucun Nginx n'est nécessaire** : la plateforme gère elle-même le TLS et
la terminaison HTTPS en façade — passez directement à la section suivante si vous déployez ailleurs
(VPS) et avez besoin d'un reverse proxy.

**1. Créer les services sur [render.com](https://render.com) :**

| Étape | Type Render | Nom suggéré |
|---|---|---|
| 1 | New → PostgreSQL | `nexus-db` |
| 2 | New → Key Value (Redis) | `nexus-redis` |
| 3 | New → Web Service → connecter le dépôt GitHub, runtime **Docker** | `nexus-web` |

**2. Variables d'environnement à définir sur le Web Service :**

| Variable | Valeur |
|---|---|
| `FLASK_ENV` | `production` |
| `SECRET_KEY` | `python -c "import secrets; print(secrets.token_hex(32))"` |
| `AES_ENCRYPTION_KEY` | `python -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"` |
| `DATABASE_URL` | Internal Database URL fournie par `nexus-db` (onglet *Connect*) |
| `REDIS_URL` | Internal connection string fournie par `nexus-redis` |
| `SSO_ISSUER` | URL publique attribuée par Render, ex. `https://nexus-web.onrender.com` |
| `BCRYPT_LOG_ROUNDS` | `12` |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASS` / `SMTP_FROM` | Identifiants de votre fournisseur SMTP |

> `DATABASE_URL` peut être fournie par Render au format `postgres://...` — `config.py` corrige
> automatiquement ce schéma en `postgresql://...`, requis par SQLAlchemy 2.0.

**3. Limites du palier gratuit, en toute transparence :**

- Le service web s'endort après une période d'inactivité et met quelques dizaines de secondes à se
  réveiller à la requête suivante.
- Pendant cette mise en veille, le planificateur APScheduler (rotation des clés RS256) ne tourne pas.
  `KeyService.get_active_key()` régénère malgré tout une clé à la demande si l'active a expiré, donc
  le service reste fonctionnel, mais sans rotation proactive pendant le sommeil. Pour une rotation
  fiable indépendante du sommeil du service web, créer un *Cron Job* Render séparé qui appelle
  périodiquement un endpoint déclenchant `KeyService.rotate_if_needed()`.
- La base PostgreSQL gratuite est généralement limitée en durée ou en volume — vérifier les
  conditions actuelles sur le tableau de bord au moment du déploiement.

### Nginx (reverse proxy — déploiement VPS auto-hébergé)

Exemple minimal de configuration :

```nginx
server {
    listen 443 ssl http2;
    server_name sso.example.com;

    ssl_certificate     /etc/ssl/certs/sso.crt;
    ssl_certificate_key /etc/ssl/private/sso.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;

    location / {
        proxy_pass         http://127.0.0.1:8000;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

### Scaling

Pour plusieurs instances, assurez-vous que :

- `DATABASE_URL` pointe vers le même PostgreSQL
- `REDIS_URL` pointe vers le même Redis (sessions, blacklist, rate limiting)
- `AES_ENCRYPTION_KEY` et `SECRET_KEY` sont identiques sur toutes les instances

---

## Monitoring

### Endpoint de santé

```bash
curl https://sso.example.com/health
```

Utilisable comme probe Kubernetes :

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8000
  initialDelaySeconds: 10
  periodSeconds: 30
readinessProbe:
  httpGet:
    path: /health
    port: 8000
```

### Docker healthcheck

Le `docker-compose.yml` inclut des healthchecks sur PostgreSQL et Redis. La dépendance `depends_on: condition: service_healthy` garantit que Flask ne démarre pas avant que les services soient prêts.

### Logs

Les logs applicatifs sont émis sur `stdout` (format Gunicorn). En production, redirigez vers un agrégateur (Loki, ELK) :

```bash
docker compose logs -f web
```

### Journal d'audit

Les événements de sécurité sont consultables dans l'interface admin (`/admin/audit-logs`) et directement en base :

```sql
SELECT event_type, ip_address, created_at
FROM audit_logs
ORDER BY created_at DESC
LIMIT 100;
```
