# Rapport de conformité RFC — Nexus (SSO OAuth2 / OpenID Connect)

**Version :** 1.0  
**Date :** 2026-06-16  
**Périmètre :** Sprints 1–8

---

## Sommaire

| RFC / Spec | Titre | Statut |
|---|---|---|
| RFC 6749 | OAuth 2.0 Authorization Framework | ✅ Conforme |
| RFC 7636 | PKCE for OAuth 2.0 | ✅ Conforme |
| RFC 7009 | OAuth 2.0 Token Revocation | ✅ Conforme |
| RFC 7519 | JSON Web Token (JWT) | ✅ Conforme |
| RFC 7517 | JSON Web Key (JWK) | ✅ Conforme |
| RFC 7518 | JSON Web Algorithms (JWA) | ✅ Conforme (RS256) |
| OpenID Connect Core 1.0 | OIDC | ✅ Conforme (partiel) |
| RFC 6238 | TOTP | ✅ Conforme |
| RFC 5321 | SMTP | ✅ Conforme |
| RFC 9207 | OAuth 2.0 `iss` parameter | ⚠️ Partiel |

---

## RFC 6749 — OAuth 2.0 Authorization Framework

### §4.1 — Authorization Code Grant

| Exigence | Statut | Référence code |
|---|---|---|
| Le paramètre `response_type=code` est validé | ✅ | `oauth2.py:132` |
| `client_id` est vérifié en base | ✅ | `oauth2.py:135` |
| `redirect_uri` est validé par rapport à la liste enregistrée | ✅ | `oauth2_client.py:has_redirect_uri()` |
| `scope` est validé par rapport aux scopes autorisés | ✅ | `oauth2.py:138` |
| Le `state` est conservé et retourné dans la réponse | ✅ | `oauth2_code.py:state`, `oauth2.py:208` |
| Le code d'autorisation est à usage unique | ✅ | `oauth2_code.used_at` — vérifié à l'échange |
| Le code expire après 5 minutes | ✅ | `AUTHORIZATION_CODE_EXPIRE_SECONDS=300` |
| Le code est lié à `client_id` et `redirect_uri` | ✅ | `oauth2.py:244–246` |

### §4.2 — Implicit Grant

Non implémenté (déprécié par RFC 9700 et incompatible avec PKCE).

### §6 — Refresh Token

| Exigence | Statut | Référence code |
|---|---|---|
| Le refresh token est rotatif (RFC 6749 §10.4) | ✅ | `oauth2.py` — ancien révoqué, nouveau émis |
| Le refresh token est stocké hashé | ✅ | `OAuth2Token.token_hash` (bcrypt) |
| La vérification est O(1) via index SHA-256 | ✅ | `OAuth2Token.token_sha256` — lookup avant bcrypt |
| Le refresh token expire après 30 jours | ✅ | `REFRESH_TOKEN_EXPIRE_SECONDS=2592000` |

### §10.12 — Cross-Site Request Forgery (CSRF)

| Exigence | Statut | Référence code |
|---|---|---|
| Le paramètre `state` est stocké dans l'auth code | ✅ | `oauth2_code.py:state` |
| Le `state` est retourné dans la redirection | ✅ | `oauth2.py:207–209` |
| Les formulaires HTML sont protégés par CSRF token | ✅ | Flask-WTF sur tous les formulaires |

---

## RFC 7636 — PKCE for OAuth 2.0 Public Clients

| Exigence | Statut | Référence code |
|---|---|---|
| PKCE obligatoire pour les clients publics (`is_confidential=false`) | ✅ | `oauth2.py:143–144` |
| Seule la méthode `S256` est acceptée | ✅ | `oauth2.py:140–141` |
| `code_challenge = BASE64URL(SHA256(code_verifier))` | ✅ | `oauth2.py:254` |
| Longueur `code_verifier` validée : 43–128 caractères (§4.1) | ✅ | `oauth2.py:251–252` |
| La vérification PKCE est réalisée à l'échange du code | ✅ | `oauth2.py:247–256` |

---

## RFC 7009 — OAuth 2.0 Token Revocation

| Exigence | Statut | Référence code |
|---|---|---|
| `POST /revoke` accepte `token` et `token_type_hint` | ✅ | `oauth2.py:396` |
| Retourne HTTP 200 même si le token est inconnu | ✅ | `oauth2.py:438` |
| L'access token révoqué est blacklisté dans Redis (JTI) | ✅ | `oauth2.py:426` — `setex(blacklist:{jti})` |
| Le TTL Redis correspond à la durée restante du token | ✅ | `oauth2.py:424–425` — `ttl = exp - now` |
| Le refresh token révoqué est marqué en base | ✅ | `OAuth2Token.revoked_at` |
| La révocation via l'interface utilisateur est supportée | ✅ | `/profile/revoke-app` |

---

## RFC 7519 — JSON Web Token (JWT)

| Exigence | Statut | Référence code |
|---|---|---|
| Claims `iss`, `sub`, `aud`, `exp`, `iat`, `jti` présents | ✅ | `oauth2.py:_sign_jwt()` |
| `exp` est validé à la vérification | ✅ | `PyJWT` — `require: ['exp', 'iat', 'jti']` |
| `jti` unique par token (UUID v4) | ✅ | `oauth2.py:37` — `str(uuid.uuid4())` |
| La blacklist Redis filtre les tokens révoqués par JTI | ✅ | `oauth2.py:_verify_bearer_token():71` |

### Claims de l'access token

```json
{
  "iss": "https://sso.example.com",
  "sub": "<uuid-utilisateur>",
  "aud": "<client_id>",
  "scope": "openid email",
  "email": "user@example.com",
  "name": "Alice",
  "is_admin": false,
  "iat": 1718539200,
  "exp": 1718542800,
  "jti": "<uuid-v4>"
}
```

---

## RFC 7517 — JSON Web Key (JWK)

| Exigence | Statut | Référence code |
|---|---|---|
| `GET /jwks.json` expose les clés publiques actives | ✅ | `oauth2.py:jwks()` |
| Seules les clés non expirées sont exposées | ✅ | `RS256Key.expires_at > now` |
| Chaque clé a un `kid` unique | ✅ | `RS256Key.kid` |
| Le champ `alg` est présent dans le JWK | ✅ | `"alg": "RS256"` |
| L'en-tête JWT inclut le `kid` | ✅ | `jwt.encode(..., headers={'kid': key.kid})` |

---

## RFC 7518 — JSON Web Algorithms (JWA)

| Exigence | Statut | Référence code |
|---|---|---|
| Algorithme RS256 (RSASSA-PKCS1-v1_5 + SHA-256) | ✅ | `algorithm='RS256'` |
| Taille de clé RSA ≥ 2048 bits | ✅ | `KeyService` — clé 4096 bits |
| Clé privée chiffrée en AES-256-GCM en base | ✅ | `key_service.py:encrypt_private_key()` |
| Rotation automatique à 90 jours | ✅ | APScheduler `cron(hour=2)` |

---

## OpenID Connect Core 1.0

### Discovery (§4)

| Exigence | Statut | Référence code |
|---|---|---|
| `GET /.well-known/openid-configuration` | ✅ | `oauth2.py:openid_config()` |
| Champs obligatoires : `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri` | ✅ | Tous présents |

### ID Token (§2)

| Exigence | Statut | Référence code |
|---|---|---|
| Claims `sub`, `iss`, `aud`, `exp`, `iat` | ✅ | `oauth2.py:293–304` |
| Claim `nonce` inclus si fourni dans la requête | ✅ | `id_payload['nonce'] = auth_code.nonce` |
| Signé en RS256 | ✅ | `_sign_jwt()` |

### UserInfo Endpoint (§5.3)

| Exigence | Statut | Référence code |
|---|---|---|
| `GET /userinfo` avec Bearer token | ✅ | `oauth2.py:userinfo()` |
| Filtrage des claims selon les scopes accordés | ✅ | `oauth2.py:382–390` — `scope_set` |
| `email` retourné uniquement si scope `email` accordé | ✅ | |
| `name`, `preferred_username` si scope `profile` | ✅ | |

### Consentement utilisateur

| Exigence | Statut | Référence code |
|---|---|---|
| Page de consentement affichée avant le premier grant | ✅ | `consent.html` + `oauth2.py:179–211` |
| Le consentement est enregistré en base (RGPD Art. 7) | ✅ | `OAuth2Consent` — table `oauth2_consents` |
| Nouveau consentement si les scopes demandés s'élargissent | ✅ | `oauth2.py:needs_consent` |
| L'utilisateur peut révoquer l'accès d'une application | ✅ | `/profile/revoke-app` |

### Fonctionnalités non implémentées

| Fonctionnalité | Justification |
|---|---|
| Implicit flow (`response_type=token`) | Déprécié (RFC 9700) — non retenu par le CDC |
| Hybrid flow | Non requis par le CDC |
| Dynamic Client Registration (RFC 7591) | Hors périmètre — enregistrement via admin |
| Session Management | Hors périmètre Sprint 8 |

---

## RFC 6238 — TOTP : Time-Based One-Time Password

| Exigence | Statut | Référence code |
|---|---|---|
| Génération de codes à 6 chiffres | ✅ | `pyotp.TOTP` — `digits=6` |
| Période de 30 secondes | ✅ | Valeur par défaut pyotp |
| Algorithme HMAC-SHA1 | ✅ | Conforme RFC 6238 |
| Fenêtre de validité : ±1 période | ✅ | `TOTPService.verify_code(valid_window=1)` |
| Secret chiffré AES-256-GCM en base | ✅ | `TOTPService.encrypt_secret()` |
| QR code compatible Google Authenticator / Authy | ✅ | URI `otpauth://totp/` |
| 10 codes de secours hachés individuellement (bcrypt) | ✅ | `TOTPService.generate_backup_codes()` |

---

## RFC 9207 — OAuth 2.0 `iss` Response Parameter

| Exigence | Statut | Notes |
|---|---|---|
| Paramètre `iss` retourné dans la redirection d'autorisation | ⚠️ Non implémenté | Recommandé pour les déploiements multi-AS |

**Justification :** Le projet est mono-issuer (un seul serveur d'autorisation). La valeur ajoutée de RFC 9207 est significative uniquement dans des architectures multi-AS. L'implémentation est triviale — ajouter `iss` aux paramètres de redirection dans `oauth2.py:207`.

---

## Mesures de sécurité supplémentaires (hors RFC)

### Protection contre les attaques

| Attaque | Contre-mesure |
|---|---|
| Brute-force login | Lockout après 10 échecs, 15 minutes (`User.locked_until`) |
| Timing attack sur bcrypt | SHA-256 index pour lookup O(1) avant bcrypt |
| Clickjacking | `X-Frame-Options: DENY` + CSP `frame-ancestors 'none'` |
| MIME sniffing | `X-Content-Type-Options: nosniff` |
| Information leakage (email enumeration) | Message générique sur `/forgot-password` |
| Token replay après révocation | Blacklist Redis par JTI |
| Session fixation | Nouveau `session_id` (`secrets.token_urlsafe(32)`) à chaque login |
| Redirect URI spoofing | Normalisation `urlparse` (schéma, casse, trailing slash) |
| CSRF | Flask-WTF + `state` OAuth2 |

### Headers de sécurité HTTP

| Header | Valeur |
|---|---|
| `Content-Security-Policy` | `default-src 'self'` + CDN autorisés explicitement |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` (production) |
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` |

---

## Matrice de conformité globale

| Critère | Poids CDC | Statut |
|---|---|---|
| Flux Authorization Code complet | Critique | ✅ |
| PKCE obligatoire clients publics | Critique | ✅ |
| RS256 + rotation 90 jours | Critique | ✅ |
| Révocation tokens (Redis + DB) | Critique | ✅ |
| 2FA TOTP avec backup codes | Critique | ✅ |
| Consentement RGPD | Critique | ✅ |
| Journal d'audit complet | Critique | ✅ |
| Brute-force protection | Haut | ✅ |
| Headers sécurité HTTP | Haut | ✅ |
| Reset mot de passe par email | Moyen | ✅ |
| Interface admin TailwindCSS | Moyen | ✅ |
| CI/CD GitHub Actions | Moyen | ✅ |
| `/health` endpoint | Moyen | ✅ |
| RFC 9207 `iss` parameter | Bas | ⚠️ Partiel |
| WebSocket revocation | Optionnel | ❌ Non implémenté |
