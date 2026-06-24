# 🚀 Sprint 1 — Commandes de démarrage (dans l'ordre)

## Problèmes corrigés dans cette version
- ✅ `pg_isready -U sso_user -d sso_db` (fix "database sso_user does not exist")
- ✅ Modèles SQLAlchemy définis → `flask db migrate` détecte les tables
- ✅ Flask-Limiter configuré avec Redis (plus de warning in-memory)
- ✅ `wsgi.py` créé → gunicorn utilise `wsgi:app`
- ✅ `version:` retiré du docker-compose.yml (obsolète en Compose v2)

---

## Étape 1 — Copier les fichiers modifiés dans votre projet

Remplacer dans votre dossier `sso-project/` :
- `docker-compose.yml`     ← health check corrigé
- `config.py`              ← RATELIMIT_STORAGE_URI + AES key 32 bytes
- `Dockerfile`             ← CMD séparé de ENTRYPOINT
- `entrypoint.sh`          ← set -e ajouté
- Créer `wsgi.py`          ← nouveau
- Créer `app/__init__.py`  ← factory avec import des modèles
- Créer `app/extensions.py`
- Créer `app/models/`      ← 6 fichiers de modèles
- Créer `app/routes/health.py`
- Créer `.env`             ← copier depuis .env.example

---

## Étape 2 — Repartir de zéro (conteneurs + volumes)

```powershell
docker-compose down -v
```

---

## Étape 3 — Rebuild de l'image

```powershell
docker-compose build --no-cache
```

---

## Étape 4 — Démarrer uniquement db et redis

```powershell
docker-compose up -d db redis
```

Attendre ~5 secondes que PostgreSQL soit prêt.

---

## Étape 5 — Initialiser les migrations Alembic

```powershell
docker-compose run --rm web flask db init
```

---

## Étape 6 — Générer la migration initiale

```powershell
docker-compose run --rm web flask db migrate -m "Sprint 1 - modeles initiaux"
```

✅ Vous devez voir les tables détectées :
```
INFO  Detected added table 'users'
INFO  Detected added table 'oauth2_clients'
INFO  Detected added table 'oauth2_authorization_codes'
INFO  Detected added table 'oauth2_tokens'
INFO  Detected added table 'rs256_keys'
INFO  Detected added table 'audit_logs'
```

---

## Étape 7 — Appliquer la migration

```powershell
docker-compose run --rm web flask db upgrade
```

---

## Étape 8 — Démarrer l'application complète

```powershell
docker-compose up
```

---

## Vérification

Ouvrir dans le navigateur :
- http://localhost:8000/        → {"service": "SSO OAuth2...", "status": "running"}
- http://localhost:8000/health  → {"status": "unhealthy"} (rs256_key manquante, normal au Sprint 1)

La clé RS256 sera générée au Sprint 4.

---

## Commandes utiles

```powershell
# Voir les logs
docker-compose logs -f web

# Shell dans le conteneur
docker-compose exec web bash

# Vérifier les tables créées
docker-compose exec db psql -U sso_user -d sso_db -c "\dt"

# Vérifier les colonnes d'une table
docker-compose exec db psql -U sso_user -d sso_db -c "\d users"
```
