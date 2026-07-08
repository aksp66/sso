import secrets
import json
from datetime import datetime, timezone
from flask import current_app
from app.extensions import get_redis


def create_user_session(user_id, ip, user_agent):
    session_id = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc).timestamp()
    data = {
        'user_id': str(user_id),
        'ip': ip,
        'user_agent': user_agent,
        'created_at': now,
        'last_seen': now,
    }
    ttl = current_app.config['SESSION_TTL_SECONDS']
    redis = get_redis()
    redis.setex(f'session:{session_id}', ttl, json.dumps(data))
    return session_id


def refresh_user_session(session_id: str) -> bool:
    """Renouvelle le TTL et met à jour last_seen (sliding window).
    Retourne False si la session n'existe plus dans Redis."""
    redis = get_redis()
    key = f'session:{session_id}'
    raw = redis.get(key)
    if not raw:
        return False
    data = json.loads(raw)
    data['last_seen'] = datetime.now(timezone.utc).timestamp()
    ttl = current_app.config['SESSION_TTL_SECONDS']
    redis.setex(key, ttl, json.dumps(data))
    return True


def get_user_session(session_id: str) -> dict | None:
    """Récupère les données d'une session Redis. Retourne None si absente."""
    redis = get_redis()
    raw = redis.get(f'session:{session_id}')
    if not raw:
        return None
    return json.loads(raw)


def delete_user_session(session_id: str) -> None:
    """Supprime immédiatement la session Redis (logout explicite)."""
    get_redis().delete(f'session:{session_id}')
