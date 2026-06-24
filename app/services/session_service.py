import uuid
import json
from datetime import datetime, timezone
from flask import current_app
from app.extensions import get_redis

def create_user_session(user_id, ip, user_agent):
    session_id = str(uuid.uuid4())
    data = {
        'user_id': str(user_id),
        'ip': ip,
        'user_agent': user_agent,
        'created_at': datetime.now(timezone.utc).timestamp(),
        'last_seen': datetime.now(timezone.utc).timestamp()
    }
    ttl = current_app.config['SESSION_TTL_SECONDS']
    redis = get_redis()
    redis.setex(f'session:{session_id}', ttl, json.dumps(data))
    return session_id
