"""
Blueprint health — GET /health et GET /metrics

Conforme au cahier des charges §8.5.
Retourne l'état de chaque composant : BDD, Redis, clé RS256 active.
Utilisé par Docker healthcheck et Kubernetes liveness/readiness probes.
"""

import time
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify

from app.extensions import db, get_redis

health_bp = Blueprint("health", __name__)


@health_bp.get("/health")
def health_check():
    """
    Vérifie l'état de tous les composants critiques.

    Réponse JSON :
    {
        "status": "healthy" | "degraded" | "unhealthy",
        "version": "1.0.0",
        "components": {
            "database": {"status": "up", "latency_ms": 4},
            "redis":    {"status": "up", "latency_ms": 1},
            "rs256_key": {"status": "active", "kid": "key-2026-Q2", "expires_in_days": 47}
        },
        "timestamp": "2026-06-03T11:00:00Z"
    }
    """
    components = {}
    overall_ok = True

    # ── Vérification PostgreSQL ────────────────────────────────────────────
    t0 = time.monotonic()
    try:
        db.session.execute(db.text("SELECT 1"))
        db_latency = round((time.monotonic() - t0) * 1000, 1)
        components["database"] = {"status": "up", "latency_ms": db_latency}
    except Exception as exc:
        components["database"] = {"status": "down", "error": str(exc)}
        overall_ok = False

    # ── Vérification Redis ─────────────────────────────────────────────────
    t0 = time.monotonic()
    try:
        redis = get_redis()
        redis.ping()
        redis_latency = round((time.monotonic() - t0) * 1000, 1)
        components["redis"] = {"status": "up", "latency_ms": redis_latency}
    except Exception as exc:
        components["redis"] = {"status": "down", "error": str(exc)}
        overall_ok = False

    # ── Vérification clé RS256 active ─────────────────────────────────────
    try:
        from app.models.rs256_key import RS256Key

        active_key = RS256Key.query.filter_by(is_active=True).first()
        if active_key:
            components["rs256_key"] = {
                "status": "active",
                "kid": active_key.kid,
                "expires_in_days": active_key.days_until_expiry(),
            }
            # Alerte si la clé expire dans moins de 7 jours
            if active_key.days_until_expiry() < 7:
                components["rs256_key"]["warning"] = "Rotation imminente"
        else:
            components["rs256_key"] = {
                "status": "missing",
                "error": "Aucune clé RS256 active — exécuter init_rs256_key",
            }
            overall_ok = False
    except Exception as exc:
        components["rs256_key"] = {"status": "error", "error": str(exc)}

    status = "healthy" if overall_ok else "unhealthy"
    http_code = 200 if overall_ok else 503

    return (
        jsonify(
            {
                "status": status,
                "version": "1.0.0",
                "components": components,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ),
        http_code,
    )
