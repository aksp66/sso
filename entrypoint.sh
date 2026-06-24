#!/bin/sh
set -e

echo "🔄 Vérification des migrations Alembic..."
flask db upgrade

echo "✅ Migrations appliquées. Démarrage de l'application..."
exec "$@"
