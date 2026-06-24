"""
Point d'entrée WSGI pour Gunicorn.
Utilisation : gunicorn --bind 0.0.0.0:8000 wsgi:app
"""

from app import create_app

app = create_app()

if __name__ == "__main__":
    # Développement local uniquement (pas pour la production)
    app.run(host="0.0.0.0", port=8000, debug=True)
