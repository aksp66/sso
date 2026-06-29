FROM python:3.12-slim

WORKDIR /app

# Dépendances système pour psycopg2 et cryptography
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

# Installation des dépendances Python en premier (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copie du code source
COPY . .

RUN chmod +x entrypoint.sh

EXPOSE 8000

# ENTRYPOINT exécute les migrations, CMD est la commande réelle.
# Forme shell (pas exec) pour que ${PORT} soit interpolé par le shell — Render
# assigne dynamiquement ce port ; en local (docker-compose), il est absent et
# on retombe sur 8000. docker-compose.yml définit son propre `command:` qui
# prévaut de toute façon sur ce CMD par défaut.
# --preload : charge create_app() UNE SEULE FOIS dans le master avant le fork
# des workers — sans ça, chaque worker exécute create_app() indépendamment
# (migrations en double, plusieurs planificateurs APScheduler redondants).
CMD gunicorn --bind 0.0.0.0:${PORT:-8000} --workers 2 --preload --timeout 30 wsgi:app
