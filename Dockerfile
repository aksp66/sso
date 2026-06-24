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

# ENTRYPOINT exécute les migrations, CMD est la commande réelle
ENTRYPOINT ["./entrypoint.sh"]
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--timeout", "30", "wsgi:app"]
