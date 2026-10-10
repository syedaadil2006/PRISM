# PRISM in one container: the dashboard is built, then served by the API server.
#
#   docker compose up -d --build        (see docker-compose.yml)
#
# Everything PRISM writes (databases, access code, backups, HTTPS certificate,
# watched log folder) lives in /data, a volume, so the container itself can be
# replaced or upgraded without losing anything.

# --- 1. Build the dashboard ------------------------------------------------------
FROM node:22-alpine AS dashboard
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# --- 2. Runtime --------------------------------------------------------------------
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PRISM_STORAGE_PATH=/data/prism.db \
    PRISM_AUTH_DB_URL=/data/security.db \
    PRISM_AUTH_TOKEN_FILE=/data/.prism_token \
    PRISM_BACKUP_DIR=/data/backups \
    PRISM_LIVE_WATCH_DIR=/data/live

WORKDIR /app
COPY backend/requirements.txt backend/requirements-postgres.txt backend/
RUN pip install -r backend/requirements.txt

COPY backend/app backend/app
COPY backend/data/demo backend/data/demo
COPY backend/data/inventory backend/data/inventory
COPY backend/data/botsv1/MANIFEST.json backend/data/botsv1/inventory.json backend/data/botsv1/
COPY backend/data/botsv1/scenario backend/data/botsv1/scenario
COPY --from=dashboard /build/dist frontend/dist
COPY docker/entrypoint.sh /usr/local/bin/prism-entrypoint

# Runs as an unprivileged user that owns only /data.
RUN chmod 0755 /usr/local/bin/prism-entrypoint \
    && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin prism \
    && mkdir -p /data/live /data/backups /data/tls \
    && chown -R prism:prism /data
USER prism
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD python -c "import ssl,sys,urllib.request as u; c=ssl._create_unverified_context(); \
s='https' if __import__('os').path.exists('/data/tls/prism.crt') else 'http'; \
u.urlopen(s+'://127.0.0.1:8000/api/health', timeout=4, context=c if s=='https' else None)" || exit 1

ENTRYPOINT ["prism-entrypoint"]
