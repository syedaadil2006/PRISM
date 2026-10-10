#!/bin/sh
# Starts PRISM inside the container. Listens on all container interfaces so the
# published port works; docker-compose.yml publishes it on 127.0.0.1 only.
# HTTPS is used when /data/tls/prism.crt and prism.key exist.
set -e
cd /app
set -- python -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000 --proxy-headers=false
if [ -f /data/tls/prism.crt ] && [ -f /data/tls/prism.key ]; then
    set -- "$@" --ssl-certfile /data/tls/prism.crt --ssl-keyfile /data/tls/prism.key
fi
exec "$@"
