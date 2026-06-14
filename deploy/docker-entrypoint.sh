#!/bin/sh
set -eu

python deploy/wait_for_services.py
alembic upgrade head

exec uvicorn app.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --workers "${UVICORN_WORKERS:-2}" \
  --proxy-headers \
  --forwarded-allow-ips='*'
