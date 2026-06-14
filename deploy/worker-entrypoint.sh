#!/bin/sh
set -eu

python deploy/wait_for_services.py
alembic upgrade head

exec python -m app.outbox_worker
