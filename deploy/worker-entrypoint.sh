#!/bin/sh
set -eu

python deploy/wait_for_services.py

exec python -m app.outbox_worker
