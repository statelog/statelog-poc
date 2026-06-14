#!/usr/bin/env bash
set -euo pipefail

python deploy/wait_for_services.py
alembic upgrade head
current_output="$(alembic current)"
echo "$current_output"
if [[ "$current_output" != *"(head)"* ]]; then
  echo "Migration gate failed: database is not at alembic head" >&2
  exit 1
fi
