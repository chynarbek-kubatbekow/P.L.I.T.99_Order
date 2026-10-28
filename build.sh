#!/usr/bin/env bash
set -o errexit

source "$(dirname -- "${BASH_SOURCE[0]}")/scripts/deploy-common.sh"

"$PYTHON_EXECUTABLE" -m pip install --only-binary=:all: -r requirements.txt
"$PYTHON_EXECUTABLE" manage.py check --deploy --fail-level ERROR
"$PYTHON_EXECUTABLE" manage.py collectstatic --noinput
if [ -n "${MIGRATION_DATABASE_URL:-}" ]; then
  DATABASE_URL="$MIGRATION_DATABASE_URL" "$PYTHON_EXECUTABLE" manage.py migrate --noinput
else
  "$PYTHON_EXECUTABLE" manage.py migrate --noinput
fi
