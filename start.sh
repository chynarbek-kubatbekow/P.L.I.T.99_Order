#!/usr/bin/env bash
set -o errexit

source "$(dirname -- "${BASH_SOURCE[0]}")/scripts/deploy-common.sh"
unset MIGRATION_DATABASE_URL

PORT="${PORT:-${WAITRESS_PORT:-8000}}"
THREADS="${WAITRESS_THREADS:-4}"
HOST="${WAITRESS_HOST:-127.0.0.1}"
"$PYTHON_EXECUTABLE" manage.py check --deploy --fail-level ERROR
"$PYTHON_EXECUTABLE" manage.py migrate --check

proxy_args=()
if [ -n "${WAITRESS_TRUSTED_PROXY:-}" ]; then
  if [ "$WAITRESS_TRUSTED_PROXY" = "*" ]; then
    echo "Use an explicit trusted proxy address." >&2
    exit 1
  fi
  proxy_args=("--trusted-proxy=$WAITRESS_TRUSTED_PROXY" "--trusted-proxy-headers=x-forwarded-for x-forwarded-proto")
fi
exec "$PYTHON_EXECUTABLE" -m waitress --listen="${HOST}:${PORT}" --threads="${THREADS}" --max-request-body-size=12582912 --max-request-header-size=32768 --channel-timeout=60 --connection-limit=100 "${proxy_args[@]}" plit99_project.wsgi:application
