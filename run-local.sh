#!/usr/bin/env bash
set -o errexit
source "$(dirname -- "${BASH_SOURCE[0]}")/scripts/deploy-common.sh"
exec "$PYTHON_EXECUTABLE" scripts/local.py "$@"
