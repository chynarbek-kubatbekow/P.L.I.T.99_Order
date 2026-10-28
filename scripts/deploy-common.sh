# Sourced by the project entry points. .env is trusted server configuration.
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [ -f .env ]; then
  set -o allexport
  source .env
  set +o allexport
fi
export APP_ENV="${APP_ENV:-production}"
if [ -z "${PYTHON_EXECUTABLE:-}" ]; then
  if [ -x .venv/bin/python ]; then
    PYTHON_EXECUTABLE="$PWD/.venv/bin/python"
  else
    PYTHON_EXECUTABLE=python3
  fi
fi
