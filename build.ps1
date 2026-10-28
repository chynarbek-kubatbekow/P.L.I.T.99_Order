. (Join-Path $PSScriptRoot "scripts/deploy-common.ps1")

Invoke-ProjectPython -m pip install --only-binary=:all: -r requirements.txt
Invoke-ProjectPython manage.py check --deploy --fail-level ERROR
Invoke-ProjectPython manage.py collectstatic --noinput
$runtimeDatabaseUrl = $env:DATABASE_URL
try {
    if ($env:MIGRATION_DATABASE_URL) { $env:DATABASE_URL = $env:MIGRATION_DATABASE_URL }
    Invoke-ProjectPython manage.py migrate --noinput
} finally {
    [Environment]::SetEnvironmentVariable("DATABASE_URL", $runtimeDatabaseUrl, "Process")
}
