. (Join-Path $PSScriptRoot "scripts/deploy-common.ps1")
Remove-Item Env:MIGRATION_DATABASE_URL -ErrorAction SilentlyContinue

$port = if ($env:WAITRESS_PORT) { $env:WAITRESS_PORT } else { "8000" }
$threads = if ($env:WAITRESS_THREADS) { $env:WAITRESS_THREADS } else { "4" }
$listenHost = if ($env:WAITRESS_HOST) { $env:WAITRESS_HOST } else { "127.0.0.1" }
Invoke-ProjectPython manage.py check --deploy --fail-level ERROR
# The service must not require schema-changing database privileges.
Invoke-ProjectPython manage.py migrate --check

$waitressArgs = @("--listen=${listenHost}:$port", "--threads=$threads", "--max-request-body-size=12582912", "--max-request-header-size=32768", "--channel-timeout=60", "--connection-limit=100")
if ($env:WAITRESS_TRUSTED_PROXY) {
    if ($env:WAITRESS_TRUSTED_PROXY -eq "*") { throw "Use an explicit trusted proxy address." }
    $waitressArgs += "--trusted-proxy=$env:WAITRESS_TRUSTED_PROXY"
    $waitressArgs += "--trusted-proxy-headers=x-forwarded-for x-forwarded-proto"
}
Invoke-ProjectPython -m waitress @waitressArgs plit99_project.wsgi:application
