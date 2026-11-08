# Local commands in a child process; start.ps1 remains the production entry point.
. (Join-Path $PSScriptRoot "scripts/deploy-common.ps1")
Invoke-ProjectPython scripts/local.py @args
