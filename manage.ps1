# Load the same production environment and interpreter as the service.
. (Join-Path $PSScriptRoot "scripts/deploy-common.ps1")
Invoke-ProjectPython manage.py @args
