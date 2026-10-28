$ErrorActionPreference = "Stop"

# Resolve paths independently of the Windows service's working directory.
Set-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)
if (Test-Path -LiteralPath ".env") {
    Get-Content -LiteralPath ".env" -Encoding UTF8 | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
            $name, $value = $line.Split("=", 2)
            $name = $name.Trim()
            $value = $value.Trim()
            if ($name -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') {
                throw "Invalid environment variable name in .env."
            }
            if ($value.Length -ge 2 -and (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'")))) {
                $value = $value.Substring(1, $value.Length - 2)
            }
            [Environment]::SetEnvironmentVariable($name, $value, "Process")
        }
    }
}
if (-not $env:APP_ENV) { $env:APP_ENV = "production" }
$pythonExecutable = if ($env:PYTHON_EXECUTABLE) {
    $env:PYTHON_EXECUTABLE
} elseif (Test-Path -LiteralPath ".venv/Scripts/python.exe") {
    (Resolve-Path -LiteralPath ".venv/Scripts/python.exe").Path
} else {
    "python"
}

function Invoke-ProjectPython {
    & $pythonExecutable @args
    if ($LASTEXITCODE -ne 0) { throw "Python command failed (exit $LASTEXITCODE)." }
}
