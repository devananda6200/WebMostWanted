[CmdletBinding()]
param([int]$Port = 8000)
$ErrorActionPreference = 'Stop'
$portRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $portRoot
try {
    & '.\.venv\Scripts\python.exe' -m tools.serve --port $Port
    if ($LASTEXITCODE -ne 0) { throw 'Local resource server failed.' }
} finally { Pop-Location }
