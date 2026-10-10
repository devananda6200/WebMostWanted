[CmdletBinding()]
param([int]$Limit = 3000)
$ErrorActionPreference = 'Stop'
$portRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $portRoot
try {
    & '.\.venv\Scripts\python.exe' -m tools.build_startup --limit $Limit
    if ($LASTEXITCODE -ne 0) { throw 'Startup translation build failed.' }
    & '.\.tools\emsdk-4.0.23\node\22.16.0_64bit\bin\node.exe' 'tests/run_startup.mjs'
    if ($LASTEXITCODE -ne 0) { throw 'Startup stopped at a compatibility barrier; see artifacts/startup-node.json.' }
} finally { Pop-Location }
