[CmdletBinding()]
param([switch]$SyntheticOnly)
$ErrorActionPreference = 'Stop'
$portRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $portRoot
try {
    $buildArgs = @('-m', 'tools.build_tests')
    if ($SyntheticOnly) { $buildArgs += '--synthetic-only' }
    & '.\.venv\Scripts\python.exe' @buildArgs
    if ($LASTEXITCODE -ne 0) { throw 'Binary translation build failed.' }
    if (-not $SyntheticOnly) {
        & '.\.venv\Scripts\python.exe' -m tools.build_startup
        if ($LASTEXITCODE -ne 0) { throw 'Startup translation build failed.' }
        & '.\.venv\Scripts\python.exe' -m tools.startup_reference
        if ($LASTEXITCODE -ne 0) { throw 'Startup prefix reference failed.' }
    }
} finally { Pop-Location }
