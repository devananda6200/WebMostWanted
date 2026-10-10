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
} finally { Pop-Location }
