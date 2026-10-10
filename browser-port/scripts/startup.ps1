[CmdletBinding()]
param([int]$Limit = 24000, [string[]]$Seed = @(), [switch]$FromTrace, [int]$MaxSteps = 2000000, [string]$SeedFile)
$ErrorActionPreference = 'Stop'
$portRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $portRoot
try {
    $startupArgs = @('-m', 'tools.build_startup', '--limit', "$Limit", '--max-steps', "$MaxSteps")
    foreach ($address in $Seed) { $startupArgs += @('--seed', $address) }
    if ($SeedFile) { $startupArgs += @('--seed-file', $SeedFile) }
    if ($FromTrace) { $startupArgs += '--from-trace' }
    & '.\.venv\Scripts\python.exe' @startupArgs
    if ($LASTEXITCODE -ne 0) { throw 'Startup translation build failed.' }
    & '.\.venv\Scripts\python.exe' -m tools.startup_reference
    if ($LASTEXITCODE -ne 0) { throw 'Startup prefix reference failed.' }
    & '.\.tools\emsdk-4.0.23\node\22.16.0_64bit\bin\node.exe' 'tests/compare_startup.mjs'
    if ($LASTEXITCODE -ne 0) { throw 'Original entry prefix differential check failed.' }
    & '.\.tools\emsdk-4.0.23\node\22.16.0_64bit\bin\node.exe' 'tests/run_startup.mjs'
    if ($LASTEXITCODE -ne 0) { throw 'Startup stopped at a compatibility barrier; see artifacts/startup-node.json.' }
} finally { Pop-Location }
