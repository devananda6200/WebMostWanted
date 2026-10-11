[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$portRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $portRoot
try {
    & '.\.venv\Scripts\python.exe' -m unittest discover -s tests -p 'test_*.py' -v
    if ($LASTEXITCODE -ne 0) { throw 'Python tests failed.' }
    & '.\.tools\emsdk-4.0.23\node\22.16.0_64bit\bin\node.exe' 'tests/run_wasm.mjs'
    if ($LASTEXITCODE -ne 0) { throw 'Wasm differential tests failed.' }
    $testManifest = Get-Content -LiteralPath 'build/manifest.json' -Raw | ConvertFrom-Json
    if ($testManifest.suites.id -contains 'startup-prefix') {
        & '.\.tools\emsdk-4.0.23\node\22.16.0_64bit\bin\node.exe' 'tests/compare_startup.mjs'
        if ($LASTEXITCODE -ne 0) { throw 'Original entry trace differential check failed.' }
    }
    & '.\.venv\Scripts\python.exe' -m tools.win32_test
    if ($LASTEXITCODE -ne 0) { throw 'Win32 contract tests failed.' }
} finally { Pop-Location }
