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
} finally { Pop-Location }
