$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$projectPython = Join-Path $projectRoot '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $projectPython)) {
    throw 'Run scripts/setup.ps1 to create the project Python environment first.'
}
Push-Location -LiteralPath $projectRoot
try {
    & $projectPython -m tools.toolchain environment
    if ($LASTEXITCODE -ne 0) { throw 'Environment audit failed.' }
} finally {
    Pop-Location
}
