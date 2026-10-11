param([switch]$SkipPythonDependencies)
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location -LiteralPath $projectRoot
try {
    $projectPython = Join-Path $projectRoot '.venv/Scripts/python.exe'
    if (-not (Test-Path -LiteralPath $projectPython)) {
        python -m venv (Join-Path $projectRoot '.venv')
        if ($LASTEXITCODE -ne 0) { throw 'Creating local Python environment failed.' }
    }
    if (-not $SkipPythonDependencies) {
        & $projectPython -m pip install -r (Join-Path $projectRoot 'requirements.txt')
        if ($LASTEXITCODE -ne 0) { throw 'Installing pinned Python dependencies failed.' }
    }
    & $projectPython -m tools.toolchain setup
    if ($LASTEXITCODE -ne 0) { throw 'Installing local Emscripten SDK failed.' }
    & $projectPython -m tools.toolchain environment
    if ($LASTEXITCODE -ne 0) { throw 'Environment audit failed.' }
} finally {
    Pop-Location
}
