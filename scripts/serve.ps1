param([string]$GameDir = 'C:\Users\festi\Downloads\WebMostWanted\NFS-Most-Wanted-2005\Need For Speed Most Wanted Black Edition',
      [int]$Port = 8080)
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location -LiteralPath $projectRoot
try {
    if (-not (Test-Path -LiteralPath 'build\site\nfsmw\SpeedRecomp.wasm')) {
        throw 'Build/stage the runtime first; see docs/browser-runtime.md.'
    }
    if (-not (Test-Path -LiteralPath 'artifacts\asset-manifest.json')) {
        python tools/assets.py manifest --game-dir $GameDir
        if ($LASTEXITCODE -ne 0) { throw 'Asset manifest generation failed.' }
    }
    python tools/assets.py serve --game-dir $GameDir --port $Port
    if ($LASTEXITCODE -ne 0) { throw 'Private server failed.' }
} finally { Pop-Location }
