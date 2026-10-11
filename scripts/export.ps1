param([Parameter(Mandatory=$true)][string]$GhidraHome,
      [Parameter(Mandatory=$true)][string]$JavaHome,
      [Parameter(Mandatory=$true)][string]$ExistingProjects,
      [string]$ProjectName = 'speed_exe')
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$repoPath = Join-Path $projectRoot 'reference\nfsmw-recomp'
$outputPath = Join-Path $repoPath 'analysis\decompiled'
$statePath = Join-Path $projectRoot '.tools\ghidra-state'
$logPath = Join-Path $projectRoot 'artifacts\ghidra-export.log'
New-Item -ItemType Directory -Force -Path $outputPath,$statePath,(Split-Path -Parent $logPath) | Out-Null
$env:JAVA_HOME = $JavaHome
$env:JAVA_TOOL_OPTIONS = '-Dapplication.settingsdir="' + $statePath + '\settings" -Dapplication.cachedir="' + $statePath + '\cache" -Dapplication.tempdir="' + $statePath + '\temp"'
# Reuse the audited program without changing the original Ghidra project.
$ErrorActionPreference = 'Continue' # Windows PowerShell treats native stderr as an error record.
& (Join-Path $GhidraHome 'support\analyzeHeadless.bat') $ExistingProjects $ProjectName `
    -process speed.exe -readOnly -noanalysis -scriptPath (Join-Path $repoPath 'kit\tools') `
    -postScript ExportProgram.java $outputPath -max-cpu 4 2>&1 | Tee-Object -FilePath $logPath
$nativeExit = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
if ($nativeExit -ne 0) { throw "Ghidra export failed: $nativeExit" }
if (-not (Test-Path -LiteralPath (Join-Path $outputPath 'speed.exe\summary.txt'))) { throw 'Missing export summary' }
