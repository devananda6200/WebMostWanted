param(
    [string[]]$Binaries = @('speed.exe', 'server.dll', 'nfsmwres.exe', 'safemode_inst.exe', 'shell_inst.exe'),
    [string]$JavaHome = 'C:\Program Files\Android\Android Studio\jbr'
)
$ErrorActionPreference = 'Stop'
$recoveryRoot = Split-Path $PSScriptRoot -Parent
$gameRoot = Split-Path $recoveryRoot -Parent
$launcher = Join-Path $recoveryRoot '.tools\ghidra_12.1.4_PUBLIC\support\analyzeHeadless.bat'
if (-not (Test-Path -LiteralPath $launcher)) { throw 'Run tools/setup_ghidra.py first.' }
if (-not (Test-Path -LiteralPath (Join-Path $JavaHome 'bin\javac.exe'))) { throw 'A full Java 21 JDK is required; pass -JavaHome.' }
$env:JAVA_HOME = $JavaHome
$localState = Join-Path $recoveryRoot '.tools\ghidra-state'
$env:JAVA_TOOL_OPTIONS = '-Dapplication.settingsdir="' + $localState + '\settings" -Dapplication.cachedir="' + $localState + '\cache" -Dapplication.tempdir="' + $localState + '\temp"'
$projects = Join-Path $recoveryRoot 'projects'
$recovered = Join-Path $recoveryRoot 'recovered'
$logs = Join-Path $recoveryRoot 'logs'
New-Item -ItemType Directory -Force -Path $projects,$recovered,$logs | Out-Null
foreach ($binary in $Binaries) {
    if ($binary -notin @('speed.exe', 'server.dll', 'nfsmwres.exe', 'safemode_inst.exe', 'shell_inst.exe')) {
        throw "Unexpected binary name: $binary"
    }
    $inputFile = Join-Path $gameRoot $binary
    if (-not (Test-Path -LiteralPath $inputFile -PathType Leaf)) { throw "Missing input: $inputFile" }
    $beforeHash = (Get-FileHash -LiteralPath $inputFile -Algorithm SHA256).Hash
    $projectName = $binary.Replace('.', '_')
    $summaryPath = Join-Path $recovered ($binary + '\summary.json')
    if (Test-Path -LiteralPath $summaryPath) { Remove-Item -LiteralPath $summaryPath }
    $arguments = @($projects, $projectName)
    if (Test-Path -LiteralPath (Join-Path $projects ($projectName + '.gpr'))) {
        # Preserve saved analysis and annotations when resuming an export.
        $arguments += @('-process', $binary, '-noanalysis')
    } else {
        $arguments += @('-import', $inputFile, '-analysisTimeoutPerFile', '1800')
    }
    $arguments += @('-scriptPath', $PSScriptRoot, '-postScript', 'ExportRecovery.java', $recovered,
        '-max-cpu', '4', '-log', (Join-Path $logs ($projectName + '.log')),
        '-scriptlog', (Join-Path $logs ($projectName + '-script.log')))
    & $launcher @arguments
    if ($LASTEXITCODE -ne 0) { throw "Ghidra failed for $binary with exit code $LASTEXITCODE" }
    if (-not (Test-Path -LiteralPath $summaryPath)) {
        throw "Export did not complete for $binary; inspect the log."
    }
    if ((Get-FileHash -LiteralPath $inputFile -Algorithm SHA256).Hash -ne $beforeHash) {
        throw "Input changed during analysis: $binary"
    }
}
