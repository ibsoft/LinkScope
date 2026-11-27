# Build the actual project, not the solution's potentially excluded project selection.
# No source, Git metadata, installed program or deployment package is deleted.
[CmdletBinding()]
param(
    [ValidateSet('Build','Clean','Rebuild')][string]$Mode = 'Rebuild',
    [ValidateSet('Debug','Release')][string]$Configuration = 'Release'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$project = Join-Path $root 'LinkScope.csproj'
$bin = Join-Path $root "bin\$Configuration"
$app = Join-Path $bin 'LinkScope.exe'
$setup = Join-Path $bin 'LinkScopeSetup.exe'
$logs = Join-Path $root 'build-logs'
$stamp = (Get-Date -Format 'yyyyMMdd-HHmmss-fff')
function Find-MSBuild {
    # Prefer the installed Visual Studio/MSBuild toolset, not the legacy Framework 4 executable.
    $pf86 = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
    $vswhere = Join-Path $pf86 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere -PathType Leaf) {
        $installations = @(& $vswhere -all -products '*' -requires Microsoft.Component.MSBuild -property installationPath -sort)
        foreach ($installation in $installations) {
            foreach ($relative in @('MSBuild\Current\Bin\amd64\MSBuild.exe','MSBuild\Current\Bin\MSBuild.exe')) {
                $candidate = Join-Path $installation $relative
                if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
            }
        }
    }
    $command = Get-Command MSBuild.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command -and [Diagnostics.FileVersionInfo]::GetVersionInfo($command.Source).FileMajorPart -ge 16) { return $command.Source }
    throw 'Visual Studio 2019 or later MSBuild not found. Install the .NET desktop development workload and .NET Framework 4.8 targeting pack, or use Developer PowerShell.'
}
function Run-Target([string]$Target) {
    $log = Join-Path $logs "$stamp-$Configuration-$Target.log"
    Write-Host "`n=== $Target LinkScope.csproj ($Configuration|x64) ===" -ForegroundColor Cyan
    Write-Host "MSBuild: $script:msbuild"
    Write-Host "Log: $log"
    $arguments = @($project, "/t:$Target", "/p:Configuration=$Configuration", '/p:Platform=x64', '/p:DesignTimeBuild=false', '/p:SkipCompilerExecution=false', '/p:BuildProjectReferences=true', '/m:1', '/nr:false', '/nologo', '/v:normal', '/fl', "/flp:LogFile=$log;Verbosity=diagnostic;Encoding=UTF-8")
    & $script:msbuild @arguments
    $code = $LASTEXITCODE
    if ($code -ne 0) { throw "MSBuild $Target failed (exit $code). See $log" }
}
try {
    if (-not (Test-Path -LiteralPath $project -PathType Leaf)) { throw "Missing $project" }
    $script:msbuild = Find-MSBuild
    New-Item -ItemType Directory -Path $logs -Force | Out-Null
    Push-Location -LiteralPath $root
    try {
        if ($Mode -eq 'Clean' -or $Mode -eq 'Rebuild') {
            Run-Target 'Clean'
            foreach ($output in @($app,$setup)) {
                if (Test-Path -LiteralPath $output) { throw "Clean did not remove $output. Close any running build-output executables, then retry. See build-logs." }
            }
            Write-Host 'Clean verified: application and setup outputs are absent.' -ForegroundColor Green
        }
        if ($Mode -ne 'Clean') {
            Run-Target 'Build'
            foreach ($output in @($app,$setup)) {
                if (-not (Test-Path -LiteralPath $output -PathType Leaf)) { throw "MSBuild reported success but the required output is missing: $output" }
            }
            # Verify x64 setup and that it embeds the exact newly built application, without executing either.
            & (Join-Path $root 'tests\Verify-VisualStudioSetup.ps1') -OutputDirectory $bin
            Write-Host "Application: $app" -ForegroundColor Green
            Write-Host "Setup:       $setup" -ForegroundColor Green
        }
    } finally { Pop-Location }
    Write-Host "`n$Mode completed and outputs verified." -ForegroundColor Green
    exit 0
} catch {
    Write-Host "`nERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'No installation or upgrade was attempted.'
    exit 1
}
