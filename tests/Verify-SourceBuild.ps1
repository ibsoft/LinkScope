# Run from Developer PowerShell for Visual Studio on Windows (.NET Framework 4.8).
param([ValidateSet('Debug','Release')][string]$Configuration = 'Release', [switch]$FullBuild)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$project = Join-Path $root 'LinkScope.csproj'
$guard = Join-Path $root 'tools\Assert-EndpointSources.ps1'
$msbuild = (Get-Command MSBuild.exe -ErrorAction Stop).Source
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('LinkScope-compile-check-' + [Guid]::NewGuid().ToString('N') + '.txt')
try {
    $files = @(Get-ChildItem -LiteralPath (Join-Path $root 'src') -Filter '*.cs' -File)
    $mixed = @(foreach ($f in $files) {
        if ($f.Name -eq 'CanaryTemplates.cs') { 'src\' + $f.Name } else { $f.FullName }
    })
    [IO.File]::WriteAllLines($fixture,[string[]]$mixed)
    & $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $guard -CompileList $fixture
    if ($LASTEXITCODE -ne 0) { throw 'Preflight rejected a complete compiler list.' }
    [IO.File]::WriteAllLines($fixture,[string[]]@($mixed | Where-Object { $_ -notmatch 'CanaryTemplates\.cs$' }))
    & $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $guard -CompileList $fixture
    if ($LASTEXITCODE -eq 0) { throw 'Preflight accepted missing CanaryTemplates.cs.' }
    [IO.File]::WriteAllLines($fixture,[string[]]@($mixed + (Join-Path $root 'src\EndpointResponse.cs')))
    & $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $guard -CompileList $fixture
    if ($LASTEXITCODE -eq 0) { throw 'Preflight accepted duplicate EndpointResponse.cs.' }
    & $msbuild $project /t:VerifyEndpointProtectionSource "/p:Configuration=$Configuration" /p:Platform=x64 /nologo
    if ($LASTEXITCODE -ne 0) { throw 'Real MSBuild compile-item refresh or preflight failed.' }
    if ($FullBuild) {
        $outputDirectory = Join-Path $root "bin\$Configuration"
        # Seed the output folder with verified genuine build outputs using the independent project path.
        & $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $root 'tools\Invoke-ProjectBuild.ps1') -Mode Rebuild -Configuration $Configuration
        if ($LASTEXITCODE -ne 0) { throw 'Direct project rebuild failed.' }
        # This now detects solution skips even when stale output binaries already existed.
        & $msbuild (Join-Path $root 'LinkScope.sln') /t:Clean "/p:Configuration=$Configuration" /p:Platform=x64 /nologo
        if ($LASTEXITCODE -ne 0) { throw 'Solution Clean failed.' }
        foreach ($name in @('LinkScope.exe','LinkScopeSetup.exe')) {
            if (Test-Path -LiteralPath (Join-Path $outputDirectory $name)) { throw "Solution Clean skipped the project: $name still exists." }
        }
        & $msbuild (Join-Path $root 'LinkScope.sln') /t:Rebuild "/p:Configuration=$Configuration" /p:Platform=x64 /nologo
        if ($LASTEXITCODE -ne 0) { throw 'Application/setup solution compilation failed.' }
        & (Join-Path $PSScriptRoot 'Verify-VisualStudioSetup.ps1') -OutputDirectory $outputDirectory
    }
    Write-Host 'PASS: actual MSBuild input list and preflight negative cases.'
} finally { Remove-Item -LiteralPath $fixture -Force -ErrorAction SilentlyContinue }
