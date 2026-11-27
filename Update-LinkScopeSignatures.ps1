# Run locally under a trusted maintenance account; never called by the web service.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$FreshClamExe,
    [Parameter(Mandatory=$true)][string]$ConfigFile
)
$ErrorActionPreference = 'Stop'
$exe = Get-Item -LiteralPath $FreshClamExe
$config = Get-Item -LiteralPath $ConfigFile
if ($exe.Name -ine 'freshclam.exe' -or $exe.PSIsContainer -or $config.PSIsContainer) { throw 'Supply installed freshclam.exe and its configuration file.' }
if (-not ($exe.FullName.StartsWith(($env:ProgramFiles.TrimEnd('\')+'\'),[StringComparison]::OrdinalIgnoreCase))) { throw 'Use a trusted FreshClam installation under Program Files.' }
$lines = Get-Content -LiteralPath $config.FullName
if (-not ($lines -match '^\s*TestDatabases\s+yes\s*(?:#.*)?$')) { throw 'Set TestDatabases yes before updating.' }
foreach ($line in $lines) {
    if ($line -match '^\s*DatabaseCustomURL\s+(.+?)\s*$') {
        $uri = $null
        if (-not [Uri]::TryCreate($Matches[1],[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -ne 'https' -or $uri.UserInfo -or [IO.Path]::GetExtension($uri.AbsolutePath) -notin @('.ndb','.ldb','.hdb','.hsb')) { throw 'Custom feed must use an approved HTTPS URL with a supported content/hash signature extension.' }
    }
}
& $exe.FullName "--config-file=$($config.FullName)"
if ($LASTEXITCODE -ne 0) { throw "FreshClam failed (exit $LASTEXITCODE). Review its protected local log." }
Write-Output 'FreshClam completed. Verify ClamD reload and engine-reported database version in LinkScope.'
