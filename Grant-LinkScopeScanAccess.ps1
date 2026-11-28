# Windows PowerShell 5.1; run locally as administrator. No web elevation endpoint.
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true)][string]$Path,
    [switch]$AllowProfileRoot
)
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Open Windows PowerShell as Administrator.' }
if ($Path -notmatch '^[A-Za-z]:\\' -or $Path.Substring(2).Contains(':') -or $Path -match '[*?]') { throw 'Supply a literal absolute local directory path.' }
$target = [IO.Path]::GetFullPath($Path).TrimEnd('\')
if ($target.Length -le 3) { throw 'Drive-root permission changes are prohibited.' }
$service = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\LinkScope'
if ($service.ObjectName -ne 'NT AUTHORITY\LocalService' -or $service.ServiceSidType -ne 1) { throw 'Expected LinkScope LocalService with unrestricted service SID. Run Upgrade / repair first.' }
$sid = ([Security.Principal.NTAccount]::new('NT SERVICE','LinkScope')).Translate([Security.Principal.SecurityIdentifier])
# Only a registered, non-system local user profile or a directory within it is permitted.
$profiles = @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' | ForEach-Object {
    if ($_.PSChildName -match '^S-1-(5-21|12-1)-') {
        $raw = (Get-ItemProperty -LiteralPath $_.PSPath).ProfileImagePath
        if ($raw) { [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($raw)).TrimEnd('\') }
    }
})
$profile = $profiles | Where-Object { $target.Equals($_,[StringComparison]::OrdinalIgnoreCase) -or $target.StartsWith($_+'\',[StringComparison]::OrdinalIgnoreCase) } | Sort-Object Length -Descending | Select-Object -First 1
if (-not $profile) { throw 'Choose a registered local user profile directory (or a subdirectory), not a drive or system directory.' }
if ($target.Equals($profile,[StringComparison]::OrdinalIgnoreCase) -and -not $AllowProfileRoot) { throw 'The entire profile contains private files and application data. Choose a narrower folder, or explicitly specify -AllowProfileRoot.' }
# Match an exact configured scan directory. This is not a general-purpose ACL editor.
$configPath = Join-Path $env:ProgramData 'LinkScope\settings\config.json'
$config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
if (-not $config.Endpoint.Enabled -or -not (@($config.Endpoint.Paths) | Where-Object { $_ -and [IO.Path]::GetFullPath($_).TrimEnd('\').Equals($target,[StringComparison]::OrdinalIgnoreCase) })) { throw 'Enable Endpoint Protection and save this exact directory in Protected paths first.' }
# Check the directory and all ancestors, refusing junctions and symlinks.
$item = Get-Item -LiteralPath $target -Force
if (-not $item.PSIsContainer) { throw 'Only directories are supported.' }
for ($ancestor=$item; $null -ne $ancestor; $ancestor=$ancestor.Parent) {
    if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw ('Reparse point refused: '+$ancestor.FullName) }
}
Write-Host ('Selected path: '+$target)
Write-Host ('Dedicated service SID: '+$sid.Value)
Write-Warning 'This grants inheritable read/list access to the selected directory, potentially including private files. It does not grant write, delete, ownership or ACL modification rights. Existing protected child ACLs may still deny access. Windows may take time to propagate inheritance.'
Write-Host 'No /T recursive ACL rewrite, no changes to parent directories, no change to the service account.'
if ($PSCmdlet.ShouldProcess($target,'Add inheritable read-only access for NT SERVICE\LinkScope')) {
    $grant = '*'+$sid.Value+':(OI)(CI)(R)'
    & (Join-Path $env:SystemRoot 'System32\icacls.exe') $target /grant $grant /L
    if ($LASTEXITCODE -ne 0) { throw 'icacls reported failure. Review the output; some permissions may already have changed.' }
    Write-Host 'ACL operation completed. This is not proof of effective access; run the service file probe and check coverage.'
    Write-Host 'V20 retries failed watcher roots every 60 seconds. Alternatively, restart LinkScope locally after the grant.'
}
