# Authorized local incident-response workflow. Does not restore to the original path or execute anything.
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{32}$')][string]$EvidenceId,
      [Parameter(Mandatory=$true)][string]$IsolatedReviewDirectory)
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run in an elevated local PowerShell session.' }
Add-Type -AssemblyName System.Security
$vault = Join-Path $env:ProgramData 'LinkScope\data\endpoint\quarantine'
$meta = Get-Content -LiteralPath (Join-Path $vault "$EvidenceId.json") -Raw | ConvertFrom-Json
if ($meta.id -ne $EvidenceId -or $meta.sha256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'Invalid evidence metadata.' }
$dir = Get-Item -LiteralPath $IsolatedReviewDirectory
if (-not $dir.PSIsContainer -or ($dir.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $dir.FullName.StartsWith('\\')) { throw 'Use an existing, restricted local review directory.' }
$out = Join-Path $dir.FullName "$EvidenceId.bin"
if (Test-Path -LiteralPath $out) { throw 'Refusing to overwrite review evidence.' }
if ($PSCmdlet.ShouldProcess($out,'Export potentially malicious bytes for isolated forensic analysis')) {
    $encrypted = [IO.File]::ReadAllBytes((Join-Path $vault "$EvidenceId.sealed"))
    $bytes = [Security.Cryptography.ProtectedData]::Unprotect($encrypted,$null,[Security.Cryptography.DataProtectionScope]::LocalMachine)
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $hash = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
        if ($hash -ne $meta.sha256) { throw 'Evidence hash mismatch.' }
        $file = [IO.File]::Open($out,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $file.Write($bytes,0,$bytes.Length); $file.Flush($true) } finally { $file.Dispose() }
        $record = @{utc=[DateTime]::UtcNow.ToString('o');actor=$identity.Name;id=$EvidenceId;sha256=$hash;operation='isolated evidence export';destination=$out} | ConvertTo-Json -Compress
        Add-Content -LiteralPath (Join-Path $vault 'local-recovery-audit.jsonl') -Value $record -Encoding UTF8
        Write-Warning 'Potentially malicious evidence exported. Never execute or restore it to production without independent review.'
    } finally { [Array]::Clear($bytes,0,$bytes.Length) }
}
