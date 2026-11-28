# Run on Windows PowerShell 5.1 after a full V78 Release build. No live web shell,
# no command execution, no application writes, no Windows policy changes.
param([string]$AssemblyPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'bin\Release\LinkScope.exe'))
$ErrorActionPreference = 'Stop'
$assembly = [Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath $AssemblyPath).Path)
$type = $assembly.GetType('LinkScope.WebServerProtection', $true)
$flags = [Reflection.BindingFlags]'Static, NonPublic'
$analyze = $type.GetMethod('Analyze', $flags)
$child = $type.GetMethod('SuspiciousChild', $flags)
$inspect = $type.GetMethod('Inspect', $flags)
function Assert-True([bool]$Condition, [string]$Description) {
    if (-not $Condition) { throw "FAIL: $Description" }
    Write-Host "PASS: $Description"
}
# Inert comment text: not executable scripts and not malware samples.
$match = '// $_POST is an input marker; shell_exec( is an execution marker.'
$clean = '// This is ordinary documentation with no request or execution markers.'
Assert-True ($analyze.Invoke($null, @($match)).StartsWith('Review: ')) 'Combined indicators produce a warning'
Assert-True ($analyze.Invoke($null, @($clean)) -eq 'No match') 'Benign text returns no match'
Assert-True ($analyze.Invoke($null, @('// shell_exec( is a single marker')) -eq 'No match') 'Single indicator does not qualify'
Assert-True ($child.Invoke($null, @('C:\Windows\System32\inetsrv\w3wp.exe','C:\Windows\System32\cmd.exe'))) 'IIS unexpected direct child'
Assert-True (-not $child.Invoke($null, @('C:\Windows\explorer.exe','C:\Windows\System32\cmd.exe'))) 'Unrelated parent does not qualify'
$stop = New-Object System.Threading.ManualResetEvent($false)
try {
    $stream = New-Object System.IO.MemoryStream(,([Text.Encoding]::UTF8.GetBytes($match)))
    try {
        $result = $inspect.Invoke($null, @($stream, $null, $stop))
        Assert-True ($result.StartsWith('Review: ') -and $stream.Position -eq 0) 'Full-stream inspection preserves stream position for antivirus'
    } finally { $stream.Dispose() }
    $stream = New-Object System.IO.MemoryStream
    try {
        $stream.SetLength(4194305)
        Assert-True ($inspect.Invoke($null, @($stream, $null, $stop)).StartsWith('Unverified: ')) 'Over-limit script is not presented as clean'
    } finally { $stream.Dispose() }
} finally { $stop.Dispose() }
Write-Host 'Pure managed rule tests completed. Live Windows audit, watcher, service and helper acceptance tests are still required.'
