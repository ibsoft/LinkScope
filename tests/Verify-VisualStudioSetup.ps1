param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$dir = (Resolve-Path -LiteralPath $OutputDirectory).Path
$app = Join-Path $dir 'LinkScope.exe'
$setup = Join-Path $dir 'LinkScopeSetup.exe'
foreach ($file in @($app, $setup)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing output: $file" }
}
# Read the setup assembly as data, without executing its entry point.
$assembly = [Reflection.Assembly]::ReflectionOnlyLoad([IO.File]::ReadAllBytes($setup))
$payload = $assembly.GetManifestResourceStream('LinkScope.exe')
$wizard = $assembly.GetManifestResourceStream('wizard.ps1')
if ($null -eq $payload -or $null -eq $wizard) { throw 'Missing embedded application or wizard.' }
$sha = [Security.Cryptography.SHA256]::Create()
try {
    $actual = [BitConverter]::ToString($sha.ComputeHash($payload)).Replace('-', '')
    $expected = (Get-FileHash -LiteralPath $app -Algorithm SHA256).Hash
    if ($actual -ne $expected) { throw 'Setup contains an outdated or different application.' }
} finally { $payload.Dispose(); $wizard.Dispose(); $sha.Dispose() }
# PE file machine (AMD64) and subsystem (Windows GUI).
$reader = New-Object IO.BinaryReader([IO.File]::OpenRead($setup))
try {
    if ($reader.ReadUInt16() -ne 0x5A4D) { throw 'Invalid MZ signature.' }
    $reader.BaseStream.Position = 0x3c
    $pe = $reader.ReadInt32()
    $reader.BaseStream.Position = $pe
    if ($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne 0x8664) { throw 'Setup is not x64 PE.' }
    $reader.BaseStream.Position = $pe + 24
    if ($reader.ReadUInt16() -ne 0x20b) { throw 'Setup is not PE32+.' }
    $reader.BaseStream.Position = $pe + 24 + 68
    if ($reader.ReadUInt16() -ne 2) { throw 'Setup is not a Windows GUI executable.' }
} finally { $reader.Dispose() }
Write-Host "PASS: x64 GUI setup, embedded wizard, and exact application SHA-256: $expected"
