# Read-only administrator acceptance test; creates only a benign whoami process.
# This does not prove that the LinkScope service can read the Security log.
# Run from elevated Windows PowerShell after installation.
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this test in elevated Windows PowerShell.' }
& "$env:SystemRoot\System32\auditpol.exe" '/get' '/subcategory:{0cce922b-69ae-11d9-bed3-505054503030}'
if ($LASTEXITCODE -ne 0) { throw 'Audit policy query failed.' }
$started = (Get-Date).AddSeconds(-1)
$child = Start-Process -FilePath "$env:SystemRoot\System32\whoami.exe" -WindowStyle Hidden -PassThru -Wait
$childId = $child.Id
$match = $null
$deadline = (Get-Date).AddSeconds(15)
do {
    $events = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=$started} -ErrorAction SilentlyContinue)
    foreach ($event in $events) {
        $xml = [xml]$event.ToXml()
        $pidField = @($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'NewProcessId' }) | Select-Object -First 1
        $imageField = @($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'NewProcessName' }) | Select-Object -First 1
        if ($null -ne $pidField -and $null -ne $imageField) {
            $raw = [string]$pidField.'#text'
            if ($raw -match '^0x[0-9a-fA-F]+$' -and [Convert]::ToInt64($raw.Substring(2),16) -eq $childId -and [IO.Path]::GetFileName([string]$imageField.'#text') -ieq 'whoami.exe') { $match = $event; break }
        }
    }
    if (-not $match) { Start-Sleep -Milliseconds 500 }
} until ($match -or (Get-Date) -ge $deadline)
if (-not $match) { throw 'Fresh 4688 event not verified. Review audit policy and Security log. No protection verdict inferred.' }
Write-Host "Administrator verified fresh Security event 4688, record $($match.RecordId)."
Get-Service LinkScope,LinkScopeUsn | Format-Table Name,Status
Write-Host 'Next: verify actual service access and process audit status in LinkScope. This test does not certify coverage.'
