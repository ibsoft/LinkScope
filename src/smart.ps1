$ErrorActionPreference='Stop'
$WarningPreference='SilentlyContinue'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$limit=[int]$env:LINKSCOPE_LIFE
function ShortId($identity) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try { [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$identity))).Replace('-','').Substring(0,24) }
    finally { $sha.Dispose() }
}
function DriveReport($n,$d,$nativeStatus) {
    $findings=New-Object 'Collections.Generic.List[string]'
    $diags=New-Object 'Collections.Generic.List[string]'
    foreach ($entry in $n.diagnostics) { $diags.Add([string]$entry) }
    if (!$n) { $diags.Add("Direct SMART reader: $nativeStatus. No positively matched hardware record.") }
    $counter=$null
    if ($d) { try { $counter=$d | Get-StorageReliabilityCounter } catch { $diags.Add('Windows reliability counters unavailable.') } }
    $model=if ($n) { $n.model } else { [string]$d.FriendlyName }
    $serial=if ($n.serial) { $n.serial } else { [string]$d.SerialNumber }
    $firmware=if ($n.firmware) { $n.firmware } else { [string]$d.FirmwareVersion }
    $capacity=if ($n.capacityBytes) { $n.capacityBytes } else { $d.Size }
    $device=if ($n) { $n.device } else { [string]$d.DeviceId }
    $bus=if ($n) { $n.bus } else { [string]$d.BusType }
    $vendor=if ($n.vendor) { $n.vendor } elseif ($model -match 'Samsung') { 'Samsung' } else { [string]$d.Manufacturer }
    $health=[string]$d.HealthStatus; $op=@($d.OperationalStatus | Where-Object { $_ } | ForEach-Object { [string]$_ })
    $attrs=@($n.attributes | Where-Object { $null -ne $_ }); $nv=$n.nvme
    $wear=$null; $remaining=$null; $lifeSource=$null; $level=0
    $evidence=@($attrs | Where-Object { $null -ne $_.threshold }).Count -eq $attrs.Count -and $attrs.Count -gt 0
    if ($evidence -or $nv) { $level=1 }
    if ($null -ne $counter.Wear) { $wear=[int]$counter.Wear; $lifeSource='Windows Storage wear'; $level=1 }
    if ($nv) {
        $wear=[int]$nv.percentageUsed; $lifeSource='NVMe percentage used'
        if (([int]$nv.criticalWarning -band 12) -ne 0) { $level=4; $findings.Add('NVMe reports degraded reliability or read-only media.') }
        if (([int]$nv.criticalWarning -band 17) -or $nv.availableSparePercent -lt $nv.spareThresholdPercent) { $level=[Math]::Max($level,3); $findings.Add('NVMe reports a spare-capacity or backup-device warning.') }
        if (([int]$nv.criticalWarning -band 226) -or $nv.mediaErrors -ne '0') { $level=[Math]::Max($level,2); $findings.Add('Review NVMe critical warning bits and lifetime media errors.') }
    }
    # The normalized wear attribute is model-specific. Other controllers keep their raw values.
    if ($model -match '(?i)Samsung SSD 870 EVO' -and !$nv) {
        $a=$attrs | Where-Object id -eq 177 | Select-Object -First 1
        if ($a -and $a.value -ge 0 -and $a.value -le 100 -and ($null -eq $wear -or (100-[int]$a.value) -gt $wear)) {
            $wear=100-[int]$a.value; $lifeSource='Samsung 870 EVO normalized SMART 177 estimate'
        }
    }
    if ($null -ne $wear) {
        $remaining=[Math]::Max(0,100-$wear)
        if ($remaining -le $limit) { $level=[Math]::Max($level,3); $findings.Add("Estimated life remaining is $remaining%, at or below the configured $limit% threshold.") }
    }
    if ($n.predictFailure -eq $true -or $health -eq 'Unhealthy' -or ($op -contains 'Predictive Failure') -or ($op -contains 'Failed')) {
        $level=4; $findings.Add('Firmware or Windows Storage reports a physical disk failure condition.')
    }
    if ($health -eq 'Warning' -or $counter.ReadErrorsUncorrected -gt 0 -or $counter.WriteErrorsUncorrected -gt 0) {
        $level=[Math]::Max($level,2); $findings.Add('Review the Windows disk health warning or uncorrected I/O counters.')
    }
    foreach ($a in $attrs) {
        if ($a.state -eq 'FAIL') {
            $severity=if ($a.id -in 5,10,171,172,179,181,182,187,197,198) { 4 } else { 2 }
            $level=[Math]::Max($level,$severity); $findings.Add("SMART $($a.id) $($a.name) reached its manufacturer threshold.")
        } elseif ($a.state -eq 'REVIEW') {
            $level=[Math]::Max($level,2); $findings.Add("Review SMART $($a.id) $($a.name), raw value $($a.rawDecimal).")
        }
    }
    if (!$findings.Count) {
        if ($level -eq 0) { $findings.Add('Insufficient SMART evidence to assess replacement. Check the drive with its vendor diagnostic.') }
        else { $findings.Add('Available readings show no replacement trigger at scan time.') }
    }
    $state=@('unknown','normal','review','replace','replace')[$level]
    $head=@('UNABLE TO DETERMINE','NO REPLACEMENT INDICATED','MONITOR / INVESTIGATE','REPLACE SOON','REPLACE NOW')[$level]
    $advice=@('Obtain direct readings or vendor diagnostics.','Continue routine monitoring and backups.','Review the flagged counters and check whether they increase.','Verify backups and schedule disk replacement.','Protect the data immediately and arrange replacement.')[$level]
    $identity=if ($serial) { $model+'|'+$serial } elseif ($d.UniqueId) { [string]$d.UniqueId } else { $bus+'|'+$model+'|'+$device }
    $scan=if ($n.scanUtc) { $n.scanUtc } else { [datetime]::UtcNow.ToString('o') }
    [pscustomobject]@{diskId=(ShortId $identity); device=$device; model=$model; firmware=$firmware; serial=$serial; capacityBytes=$capacity; vendor=$vendor; bus=$bus
        scanUtc=$scan; reportBy='Unixfor LinkScope'; media=[string]$d.MediaType; health=$health; operational=$op
        recommendation=$state; headline=$head; advice=$advice; findings=@($findings.ToArray()); diagnostics=@($diags.ToArray())
        smartSource=$n.smartSource; attributes=$attrs; nvme=$nv; predictFailure=$n.predictFailure; wearUsedPercent=$wear; estimatedLifeRemainingPercent=$remaining
        lifeSource=$lifeSource; thresholdPercent=$limit; temperatureC=$(if ($null -ne $nv.temperatureC) { $nv.temperatureC } else { $counter.Temperature })
        powerOnHours=$(if ($nv) { $nv.powerOnHours } else { $counter.PowerOnHours }); readErrorsTotal=$counter.ReadErrorsTotal; writeErrorsTotal=$counter.WriteErrorsTotal
        readErrorsUncorrected=$counter.ReadErrorsUncorrected; writeErrorsUncorrected=$counter.WriteErrorsUncorrected; countersAvailable=($null -ne $counter) }
}
try {
    $hardware=@(); $nativeStatus='unavailable'
    $path=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'LinkScope\hardware.json'
    if (Test-Path -LiteralPath $path) {
        $cache=[IO.File]::ReadAllText($path) | ConvertFrom-Json
        $age=([datetimeoffset]::UtcNow - [datetimeoffset]::Parse($cache.scannedUtc)).TotalMinutes
        if ($age -ge 0 -and $age -le 15) { $hardware=@($cache.disks); $nativeStatus='current' } else { $nativeStatus='stale' }
    }
    $windows=@(); try { $windows=@(Get-PhysicalDisk) } catch {}
    $used=@{}
    $rows=@(foreach ($n in $hardware) {
        $serial=([string]$n.serial).Trim()
        $matches=@($windows | Where-Object { $serial -and ([string]$_.SerialNumber).Trim() -eq $serial })
        $same=@($hardware | Where-Object { $serial -and ([string]$_.serial).Trim() -eq $serial })
        if ($matches.Count -eq 1 -and $same.Count -eq 1) { $d=$matches[0]; $used[[string]$d.ObjectId]=$true; DriveReport $n $d $nativeStatus }
        else { DriveReport $n $null $nativeStatus }
    }
    foreach ($d in $windows) { if (!$used.ContainsKey([string]$d.ObjectId)) { DriveReport $null $d $nativeStatus } })
    $status=if (!$rows.Count) { 'unavailable' } elseif (@($rows | Where-Object recommendation -eq 'unknown').Count -gt 0) { 'partial' } else { 'ok' }
    $result=@{status=$status;hardwareReader=$nativeStatus;items=$rows}
} catch { $result=@{status='unavailable';reason='Windows disk inventory could not be read';items=@()} }
[Console]::Write((ConvertTo-Json -InputObject $result -Depth 10 -Compress))
