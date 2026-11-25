# Runs with the service identity. Inputs select fixed local readers.
$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
$kind = $env:LINKSCOPE_CATEGORY
function EventRows {
    $limit = [int]$env:LINKSCOPE_LIMIT
    $cutoff = [DateTime]::UtcNow.AddHours(-24)
    foreach ($channel in ($env:LINKSCOPE_CHANNELS -split '\|')) {
        try {
            $list = @(Get-WinEvent -FilterHashtable @{LogName=$channel; StartTime=$cutoff; Level=1,2,3} -MaxEvents ($limit+1))
            $rows = @(foreach ($e in @($list | Select-Object -First $limit)) {
                $row = [ordered]@{ utc=$e.TimeCreated.ToUniversalTime().ToString('o'); level=@('','Critical','Error','Warning')[[int]$e.Level]; provider=$e.ProviderName; eventId=$e.Id; recordId=$e.RecordId }
                if ($kind -eq 'event_details') {
                    $msg = [string]$e.Message
                    $row.message = $msg.Substring(0,[Math]::Min(512,$msg.Length))
                }
                [pscustomobject]$row
            })
            [pscustomobject]@{channel=$channel; status='ok'; truncated=($list.Count -gt $limit); items=$rows}
        } catch {
            $status = if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { 'ok' } else { 'unavailable' }
            [pscustomobject]@{channel=$channel; status=$status; truncated=$false; items=@()}
        }
    }
}
# Each inventory entry specifies a local WMI class and the exact fields released.
$catalog = @{
    os=@('Win32_OperatingSystem','Caption,Version,BuildNumber,OSArchitecture,LastBootUpTime')
    computer=@('Win32_ComputerSystem','Name,Manufacturer,Model,Domain,NumberOfLogicalProcessors,TotalPhysicalMemory')
    bios=@('Win32_BIOS','Manufacturer,SMBIOSBIOSVersion,ReleaseDate')
    baseboard=@('Win32_BaseBoard','Manufacturer,Product,Version')
    processors=@('Win32_Processor','Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed')
    memory_modules=@('Win32_PhysicalMemory','BankLabel,Capacity,Speed,Manufacturer,PartNumber')
    graphics=@('Win32_VideoController','Name,DriverVersion,VideoProcessor')
    network_adapters=@('Win32_NetworkAdapter','NetConnectionID,Name,MACAddress,Speed,NetEnabled')
    ip_addresses=@('Win32_NetworkAdapterConfiguration','Description,IPEnabled,IPAddress,IPSubnet,DefaultIPGateway,DHCPEnabled')
    dns=@('Win32_NetworkAdapterConfiguration','Description,IPEnabled,DNSDomain,DNSServerSearchOrder')
    routes=@('Win32_IP4RouteTable','Destination,Mask,NextHop,InterfaceIndex,Metric1')
    volumes=@('Win32_Volume','DriveLetter,Label,FileSystem,Capacity,FreeSpace')
    partitions=@('Win32_DiskPartition','DiskIndex,Index,Type,Size,BootPartition')
    services=@('Win32_Service','Name,DisplayName,State,StartMode')
    processes=@('Win32_Process','Name,ProcessId,WorkingSetSize,ThreadCount')
    hotfixes=@('Win32_QuickFixEngineering','HotFixID,Description,InstalledOn')
    drivers=@('Win32_PnPSignedDriver','DeviceName,Manufacturer,DriverVersion,IsSigned')
    pnp_devices=@('Win32_PnPEntity','Name,PNPClass,Status,ConfigManagerErrorCode')
    usb=@('Win32_USBController','Name,Manufacturer,Status')
    battery=@('Win32_Battery','Name,BatteryStatus,EstimatedChargeRemaining,EstimatedRunTime')
    shares=@('Win32_Share','Name,Type,Description')
    printers=@('Win32_Printer','Name,DriverName,PrinterStatus,WorkOffline')
    pagefile=@('Win32_PageFileUsage','Name,AllocatedBaseSize,CurrentUsage,PeakUsage')
    time_zone=@('Win32_TimeZone','Caption,StandardName,Bias')
}
try {
    $cap = 256
    $rows = @(switch ($kind) {
        events { EventRows }
        event_details { EventRows }
        firewall {
            Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
                [pscustomobject]@{profile=[string]$_.Name; enabled=[string]$_.Enabled; inboundDefault=[string]$_.DefaultInboundAction; outboundDefault=[string]$_.DefaultOutboundAction}
            }
        }
        antivirus {
            $defender = $null; $registered = @(); $registration = 'unavailable'
            try {
                $defender = Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AMRunningMode,AntivirusSignatureVersion,AntivirusSignatureAge
            } catch {}
            try {
                $registered = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName,productState)
                $registration = 'ok'
            } catch {}
            if (($null -eq $defender) -and $registration -eq 'unavailable') { throw 'Providers unavailable' }
            [pscustomobject]@{defender=$defender; registrationStatus=$registration; registeredProducts=$registered}
        }
        installed_software {
            foreach ($path in 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
                if (Test-Path ($path.Substring(0,$path.Length-2))) {
                    Get-ItemProperty $path | Where-Object DisplayName | Select-Object -First ($cap+1) DisplayName,DisplayVersion,Publisher
                }
            }
        }
        default {
            if (!$catalog.ContainsKey($kind)) { throw 'Unknown category' }
            $spec = $catalog[$kind]; $fields = $spec[1].Split(',')
            Get-CimInstance -ClassName $spec[0] -Property $fields -OperationTimeoutSec 12 |
                Select-Object -First ($cap+1) -Property $fields | ForEach-Object {
                    $row = [ordered]@{}
                    foreach ($field in $fields) {
                        $value = $_.$field
                        if ($value -is [datetime]) { $value = $value.ToUniversalTime().ToString('o') }
                        $row[$field]=$value
                    }
                    [pscustomobject]$row
                }
        }
    })
    $status = 'ok'
    if ($kind -in 'events','event_details' -and @($rows | Where-Object status -eq 'unavailable').Count -gt 0) { $status='partial' }
    $result = @{status=$status; truncated=($rows.Count -gt $cap); items=@($rows | Select-Object -First $cap)}
} catch { $result = @{status='unavailable';items=@();reason='Windows provider unavailable or access denied'} }
[Console]::Write((ConvertTo-Json -InputObject $result -Depth 8 -Compress))
