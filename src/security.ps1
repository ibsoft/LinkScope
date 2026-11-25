$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
function Check([string]$control, [scriptblock]$reader) {
    try {
        $reading = & $reader
        if ($reading.state -notin 'enabled','disabled','unavailable') { throw 'Unknown state' }
        [pscustomobject]@{control=$control;state=$reading.state;detail=$reading.detail}
    } catch {
        [pscustomobject]@{control=$control;state='unavailable';detail='Provider unavailable, unsupported, or access denied.'}
    }
}
$items = @(
    Check 'UAC' {
        $value = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA).EnableLUA
        if ($null -eq $value -or $value -notin 0,1) { throw 'Unknown policy' }
        @{state=@('disabled','enabled')[[int]$value];detail='EnableLUA policy'}
    }
    Check 'Secure Boot' {
        $value = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($value -isnot [bool]) { throw 'Unknown firmware state' }
        @{state=@('disabled','enabled')[[int]$value];detail='UEFI Secure Boot'}
    }
    Check 'TPM' {
        $v=Get-Tpm -ErrorAction Stop
        if ($null -eq $v.TpmPresent -or $null -eq $v.TpmReady) { throw 'Unknown TPM state' }
        if (!$v.TpmPresent) { @{state='disabled';detail='TPM not present.'} }
        elseif (!$v.TpmReady) { @{state='disabled';detail='TPM present but not ready.'} }
        else { @{state='enabled';detail='TPM present and ready.'} }
    }
    Check 'BitLocker' {
        $v=Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        $state=switch ([string]$v.ProtectionStatus) { 'On' {'enabled'} 'Off' {'disabled'} default {'unavailable'} }
        @{state=$state;detail=("OS volume {0}, encryption {1}%." -f $env:SystemDrive,$v.EncryptionPercentage)}
    }
)
[pscustomobject]@{scannedUtc=[DateTime]::UtcNow.ToString('o');items=$items} | ConvertTo-Json -Depth 4 -Compress
