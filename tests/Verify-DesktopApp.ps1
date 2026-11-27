# Run after setup on a disposable Windows test machine, as an ordinary desktop user.
# Add -ExpectManagedPwa only when no pre-existing web-app policy blocked registration.
param([string]$ExpectedOrigin='http://127.0.0.1:9876/',[switch]$ExpectManagedPwa)
$ErrorActionPreference='Stop'
$expected=([uri]$ExpectedOrigin).GetLeftPart([UriPartial]::Authority)+'/'
$shell=New-Object -ComObject WScript.Shell
try {
    foreach($folder in @([Environment]::GetFolderPath('CommonDesktopDirectory'),[Environment]::GetFolderPath('CommonPrograms'))) {
        $lnk=Join-Path $folder 'LinkScope.lnk';$url=Join-Path $folder 'LinkScope.url'
        if(Test-Path -LiteralPath $lnk -PathType Leaf){
            $shortcut=$shell.CreateShortcut($lnk)
            try {
                if($shortcut.Description -ne 'LinkScope desktop application (managed by LinkScope Setup)'){throw "Unmanaged shortcut: $lnk"}
                if($shortcut.Arguments -ne ('--app="'+$expected+'"')){throw "Unexpected arguments: $($shortcut.Arguments)"}
                if([IO.Path]::GetFileName($shortcut.TargetPath) -notin @('msedge.exe','chrome.exe')){throw 'Unexpected browser'}
                if(-not (Test-Path -LiteralPath $shortcut.TargetPath -PathType Leaf)){throw 'Browser missing'}
                $icon=$shortcut.IconLocation -replace ',\s*0$',''
                if(-not (Test-Path -LiteralPath $icon -PathType Leaf)){throw 'Public icon unavailable'}
                [void][IO.File]::ReadAllBytes($icon)
            } finally {[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shortcut)}
        } elseif(Test-Path -LiteralPath $url -PathType Leaf){
            $lines=Get-Content -LiteralPath $url
            if($lines[0] -ne '; LinkScope Setup managed shortcut' -or $lines -notcontains ('URL='+$expected)){throw "Unexpected URL shortcut: $url"}
        } else {throw "Missing LinkScope shortcut in $folder"}
        Write-Host "PASS: $folder"
    }
} finally {[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)}
if($ExpectManagedPwa){
    $policy=Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name WebAppInstallForceList
    $items=$policy|ConvertFrom-Json
    if(-not @($items|Where-Object {$_.url -eq $expected -and $_.default_launch_container -eq 'window'}).Count){throw 'Expected Edge managed PWA policy not found'}
    Write-Host 'PASS: Edge policy present. Open edge://policy and edge://apps in the intended user profile to verify actual installation.'
}
Write-Host 'Open the desktop icon, verify login and monitoring, then test uninstall on the disposable VM.'
