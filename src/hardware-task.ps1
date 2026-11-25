$ErrorActionPreference='Stop'
$name='Unixfor LinkScope SMART'
$exe=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'LinkScope\LinkScope.exe'
$existing=Get-ScheduledTask -TaskPath '\' | Where-Object TaskName -eq $name
if ($existing -and (@($existing.Actions).Count -ne 1 -or $existing.Actions[0].Execute -ne $exe -or $existing.Actions[0].Arguments -ne '--smart-once')) {
    throw 'A different task uses the LinkScope SMART task name.'
}
$restartName='Unixfor LinkScope Restart'
$restart=Get-ScheduledTask -TaskPath '\' | Where-Object TaskName -eq $restartName
if ($restart -and (@($restart.Actions).Count -ne 1 -or $restart.Actions[0].Execute -ne $exe -or $restart.Actions[0].Arguments -ne '--restart-installed')) {
    throw 'A different task uses the LinkScope restart task name.'
}
if ($env:LINKSCOPE_TASK_ACTION -eq 'remove') {
    if ($restart) { Unregister-ScheduledTask -TaskPath '\' -TaskName $restartName -Confirm:$false }
    if ($existing) { if ($existing.State -eq 'Running') { Stop-ScheduledTask -TaskName $name }; Unregister-ScheduledTask -TaskName $name -Confirm:$false }
    return
}
$action=New-ScheduledTaskAction -Execute $exe -Argument '--smart-once' -WorkingDirectory (Split-Path $exe)
$trigger=New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(1)) -RepetitionInterval ([TimeSpan]::FromMinutes(5))
$principal=New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
$settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::FromMinutes(3)) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $name -TaskPath '\' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
# This on-demand task has one fixed action. Its read/execute ACE is specific to the LinkScope service SID.
$scheduler=New-Object -ComObject 'Schedule.Service'
$scheduler.Connect()
$definition=$scheduler.NewTask(0)
$definition.RegistrationInfo.Description='Apply saved LinkScope settings by restarting the installed LinkScope service.'
$definition.Principal.UserId='SYSTEM'
$definition.Principal.LogonType=5
$definition.Principal.RunLevel=1
$definition.Settings.MultipleInstances=2
$definition.Settings.DisallowStartIfOnBatteries=$false
$definition.Settings.StopIfGoingOnBatteries=$false
$definition.Settings.ExecutionTimeLimit='PT4M'
$restartAction=$definition.Actions.Create(0)
$restartAction.Path=$exe
$restartAction.Arguments='--restart-installed'
$restartAction.WorkingDirectory=Split-Path $exe
$account=[System.Security.Principal.NTAccount]::new('NT SERVICE','LinkScope')
$sid=$account.Translate([System.Security.Principal.SecurityIdentifier]).Value
$acl="D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;$sid)"
$scheduler.GetFolder('\').RegisterTaskDefinition($restartName,$definition,6,'SYSTEM',$null,5,$acl) | Out-Null
Start-ScheduledTask -TaskName $name
