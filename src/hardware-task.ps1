$ErrorActionPreference='Stop'
$name='LinkScope SMART'
$exe=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'LinkScope\LinkScope.exe'
# Upgrade-only migration: remove exactly the retired tasks owned by this installation.
# Do not touch unrelated tasks or stop a running maintenance operation.
$legacyTasks=@{
    'Unixfor LinkScope SMART'='--smart-once';
    'Unixfor LinkScope Restart'='--restart-installed';
    'Unixfor LinkScope Signature Update'='--signature-update-installed';
    'Unixfor LinkScope ClamD Query Access'='--clam-peer-access-installed'
}
$oldTasks=@(Get-ScheduledTask -TaskPath '\' | Where-Object { $legacyTasks.ContainsKey($_.TaskName) })
foreach($task in $oldTasks){
    if (@($task.Actions).Count -ne 1 -or $task.Actions[0].Execute -ne $exe -or $task.Actions[0].Arguments -ne $legacyTasks[$task.TaskName]) {throw 'A retired task name is used by a different action; review Task Scheduler before upgrading.'}
    if ($task.State -eq 'Running') {throw 'A previous LinkScope maintenance task is running. Retry after completion.'}
}
foreach($task in $oldTasks){Unregister-ScheduledTask -TaskPath '\' -TaskName $task.TaskName -Confirm:$false}
$existing=Get-ScheduledTask -TaskPath '\' | Where-Object TaskName -eq $name
if ($existing -and (@($existing.Actions).Count -ne 1 -or $existing.Actions[0].Execute -ne $exe -or $existing.Actions[0].Arguments -ne '--smart-once')) {
    throw 'A different task uses the LinkScope SMART task name.'
}
$restartName='LinkScope Restart'
$restart=Get-ScheduledTask -TaskPath '\' | Where-Object TaskName -eq $restartName
if ($restart -and (@($restart.Actions).Count -ne 1 -or $restart.Actions[0].Execute -ne $exe -or $restart.Actions[0].Arguments -ne '--restart-installed')) {
    throw 'A different task uses the LinkScope restart task name.'
}
$signatureName='LinkScope Signature Update'
$signature=Get-ScheduledTask -TaskPath '\' | Where-Object TaskName -eq $signatureName
if ($signature -and (@($signature.Actions).Count -ne 1 -or $signature.Actions[0].Execute -ne $exe -or $signature.Actions[0].Arguments -ne '--signature-update-installed')) {
    throw 'A different task uses the LinkScope signature update task name.'
}
$peerName='LinkScope ClamD Query Access'
$peer=Get-ScheduledTask -TaskPath '\' | Where-Object TaskName -eq $peerName
if ($peer -and (@($peer.Actions).Count -ne 1 -or $peer.Actions[0].Execute -ne $exe -or $peer.Actions[0].Arguments -ne '--clam-peer-access-installed')) {
    throw 'A different task uses the LinkScope ClamD query-access task name.'
}
if ($signature -and $signature.State -eq 'Running') { throw 'Wait for the ClamAV signature update to finish before upgrading or removing LinkScope.' }
if ($env:LINKSCOPE_TASK_ACTION -eq 'remove') {
    if ($peer) { if ($peer.State -eq 'Running') { Stop-ScheduledTask -TaskName $peerName }; Unregister-ScheduledTask -TaskPath '\' -TaskName $peerName -Confirm:$false }
    if ($signature) { Unregister-ScheduledTask -TaskPath '\' -TaskName $signatureName -Confirm:$false }
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
# Demand-only, no argument substitution, no browser-controlled command or path.
$updateDef=$scheduler.NewTask(0)
$updateDef.RegistrationInfo.Description='Run one verified local FreshClam update and reload ClamD.'
$updateDef.Principal.UserId='SYSTEM'
$updateDef.Principal.LogonType=5
$updateDef.Principal.RunLevel=1
$updateDef.Settings.MultipleInstances=2
$updateDef.Settings.AllowDemandStart=$true
$updateDef.Settings.DisallowStartIfOnBatteries=$false
$updateDef.Settings.StopIfGoingOnBatteries=$false
$updateDef.Settings.ExecutionTimeLimit='PT35M'
$updateAction=$updateDef.Actions.Create(0)
$updateAction.Path=$exe
$updateAction.Arguments='--signature-update-installed'
$updateAction.WorkingDirectory=Split-Path $exe
$scheduler.GetFolder('\').RegisterTaskDefinition($signatureName,$updateDef,6,'SYSTEM',$null,5,$acl) | Out-Null
Start-ScheduledTask -TaskName $name

# Periodic fixed-action query-only ACL maintenance. Not callable by the web service;
# no variable arguments, executable paths, PIDs, or privileges provided by the dashboard.
$peerDef=$scheduler.NewTask(0)
$peerDef.RegistrationInfo.Description='Grant only PROCESS_QUERY_LIMITED_INFORMATION on the standard ClamD process to NT SERVICE\LinkScope.'
$peerDef.Principal.UserId='SYSTEM'
$peerDef.Principal.LogonType=5
$peerDef.Principal.RunLevel=1
$peerDef.Settings.MultipleInstances=2
$peerDef.Settings.AllowDemandStart=$true
$peerDef.Settings.StartWhenAvailable=$true
$peerDef.Settings.DisallowStartIfOnBatteries=$false
$peerDef.Settings.StopIfGoingOnBatteries=$false
$peerDef.Settings.ExecutionTimeLimit='PT30S'
$peerTrigger=$peerDef.Triggers.Create(1)
$peerTrigger.StartBoundary=(Get-Date).AddMinutes(1).ToString('yyyy-MM-ddTHH:mm:ss')
$peerTrigger.Repetition.Interval='PT1M'
$peerAction=$peerDef.Actions.Create(0)
$peerAction.Path=$exe
$peerAction.Arguments='--clam-peer-access-installed'
$peerAction.WorkingDirectory=Split-Path $exe
$scheduler.GetFolder('\').RegisterTaskDefinition($peerName,$peerDef,6,'SYSTEM',$null,5,'D:P(A;;GA;;;SY)(A;;GA;;;BA)') | Out-Null
