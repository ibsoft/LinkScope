$ErrorActionPreference='Stop'
$debugLog=Join-Path ([IO.Path]::GetTempPath()) 'LinkScope-Setup-debug.log'
function Write-DebugLog([string]$message){
 try {Add-Content -LiteralPath $debugLog -Value ((Get-Date).ToString('o')+' [wizard '+$PID+'] '+$message) -Encoding UTF8 -ErrorAction Stop}catch{}
}
Write-DebugLog 'Wizard starting' 
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::SetUnhandledExceptionMode([Windows.Forms.UnhandledExceptionMode]::CatchException)
[Windows.Forms.Application]::EnableVisualStyles()
$exe=$env:LINKSCOPE_SETUP_EXE
if(-not [IO.File]::Exists($exe)){throw 'Setup executable not found.'}
$msi=Join-Path ([IO.Path]::GetDirectoryName($exe)) 'deploy\clamav-latest.msi'
$sig=$msi+'.sig'
$logFolder=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'LinkScope Setup Logs'
$form=New-Object Windows.Forms.Form
$form.Text='LinkScope Setup'; $form.ClientSize=New-Object Drawing.Size(700,722); $form.StartPosition='CenterScreen'; $form.FormBorderStyle='FixedDialog'; $form.MaximizeBox=$false
$form.Icon=[Drawing.Icon]::ExtractAssociatedIcon($exe)
$form.ShowIcon=$true;$form.Font=New-Object Drawing.Font('Segoe UI',10);$form.AutoScaleMode='Dpi'
function Label($text,$x,$y,$w,$h){$l=New-Object Windows.Forms.Label;$l.Text=$text;$l.SetBounds($x,$y,$w,$h);$form.Controls.Add($l);return $l}
function Button($text,$x,$y,$w){$b=New-Object Windows.Forms.Button;$b.Text=$text;$b.SetBounds($x,$y,$w,34);$form.Controls.Add($b);return $b}
$head=Label 'LinkScope | Installation wizard' 0 0 700 70
$head.BackColor=[Drawing.Color]::FromArgb(19,49,65);$head.ForeColor=[Drawing.Color]::White;$head.Font=New-Object Drawing.Font('Segoe UI',19,[Drawing.FontStyle]::Bold);$head.TextAlign='MiddleCenter'
$brand=New-Object Windows.Forms.PictureBox;$brand.Image=$form.Icon.ToBitmap();$brand.SizeMode='Zoom';$brand.SetBounds(18,15,40,40);$brand.BackColor=$head.BackColor;$form.Controls.Add($brand);$brand.BringToFront()
$intro=Label 'Install, upgrade or remove LinkScope. Changes require administrator approval.' 24 85 652 42
$state=Label '' 24 135 652 26
$install=Button 'Install LinkScope' 24 168 212
$remove=Button 'Uninstall service' 246 168 206
$dashboard=Button 'Open default dashboard' 462 168 214
$clamTitle=Label 'ClamAV | Optional antivirus engine' 24 221 652 26
$clamTitle.Font=New-Object Drawing.Font('Segoe UI',11,[Drawing.FontStyle]::Bold)
$clamState=Label 'Checking installation and engine readiness...' 24 252 652 62
$clamButton=Button 'Install and configure ClamAV' 24 318 246
$checkButton=Button 'Check again' 280 318 130
$update=Button 'Update signatures' 420 318 256
$providers=Button 'Third-party signature sources...' 24 359 410
$clamRemove=Button 'Uninstall ClamAV' 444 359 232
$pwa=New-Object Windows.Forms.CheckBox;$pwa.Text='Register managed Edge PWA (local policy; optional)';$pwa.Checked=$true;$pwa.SetBounds(24,401,652,26);$form.Controls.Add($pwa)
$pwaNote=Label 'Desktop shortcut is created by default. Managed Edge PWA installs at browser launch and cannot be removed in Edge. Existing policies are preserved.' 24 429 652 45
$canaries=New-Object Windows.Forms.CheckBox;$canaries.Text='Create and enroll Word, Excel and text canaries in my Documents';$canaries.Checked=$true;$canaries.SetBounds(24,474,652,25);$form.Controls.Add($canaries)
$note=Label 'ClamAV settings are preserved. Definitions need Internet access. Canaries enable Monitor mode only if protection was disabled.' 24 505 652 72
$progress=New-Object Windows.Forms.ProgressBar;$progress.SetBounds(24,590,652,16);$form.Controls.Add($progress)
$status=Label 'Ready.' 24 616 550 58
$close=Button 'Close' 586 627 90
$debugButton=Button 'Open debug log' 24 676 160
$debugButton.Add_Click({try{Write-DebugLog 'Debug log opened';Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\notepad.exe') -ArgumentList ('"'+$debugLog+'"')}catch{$status.Text=$_.Exception.Message}})
$timer=New-Object Windows.Forms.Timer;$timer.Interval=500
$script:job=$null;$script:operation='';$script:pendingInstall=$false;$script:clamCheck=1;$script:rebootRequired=$false;$script:checking=$false
$clamRemove.Enabled=$false
$form.AutoScroll=$true
$form.AutoScrollMinSize=New-Object Drawing.Size(700,720)
$area=[Windows.Forms.Screen]::FromControl($form).WorkingArea
$form.Height=[Math]::Min($form.Height,$area.Height-24)
function Is-ClamOperation($verb){return ($verb -in @('--install-clamav','--configure-clamav','--update-clamav','--clamav-providers','--uninstall-clamav'))}
$checkTimer=New-Object Windows.Forms.Timer;$checkTimer.Interval=200
$script:checkProcess=$null;$script:checkDeadline=[DateTime]::MinValue;$script:afterCheck='';$script:completedOperation='';$script:completedCode=0;$script:completedPending=$false
function Update-State([bool]$elevatedCheck=$false,[string]$after='') {
 if($script:checking -or $script:job -or $script:prepProcess){return}
 Write-DebugLog ('Readiness check: '+$after+' elevated='+$elevatedCheck)
 $script:checking=$true;$script:afterCheck=$after
 $install.Enabled=$false;$remove.Enabled=$false;$clamButton.Enabled=$false;$clamRemove.Enabled=$false;$update.Enabled=$false;$providers.Enabled=$false;$checkButton.Enabled=$false;$dashboard.Enabled=$false
 $close.Enabled=$true
 $clamState.Text='Checking ClamAV configuration and services...'
 try {
  $svc=Get-Service -Name LinkScope -ErrorAction SilentlyContinue
  $state.Text=if($svc){'Existing LinkScope service: '+$svc.Status}else{'No existing LinkScope service detected.'}
  $install.Text=if($svc){'Upgrade / repair'}else{'Install LinkScope'}
  $remove.Enabled=($null -ne $svc)
  $checkArgs=@{FilePath=$exe;ArgumentList='--check-clamav';PassThru=$true;ErrorAction='Stop'}
  if($elevatedCheck){$checkArgs.Verb='RunAs'}
  $script:checkProcess=Start-Process @checkArgs
  $script:checkDeadline=[DateTime]::UtcNow.AddSeconds(25)
  $checkTimer.Start()
 } catch {
  $script:clamCheck=1
  Complete-State
 }
}
function Complete-State {
 Write-DebugLog ('Readiness result: '+$script:clamCheck)
 try {
 $clamState.ForeColor=[Drawing.Color]::FromArgb(146,64,14)
 $clamButton.Text='Configure / repair ClamAV'
 $clamButton.Enabled=($script:clamCheck -in @(4,5,7,9))
 switch ($script:clamCheck){
  0 {$clamState.Text='Installed | Configured | ClamD and FreshClam running (Automatic).'+"`r`n"+'Loopback engine verified; definitions reported current.';$clamState.ForeColor=[Drawing.Color]::FromArgb(22,101,52);$clamButton.Enabled=$false}
  3 {$clamButton.Text='Install and configure ClamAV';$clamButton.Enabled=([IO.File]::Exists($msi) -and [IO.File]::Exists($sig));$clamState.Text=if($clamButton.Enabled){'Not installed | Local MSI and signature found. GnuPG verification required.'}else{'Not installed | Place clamav-latest.msi and clamav-latest.msi.sig in deploy.'}}
  4 {$clamState.Text='Installed | Configuration missing or still an example.'}
  5 {$clamState.Text='Installed | Configured | Engine not ready. Review definitions and services.'}
  6 {$clamState.Text='Installed | Custom configuration preserved. Review manually.'}
  7 {$clamState.Text='Installed | Engine responding | Updater/startup needs repair.'}
  8 {$clamButton.Text='Repair / reinstall ClamAV';$clamButton.Enabled=([IO.File]::Exists($msi) -and [IO.File]::Exists($sig));$clamState.Text=if($clamButton.Enabled){'Incomplete installation. Repair using the verified MSI, or uninstall remaining services.'}else{'Incomplete installation. Uninstall remaining services, or provide the signed MSI in deploy to repair.'}}
  13 {$clamState.Text='ClamAV settings are private. Click Check again for an elevated check.';$clamButton.Enabled=$false}
  9 {$clamState.Text='Installed | Engine responding | Definition date stale or unknown.'}
  default {$clamState.Text='ClamAV readiness unknown. Review locally.'}
 }
 if($script:rebootRequired){$clamButton.Enabled=$false;$clamState.Text+=' Restart Windows before configuring ClamAV.'}
 $clamRemove.Enabled=($script:clamCheck -ne 3) -and -not $script:rebootRequired
 $providers.Enabled=($script:clamCheck -in @(0,9)) -and -not $script:rebootRequired;$update.Enabled=($script:clamCheck -in @(0,9)) -and -not $script:rebootRequired;$install.Enabled=$true;$pwa.Enabled=$true;$canaries.Enabled=$true;$dashboard.Enabled=$true;$checkButton.Enabled=$true;$close.Enabled=$true
 } finally {$script:checking=$false;$checkButton.Enabled=$true;$close.Enabled=$true;$install.Enabled=$true}
 $after=$script:afterCheck;$script:afterCheck=''
 if($after -eq 'operation'){Complete-Operation}
 elseif($after -eq 'manual'){$status.Text='Readiness check completed.'}
 elseif($after -eq 'install'){Begin-LinkScopeInstall}
}
$checkTimer.Add_Tick({
 if(-not $script:checkProcess){$checkTimer.Stop();return}
 try {
  if(-not $script:checkProcess.HasExited -and [DateTime]::UtcNow -lt $script:checkDeadline){return}
  if($script:checkProcess.HasExited){$script:clamCheck=$script:checkProcess.ExitCode}
  else{try{$script:checkProcess.Kill()}catch{};$script:clamCheck=14}
 } catch {$script:clamCheck=1}
 $checkTimer.Stop()
 $script:checkProcess.Dispose();$script:checkProcess=$null
 Complete-State
})
function Start-Operation($verb,[bool]$skipPreparation=$false,[string]$canaryToken='', [bool]$repairCanaries=$false){
 if($script:job -or $script:checking -or $script:prepProcess){return $false}
 if($verb -eq '--uninstall' -and [Windows.Forms.MessageBox]::Show($form,'Remove the LinkScope service? Configuration, history and ClamAV are retained.','Confirm uninstall','YesNo','Warning') -ne 'Yes'){return $false}
 try {
  if($verb -eq '--upgrade' -and $pwa.Checked){$verb='--upgrade-pwa'}
  $arguments=@($verb)
  if($verb -in @('--upgrade','--upgrade-pwa') -and $canaries.Checked -and -not $skipPreparation){
   Write-DebugLog 'Canary worker launch requested'
   $script:prepVerb=$verb
   $start=New-Object Diagnostics.ProcessStartInfo
   $start.FileName=$exe;$start.Arguments=if($repairCanaries){'--repair-canaries'}else{'--prepare-canaries'};$start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.WorkingDirectory=[IO.Path]::GetDirectoryName($exe)
   $script:prepProcess=[Diagnostics.Process]::Start($start)
   if(-not $script:prepProcess){throw 'Canary worker did not start.'}
   Write-DebugLog ('Canary worker PID='+$script:prepProcess.Id)
   $script:prepDeadline=[DateTime]::UtcNow.AddSeconds(30)
   foreach($control in @($install,$pwa,$canaries,$remove,$dashboard,$clamButton,$update,$providers,$clamRemove,$checkButton)){$control.Enabled=$false}
   $close.Enabled=$true;$progress.Style='Marquee';$status.Text='Preparing optional canary documents (30 second limit)...'
   $prepTimer.Start();return $true
  }
  if($canaryToken){$arguments+=$canaryToken}
  Write-DebugLog ('Starting elevated operation '+$verb)
  $script:operation=$verb
  $script:operationStarted=[DateTime]::UtcNow
  $script:longOperationLogged=$false
  $script:job=Start-Process -FilePath $exe -ArgumentList $arguments -Verb RunAs -PassThru -ErrorAction Stop
  $install.Enabled=$false;$pwa.Enabled=$false;$canaries.Enabled=$false;$remove.Enabled=$false;$dashboard.Enabled=$false;$clamButton.Enabled=$false;$update.Enabled=$false;$providers.Enabled=$false;$clamRemove.Enabled=$false;$checkButton.Enabled=$false;$close.Enabled=$false
  $progress.Style='Marquee';$status.Text=if(Is-ClamOperation $verb){'ClamAV maintenance in progress. Follow the administrator prompts.'}else{'Running elevated installer. Console windows are hidden.'};$timer.Start()
  return $true
 } catch {Write-DebugLog ('Operation start failed: '+$_.Exception.ToString());$status.Text='Operation could not start: '+$_.Exception.Message;$script:job=$null;$script:pendingInstall=$false;Update-State;return $false}
}
$prepTimer=New-Object Windows.Forms.Timer;$prepTimer.Interval=250
$script:prepProcess=$null
$prepTimer.Add_Tick({
 if(-not $script:prepProcess){$prepTimer.Stop();return}
 $code=1;$detail=''
 try {
  if(-not $script:prepProcess.HasExited -and [DateTime]::UtcNow -lt $script:prepDeadline){return}
  if($script:prepProcess.HasExited){$code=$script:prepProcess.ExitCode}
  else{$script:prepProcess.Kill();$detail='Preparation timed out.'}
 } catch {$detail=$_.Exception.Message}
 Write-DebugLog ('Canary worker exit='+$code+' detail='+$detail)
 $prepTimer.Stop();$script:prepProcess.Dispose();$script:prepProcess=$null
 $progress.Style='Blocks';$progress.Value=0
 if($code -eq 12){
  $choice=[Windows.Forms.MessageBox]::Show($form,'Canaries are already enrolled. Restore missing original documents? Existing modified files will not be overwritten. Incident history and baselines are retained.','Repair enrolled canaries','YesNoCancel','Warning')
  if($choice -eq 'Cancel'){Update-State $false 'manual';return}
  if($choice -eq 'Yes'){if(-not (Start-Operation $script:prepVerb $false '' $true)){Update-State};return}
 }
 $token=''
 if($code -eq 0){
  try {$folder=Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'LinkScope Canary Documents';$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;$token=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($folder+'|'+$sid))}catch{$code=1;$detail=$_.Exception.Message}
 }
 if($code -notin @(0,12)){
  try {Add-Content -LiteralPath (Join-Path ([IO.Path]::GetTempPath()) 'LinkScope-Canary-errors.log') -Value ((Get-Date).ToString('o')+' Wizard preparation exit '+$code+' '+$detail) -ErrorAction Stop}catch{}
  $status.Text='Canary preparation failed. See LinkScope-Canary-errors.log in TEMP. '+$detail
  [void][Windows.Forms.MessageBox]::Show($form,('Canary preparation failed. '+$detail+"`r`nSee LinkScope-Canary-errors.log in TEMP. Installation paused; canaries remain selected."),'Canary setup','OK','Warning');Update-State $false 'manual';return
 }
 if(-not (Start-Operation $script:prepVerb $true $token)){Update-State}
})
function Begin-LinkScopeInstall {
 if($script:clamCheck -eq 3 -and [IO.File]::Exists($msi) -and [IO.File]::Exists($sig) -and -not $script:rebootRequired){
  $choice=[Windows.Forms.MessageBox]::Show($form,'ClamAV is missing. Verify the local MSI and install/configure ClamAV before LinkScope? Choose No to skip.','Optional ClamAV setup','YesNoCancel','Question')
  if($choice -eq 'Cancel'){return}
  if($choice -eq 'Yes'){$script:pendingInstall=$true;[void](Start-Operation '--install-clamav');return}
 } elseif($script:clamCheck -in @(4,5,7,9) -and -not $script:rebootRequired){
  $choice=[Windows.Forms.MessageBox]::Show($form,'ClamAV is not fully ready. Configure / repair it now? Choose No to skip.','Optional ClamAV repair','YesNoCancel','Question')
  if($choice -eq 'Cancel'){return}
  if($choice -eq 'Yes'){$script:pendingInstall=$true;[void](Start-Operation '--configure-clamav');return}
 } elseif($script:clamCheck -ne 0){
  if([Windows.Forms.MessageBox]::Show($form,($clamState.Text+"`r`n`r`n"+'Continue with LinkScope without automatic ClamAV configuration?'),'Optional engine not ready','YesNo','Warning') -ne 'Yes'){return}
 }
 [void](Start-Operation '--upgrade')
}
$install.Add_Click({Update-State $false 'install'})
$clamButton.Add_Click({$script:pendingInstall=$false;if($script:clamCheck -in @(3,8)){[void](Start-Operation '--install-clamav')}else{[void](Start-Operation '--configure-clamav')}})
$update.Add_Click({[void](Start-Operation '--update-clamav')})
$clamRemove.Add_Click({$script:pendingInstall=$false;[void](Start-Operation '--uninstall-clamav')})
$providers.Add_Click({[void](Start-Operation '--clamav-providers')})
$checkButton.Add_Click({if(-not $script:job){Update-State $true 'manual'}})
$remove.Add_Click({[void](Start-Operation '--uninstall')})
$dashboard.Add_Click({Start-Process 'http://127.0.0.1:9876/'})
$close.Add_Click({$form.Close()})
$form.Add_FormClosing({param($sender,$e) if($script:prepProcess){$prepTimer.Stop();try{if(-not $script:prepProcess.HasExited){$script:prepProcess.Kill()}}catch{};$script:prepProcess.Dispose();$script:prepProcess=$null};if($script:job -and -not $script:job.HasExited){$e.Cancel=$true;return};if($script:checking){$checkTimer.Stop();if($script:checkProcess){try{if(-not $script:checkProcess.HasExited){$script:checkProcess.Kill()}}catch{}; $script:checkProcess.Dispose();$script:checkProcess=$null};$script:checking=$false}})
$timer.Add_Tick({
 if(-not $script:job){$timer.Stop();return}
 if(-not $script:job.HasExited){
  $elapsed=[int]([DateTime]::UtcNow-$script:operationStarted).TotalSeconds
  if($elapsed -ge 60){
   $status.Text='Still running ('+$elapsed+'s). Review live elevated setup logs: '+$logFolder
   if(-not $script:longOperationLogged){Write-DebugLog ('Elevated worker still running PID='+$script:job.Id+'; review setup logs: '+$logFolder);$script:longOperationLogged=$true}
  }
  return
 }
 $timer.Stop();$rc=$script:job.ExitCode;$script:job.Dispose();$script:job=$null
 Write-DebugLog ('Elevated worker exit='+$rc)
 $op=$script:operation;$pending=$script:pendingInstall;$script:pendingInstall=$false
 $progress.Style='Blocks';$progress.Value=0
 if(($op -in @('--install-clamav','--uninstall-clamav')) -and ($rc -eq 3010 -or $rc -eq 1641)){$script:rebootRequired=$true}
 $script:completedOperation=$op;$script:completedCode=$rc;$script:completedPending=$pending
 Update-State $false 'operation'
})
function Complete-Operation {
 $op=$script:completedOperation;$rc=$script:completedCode;$pending=$script:completedPending
 $script:completedPending=$false
 if($op -eq '--uninstall-clamav' -and $rc -eq 0){$progress.Value=100;$status.Text='ClamAV removal completed. Remaining custom files are preserved.'}
 elseif($op -eq '--uninstall-clamav' -and $rc -eq 3010){$status.Text='ClamAV removal requires a Windows restart.'}
 elseif($op -eq '--uninstall-clamav' -and $rc -eq 4){$status.Text='Native services removed; non-MSI ClamAV files require manual removal.'}
 elseif($op -eq '--clamav-providers' -and $rc -eq 0){$progress.Value=100;$status.Text='Sources saved; FreshClam restarted. Review native logs for downloads.'}
 elseif($op -eq '--clamav-providers' -and $rc -eq 1602){$status.Text='Provider configuration cancelled.'}
 elseif((Is-ClamOperation $op) -and $rc -eq 0 -and $script:clamCheck -eq 0){$progress.Value=100;$status.Text='ClamAV ready. Engine checks passed.'}
 elseif((Is-ClamOperation $op) -and $script:rebootRequired){$status.Text='MSI installation requires a Windows restart. Run Configure / repair ClamAV afterward.'}
 elseif($op -eq '--install-clamav' -and $rc -eq 10){$status.Text='ClamAV MSI blocked: signature verification failed. Review setup logs.'}
 elseif((Is-ClamOperation $op) -and $rc -eq 1602){$status.Text='ClamAV setup cancelled.'}
 elseif(Is-ClamOperation $op){$status.Text='ClamAV not confirmed ready (exit '+$rc+'). Review setup logs as administrator: '+$logFolder}
 elseif($rc -eq 11){$progress.Value=100;$status.Text='LinkScope installed but canary enrollment failed. Keep documents; review setup log and retry Upgrade / repair.'}
 elseif($rc -eq 0){$progress.Value=100;$status.Text='LinkScope operation completed successfully.'}
 else{$status.Text='Setup failed (exit '+$rc+'). Review setup logs as administrator: '+$logFolder}
 if((Is-ClamOperation $op) -and $pending){
  if($rc -eq 0 -and $script:clamCheck -eq 0){[void](Start-Operation '--upgrade')}
  elseif([Windows.Forms.MessageBox]::Show($form,'ClamAV is not ready. Continue with LinkScope only?','Optional prerequisite','YesNo','Warning') -eq 'Yes'){[void](Start-Operation '--upgrade')}
 }
}
[Windows.Forms.Application]::add_ThreadException({param($sender,$eventArgs)
 $message=$eventArgs.Exception.ToString()
 Write-DebugLog $message
 try {Add-Content -LiteralPath (Join-Path ([IO.Path]::GetTempPath()) 'LinkScope-Wizard-errors.log') -Value ((Get-Date).ToString('o')+' '+$message) -ErrorAction Stop}catch{}
 $status.Text='Wizard error: '+$eventArgs.Exception.Message+' | See LinkScope-Wizard-errors.log in TEMP.'
 if(-not $script:job -and -not $script:checkProcess){$timer.Stop();$checkTimer.Stop();$script:checking=$false;$close.Enabled=$true;$checkButton.Enabled=$true;$install.Enabled=$true}
})
$form.Add_Shown({Update-State})
[void]$form.ShowDialog()
Write-DebugLog 'Wizard closed'
$prepTimer.Stop();$prepTimer.Dispose();$checkTimer.Stop();$checkTimer.Dispose();$timer.Dispose();$brand.Image.Dispose();$form.Dispose()
