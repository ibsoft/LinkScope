$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
$exe=$env:LINKSCOPE_SETUP_EXE
if(-not [IO.File]::Exists($exe)){throw 'Setup executable not found.'}
$msi=Join-Path ([IO.Path]::GetDirectoryName($exe)) 'deploy\clamav-latest.msi'
$sig=$msi+'.sig'
$logFolder=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'LinkScope Setup Logs'
$form=New-Object Windows.Forms.Form
$form.Text='LinkScope Setup'; $form.ClientSize=New-Object Drawing.Size(700,680); $form.StartPosition='CenterScreen'; $form.FormBorderStyle='FixedDialog'; $form.MaximizeBox=$false
$form.Icon=[Drawing.Icon]::ExtractAssociatedIcon($exe)
$form.ShowIcon=$true;$form.Font=New-Object Drawing.Font('Segoe UI',10);$form.AutoScaleMode='Dpi'
function Label($text,$x,$y,$w,$h){$l=New-Object Windows.Forms.Label;$l.Text=$text;$l.SetBounds($x,$y,$w,$h);$form.Controls.Add($l);return $l}
function Button($text,$x,$y,$w){$b=New-Object Windows.Forms.Button;$b.Text=$text;$b.SetBounds($x,$y,$w,34);$form.Controls.Add($b);return $b}
$head=Label 'LinkScope | Installation wizard' 0 0 700 70
$head.BackColor=[Drawing.Color]::FromArgb(19,49,65);$head.ForeColor=[Drawing.Color]::White;$head.Font=New-Object Drawing.Font('Segoe UI',19,[Drawing.FontStyle]::Bold);$head.TextAlign='MiddleCenter'
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
$providers=Button 'Third-party signature sources...' 24 359 652
$pwa=New-Object Windows.Forms.CheckBox;$pwa.Text='Register managed Edge PWA (local policy; optional)';$pwa.Checked=$true;$pwa.SetBounds(24,401,652,26);$form.Controls.Add($pwa)
$pwaNote=Label 'Desktop shortcut is created by default. Managed Edge PWA installs at browser launch and cannot be removed in Edge. Existing policies are preserved.' 24 429 652 45
$canaries=New-Object Windows.Forms.CheckBox;$canaries.Text='Create and enroll Word, Excel and text canaries in my Documents';$canaries.Checked=$true;$canaries.SetBounds(24,474,652,25);$form.Controls.Add($canaries)
$note=Label 'ClamAV settings are preserved. Definitions need Internet access. Canaries enable Monitor mode only if protection was disabled.' 24 505 652 72
$progress=New-Object Windows.Forms.ProgressBar;$progress.SetBounds(24,590,652,16);$form.Controls.Add($progress)
$status=Label 'Ready.' 24 616 550 58
$close=Button 'Close' 586 627 90
$timer=New-Object Windows.Forms.Timer;$timer.Interval=500
$script:job=$null;$script:operation='';$script:pendingInstall=$false;$script:clamCheck=1;$script:rebootRequired=$false
function Is-ClamOperation($verb){return ($verb -in @('--install-clamav','--configure-clamav','--update-clamav','--clamav-providers'))}
function Update-State([bool]$elevatedCheck=$false) {
 $svc=Get-Service -Name LinkScope -ErrorAction SilentlyContinue
 $state.Text=if($svc){'Existing LinkScope service: '+$svc.Status}else{'No existing LinkScope service detected.'}
 $install.Text=if($svc){'Upgrade / repair'}else{'Install LinkScope'}
 $remove.Enabled=($null -ne $svc)
 $clamState.Text='Checking ClamAV configuration and services...';$form.Refresh()
 try {
  $checkArgs=@{FilePath=$exe;ArgumentList='--check-clamav';Wait=$true;PassThru=$true;ErrorAction='Stop'}
  if($elevatedCheck){$checkArgs.Verb='RunAs'}
  $check=Start-Process @checkArgs
  try {$script:clamCheck=$check.ExitCode} finally {$check.Dispose()}
 } catch {$script:clamCheck=1}
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
  8 {$clamState.Text='Partial/nonstandard ClamAV installation. Repair manually.'}
  13 {$clamState.Text='ClamAV settings are private. Click Check again for an elevated check.';$clamButton.Enabled=$true}
  9 {$clamState.Text='Installed | Engine responding | Definition date stale or unknown.'}
  default {$clamState.Text='ClamAV readiness unknown. Review locally.'}
 }
 if($script:rebootRequired){$clamButton.Enabled=$false;$clamState.Text+=' Restart Windows before configuring ClamAV.'}
 $providers.Enabled=($script:clamCheck -in @(0,9,13)) -and -not $script:rebootRequired;$update.Enabled=($script:clamCheck -in @(0,9,13)) -and -not $script:rebootRequired;$install.Enabled=$true;$pwa.Enabled=$true;$canaries.Enabled=$true;$dashboard.Enabled=$true;$checkButton.Enabled=$true;$close.Enabled=$true
}
function Start-Operation($verb){
 if($script:job){return $false}
 if($verb -eq '--uninstall' -and [Windows.Forms.MessageBox]::Show($form,'Remove the LinkScope service? Configuration, history and ClamAV are retained.','Confirm uninstall','YesNo','Warning') -ne 'Yes'){return $false}
 try {
  if($verb -eq '--upgrade' -and $pwa.Checked){$verb='--upgrade-pwa'}
  $arguments=@($verb)
  if($verb -in @('--upgrade','--upgrade-pwa') -and $canaries.Checked){
   $prep=Start-Process -FilePath $exe -ArgumentList '--prepare-canaries' -Wait -PassThru -ErrorAction Stop
   try{$prepCode=$prep.ExitCode}finally{$prep.Dispose()}
   if($prepCode -eq 0){
    $folder=Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'LinkScope Canary Documents'
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $arguments+= [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($folder+'|'+$sid))
   }elseif($prepCode -ne 12){
    if([Windows.Forms.MessageBox]::Show($form,'Canary preparation failed. Install without new canaries?','Canary setup','YesNo','Warning') -ne 'Yes'){return $false}
   }
  }
  $script:operation=$verb
  $script:job=Start-Process -FilePath $exe -ArgumentList $arguments -Verb RunAs -PassThru -ErrorAction Stop
  $install.Enabled=$false;$pwa.Enabled=$false;$canaries.Enabled=$false;$remove.Enabled=$false;$dashboard.Enabled=$false;$clamButton.Enabled=$false;$update.Enabled=$false;$providers.Enabled=$false;$checkButton.Enabled=$false;$close.Enabled=$false
  $progress.Style='Marquee';$status.Text=if(Is-ClamOperation $verb){'ClamAV maintenance in progress. Follow the administrator prompts.'}else{'Running elevated installer. Console windows are hidden.'};$timer.Start()
  return $true
 } catch {$status.Text='Operation could not start: '+$_.Exception.Message;$script:job=$null;$script:pendingInstall=$false;return $false}
}
$install.Add_Click({
 Update-State
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
})
$clamButton.Add_Click({$script:pendingInstall=$false;if($script:clamCheck -eq 3){[void](Start-Operation '--install-clamav')}else{[void](Start-Operation '--configure-clamav')}})
$update.Add_Click({[void](Start-Operation '--update-clamav')})
$providers.Add_Click({[void](Start-Operation '--clamav-providers')})
$checkButton.Add_Click({if(-not $script:job){Update-State ($script:clamCheck -eq 13);$status.Text='Readiness check completed.'}})
$remove.Add_Click({[void](Start-Operation '--uninstall')})
$dashboard.Add_Click({Start-Process 'http://127.0.0.1:9876/'})
$close.Add_Click({$form.Close()})
$form.Add_FormClosing({param($sender,$e) if($script:job -and -not $script:job.HasExited){$e.Cancel=$true}})
$timer.Add_Tick({
 if(-not $script:job.HasExited){return}
 $timer.Stop();$rc=$script:job.ExitCode;$script:job.Dispose();$script:job=$null
 $op=$script:operation;$pending=$script:pendingInstall;$script:pendingInstall=$false
 $progress.Style='Blocks';$progress.Value=0
 if($op -eq '--install-clamav' -and ($rc -eq 3010 -or $rc -eq 1641)){$script:rebootRequired=$true}
 Update-State
 if($op -eq '--clamav-providers' -and $rc -eq 0){$progress.Value=100;$status.Text='Sources saved; FreshClam restarted. Review native logs for downloads.'}
 elseif($op -eq '--clamav-providers' -and $rc -eq 1602){$status.Text='Provider configuration cancelled.'}
 elseif((Is-ClamOperation $op) -and $rc -eq 0 -and $script:clamCheck -eq 0){$progress.Value=100;$status.Text='ClamAV ready. Engine checks passed.'}
 elseif((Is-ClamOperation $op) -and $script:rebootRequired){$status.Text='MSI installation requires a Windows restart. Run Configure / repair ClamAV afterward.'}
 elseif($op -eq '--install-clamav' -and $rc -eq 10){$status.Text='ClamAV MSI blocked: signature verification failed. Review setup logs.'}
 elseif((Is-ClamOperation $op) -and $rc -eq 1602){$status.Text='ClamAV setup cancelled.'}
 elseif(Is-ClamOperation $op){$status.Text='ClamAV not confirmed ready (exit '+$rc+'). Review setup logs as administrator: '+$logFolder}
 elseif($rc -eq 11){$progress.Value=100;$status.Text='LinkScope installed; canary enrollment needs attention. Review the setup log.'}
 elseif($rc -eq 0){$progress.Value=100;$status.Text='LinkScope operation completed successfully.'}
 else{$status.Text='Setup failed (exit '+$rc+'). Review setup logs as administrator: '+$logFolder}
 if((Is-ClamOperation $op) -and $pending){
  if($rc -eq 0 -and $script:clamCheck -eq 0){[void](Start-Operation '--upgrade')}
  elseif([Windows.Forms.MessageBox]::Show($form,'ClamAV is not ready. Continue with LinkScope only?','Optional prerequisite','YesNo','Warning') -eq 'Yes'){[void](Start-Operation '--upgrade')}
 }
})
Update-State
[void]$form.ShowDialog()
$timer.Dispose();$form.Dispose()
