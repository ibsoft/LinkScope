$ErrorActionPreference='Stop'
$debugLog=Join-Path ([IO.Path]::GetTempPath()) 'LinkScope-Setup-debug.log'
function Write-DebugLog([string]$message){
 try {Add-Content -LiteralPath $debugLog -Value ((Get-Date).ToString('o')+' [wizard '+$PID+'] '+$message) -Encoding UTF8 -ErrorAction Stop}catch{}
}
Write-DebugLog 'V69 guided wizard starting'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::SetUnhandledExceptionMode([Windows.Forms.UnhandledExceptionMode]::CatchException)
[Windows.Forms.Application]::EnableVisualStyles()
$exe=$env:LINKSCOPE_SETUP_EXE
if(-not [IO.File]::Exists($exe)){throw 'Setup executable not found.'}
$msi=Join-Path ([IO.Path]::GetDirectoryName($exe)) 'deploy\clamav-latest.msi'
$sig=Join-Path ([IO.Path]::GetDirectoryName($msi)) 'clamav-latest.msi.sig'
$logFolder=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'LinkScope Setup Logs'
# No elevation of the desktop shell: individual fixed operations request UAC as needed.
$ink=[Drawing.Color]::FromArgb(24,41,58);$muted=[Drawing.Color]::FromArgb(81,100,118)
$navy=[Drawing.Color]::FromArgb(16,31,49);$teal=[Drawing.Color]::FromArgb(0,116,112)
$light=[Drawing.Color]::FromArgb(244,247,250);$white=[Drawing.Color]::White
$line=[Drawing.Color]::FromArgb(219,228,235);$green=[Drawing.Color]::FromArgb(19,111,70);$amber=[Drawing.Color]::FromArgb(146,80,10)
$form=New-Object Windows.Forms.Form
$form.Text='LinkScope | Setup';$form.StartPosition='CenterScreen';$form.AutoScaleMode='Dpi'
$form.Font=New-Object Drawing.Font('Segoe UI',10);$form.BackColor=$light
$form.ClientSize=New-Object Drawing.Size(1040,690);$form.MinimumSize=New-Object Drawing.Size(780,460)
$form.Icon=[Drawing.Icon]::ExtractAssociatedIcon($exe);$form.ShowIcon=$true
$area=[Windows.Forms.Screen]::FromControl($form).WorkingArea
$form.Size=New-Object Drawing.Size([Math]::Min($form.Width,$area.Width-16),[Math]::Min($form.Height,$area.Height-24))
$layout=New-Object Windows.Forms.TableLayoutPanel;$layout.Dock='Fill';$layout.ColumnCount=2;$layout.RowCount=2;$layout.Margin=New-Object Windows.Forms.Padding(0);$layout.Padding=New-Object Windows.Forms.Padding(0)
[void]$layout.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle('Absolute',224)))
[void]$layout.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle('Percent',100)))
[void]$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle('Percent',100)))
[void]$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle('Absolute',68)))
$form.Controls.Add($layout)
$sidebar=New-Object Windows.Forms.Panel;$sidebar.BackColor=$navy;$sidebar.Dock='Fill';$sidebar.Margin=New-Object Windows.Forms.Padding(0);$sidebar.AutoScroll=$true
$layout.Controls.Add($sidebar,0,0);$layout.SetRowSpan($sidebar,2)
$workspace=New-Object Windows.Forms.Panel;$workspace.Dock='Fill';$workspace.Margin=New-Object Windows.Forms.Padding(0);$workspace.BackColor=$light;$layout.Controls.Add($workspace,1,0)
$footer=New-Object Windows.Forms.Panel;$footer.Dock='Fill';$footer.BackColor=$white;$footer.Margin=New-Object Windows.Forms.Padding(0);$layout.Controls.Add($footer,1,1)
function Label($parent,$text,$x,$y,$w,$h,$size=10,$bold=$false,$color=$ink){
 $l=New-Object Windows.Forms.Label;$l.Text=$text;$l.SetBounds($x,$y,$w,$h);$l.ForeColor=$color
 $style=if($bold){[Drawing.FontStyle]::Bold}else{[Drawing.FontStyle]::Regular}
 $l.Font=New-Object Drawing.Font('Segoe UI',$size,$style);$parent.Controls.Add($l);return $l
}
function Button($parent,$text,$x,$y,$w,$primary=$false){
 $b=New-Object Windows.Forms.Button;$b.Text=$text;$b.SetBounds($x,$y,$w,40);$b.FlatStyle='Flat';$b.Cursor=[Windows.Forms.Cursors]::Hand
 $b.FlatAppearance.BorderSize=1;$b.FlatAppearance.BorderColor=$line;$b.BackColor=$white;$b.ForeColor=$ink
 if($primary){$b.BackColor=$teal;$b.ForeColor=$white;$b.FlatAppearance.BorderColor=$teal;$b.Font=New-Object Drawing.Font('Segoe UI',10,[Drawing.FontStyle]::Bold)}
 $b.UseVisualStyleBackColor=$false;$parent.Controls.Add($b);return $b
}
function Card($parent,$x,$y,$w,$h){$p=New-Object Windows.Forms.Panel;$p.SetBounds($x,$y,$w,$h);$p.BackColor=$white;$p.BorderStyle='FixedSingle';$parent.Controls.Add($p);return $p}
function Page {
 $p=New-Object Windows.Forms.Panel;$p.Dock='Fill';$p.AutoScroll=$true;$p.AutoScrollMinSize=New-Object Drawing.Size(744,610);$p.BackColor=$light;$workspace.Controls.Add($p);return $p
}
$brand=New-Object Windows.Forms.PictureBox;$brand.Image=$form.Icon.ToBitmap();$brand.SizeMode='Zoom';$brand.SetBounds(24,27,42,42);$sidebar.Controls.Add($brand)
[void](Label $sidebar 'LinkScope' 76 29 141 35 18 $true $white)
[void](Label $sidebar 'DEPLOYMENT CENTER' 24 83 190 22 9 $true ([Drawing.Color]::FromArgb(141,183,195)))
$steps=@();$stepNames=@('Installation plan','Antivirus engine','LinkScope service','Readiness checks','Installation report')
for($i=0;$i -lt $stepNames.Count;$i++){
 $steps+=Label $sidebar (('{0:00}   {1}' -f ($i+1),$stepNames[$i])) 16 (132+$i*58) 192 44 10 $true ([Drawing.Color]::FromArgb(173,190,205))
 $steps[$i].TextAlign='MiddleLeft';$steps[$i].Padding=New-Object Windows.Forms.Padding(8,0,0,0)
}
[void](Label $sidebar 'SECURE BY DESIGN' 24 448 188 24 9 $true ([Drawing.Color]::FromArgb(141,183,195)))
[void](Label $sidebar "Verified packages`r`nExplicit protection scope`r`nLeast-privilege services" 24 477 184 90 10 $false ([Drawing.Color]::FromArgb(188,202,214)))
[void](Label $sidebar 'V69  /  WINDOWS x64' 24 585 184 26 9 $true ([Drawing.Color]::FromArgb(141,183,195)))
$homePage=Page;$advanced=Page;$running=Page;$finish=Page
[void](Label $homePage 'INSTALLATION / RECOMMENDED' 28 23 680 23 9 $true $teal)
[void](Label $homePage 'Set up LinkScope' 28 50 680 45 26 $true)
[void](Label $homePage 'One guided workflow. Existing configuration and history are retained.' 30 100 680 40 11 $false $muted)
$overview=Card $homePage 28 150 686 158
[void](Label $overview 'SYSTEM DISCOVERY' 18 13 640 23 9 $true $muted)
$state=Label $overview 'Checking Windows service...' 18 39 640 29 12 $true
$clamState=Label $overview 'Checking antivirus engine...' 18 74 640 68 10 $false $muted
$planCard=Card $homePage 28 323 686 164
[void](Label $planCard 'Automatic installation' 18 12 640 29 15 $true)
$plan=Label $planCard 'Detect prerequisites, install or repair ClamAV, deploy LinkScope and verify readiness.' 18 46 642 64 10 $false $muted
$pwa=New-Object Windows.Forms.CheckBox;$pwa.Text='Register managed Edge PWA (local policy; optional)';$pwa.Checked=$false;$pwa.SetBounds(18,115,642,28);$pwa.ForeColor=$ink;$planCard.Controls.Add($pwa)
[void](Label $homePage 'Setup enables machine-wide Process Creation success auditing (4688) and read-only Security log access for the LinkScope service. New installations do not enroll folders or canaries. Administrator and package-verification approvals remain required.' 30 501 682 78 10 $false $muted)
[void](Label $advanced 'ADVANCED / MANUAL' 28 23 680 23 9 $true $teal)
[void](Label $advanced 'Manage installation' 28 50 680 45 24 $true)
$manualState=Label $advanced '' 30 103 680 50 10 $false $muted
$ac1=Card $advanced 28 157 686 114
[void](Label $ac1 'LinkScope service' 16 10 650 29 13 $true)
$manualInstall=Button $ac1 'Install / upgrade only' 16 50 210
$endpointPermissions=Button $ac1 'Endpoint permissions' 237 50 210
$remove=Button $ac1 'Uninstall LinkScope' 458 50 210
$ac2=Card $advanced 28 285 686 190
[void](Label $ac2 'Antivirus engine' 16 10 650 29 13 $true)
$clamButton=Button $ac2 'Install / repair ClamAV' 16 49 319
$update=Button $ac2 'Update signatures' 349 49 319
$providers=Button $ac2 'Third-party signature sources' 16 99 319
$clamRemove=Button $ac2 'Uninstall ClamAV' 349 99 319
[void](Label $ac2 'Custom installations and existing provider schedules are preserved.' 16 149 650 26 9 $false $muted)
$ac3=Card $advanced 28 489 686 104
[void](Label $ac3 'Diagnostics and prerequisites' 16 8 650 27 13 $true)
$checkButton=Button $ac3 'Check again' 16 43 154
$debugButton=Button $ac3 'Debug log' 180 43 154
$gpgButton=Button $ac3 'GnuPG website' 344 43 154
$vendorButton=Button $ac3 'ClamAV website' 508 43 160
$ac4=Card $advanced 28 607 686 133
[void](Label $ac4 'Desktop application / PWA' 16 10 650 29 13 $true)
$desktopRepair=Button $ac4 'Repair app shortcut' 16 48 210
$registerPwa=Button $ac4 'Register Edge PWA' 237 48 210
$manualDashboard=Button $ac4 'Open LinkScope' 458 48 210
[void](Label $ac4 'Only the browser application launcher is published on the desktop. Managed Edge registration is optional.' 16 93 650 32 9 $false $muted)
$advanced.AutoScrollMinSize=New-Object Drawing.Size(744,758)
[void](Label $running 'AUTOMATIC / PROGRESS' 28 23 680 23 9 $true $teal)
$runTitle=Label $running 'Preparing installation' 28 50 680 48 24 $true
$runNote=Label $running 'Keep Setup open. Windows may request administrator or vendor-package approval.' 30 103 680 54 11 $false $muted
$runCard=Card $running 28 166 686 340
$phaseLabels=@();$phaseStatus=@()
for($i=0;$i -lt 4;$i++){
 $phaseLabels+=Label $runCard (('{0:00}  {1}' -f ($i+1),$stepNames[$i])) 18 (19+$i*62) 460 33 12 $true
 $phaseStatus+=Label $runCard 'Pending' 470 (19+$i*62) 188 33 10 $true $muted
 $phaseStatus[$i].TextAlign='MiddleRight'
}
$progress=New-Object Windows.Forms.ProgressBar;$progress.SetBounds(18,279,650,13);$runCard.Controls.Add($progress)
$elapsedLabel=Label $runCard 'Elapsed: 0 s' 18 300 650 27 9 $false $muted
$status=Label $running 'Ready.' 30 520 682 77 10 $false $muted
[void](Label $finish 'INSTALLATION / REPORT' 28 23 680 23 9 $true $teal)
$finishTitle=Label $finish 'Installation report' 28 50 680 48 24 $true
$finishNote=Label $finish '' 30 103 680 64 11 $false $muted
$reportBox=New-Object Windows.Forms.TextBox;$reportBox.SetBounds(28,173,686,326);$reportBox.Multiline=$true;$reportBox.ReadOnly=$true;$reportBox.ScrollBars='Vertical';$reportBox.BackColor=$white;$reportBox.Font=New-Object Drawing.Font('Consolas',10);$finish.Controls.Add($reportBox)
$saveReport=Button $finish 'Save report...' 28 515 183
$dashboard=Button $finish 'Open LinkScope' 222 515 183
[void](Label $finish 'Detailed administrator logs are retained in the LinkScope Setup Logs folder under Program Files.' 30 565 680 40 9 $false $muted)
$footerFlow=New-Object Windows.Forms.FlowLayoutPanel;$footerFlow.Dock='Fill';$footerFlow.FlowDirection='RightToLeft';$footerFlow.WrapContents=$false;$footerFlow.AutoScroll=$true;$footerFlow.Padding=New-Object Windows.Forms.Padding(10,10,10,0);$footer.Controls.Add($footerFlow)
$install=Button $footerFlow 'Install automatically' 0 0 206 $true
$close=Button $footerFlow 'Close' 0 0 92
$advancedButton=Button $footerFlow 'Advanced / manual' 0 0 170
$script:job=$null;$script:checking=$false;$script:operation='';$script:clamCheck=14;$script:rebootRequired=$false
$script:checkProcess=$null;$script:checkDeadline=[DateTime]::MinValue;$script:checkWasElevated=$false;$script:lastCheckWasElevated=$false
$script:afterCheck='';$script:completedOperation='';$script:completedCode=0;$script:autoActive=$false;$script:page='home';$script:stage=0
$script:startedAt=[DateTime]::UtcNow;$script:operationStarted=[DateTime]::UtcNow;$script:results=@();$script:servicePresent=$false;$script:serviceRunning=$false;$script:usnRunning=$false
$script:previousReport='';$script:autoUsedUpdate=$false
$timer=New-Object Windows.Forms.Timer;$timer.Interval=500
$checkTimer=New-Object Windows.Forms.Timer;$checkTimer.Interval=250
function Is-ClamOperation($verb){return ($verb -in @('--install-clamav','--install-clamav-online','--configure-clamav','--update-clamav','--clamav-providers','--uninstall-clamav'))}
function Show-Page([string]$name){
 $script:page=$name
 foreach($p in @($homePage,$advanced,$running,$finish)){$p.Visible=$false}
 switch($name){'home'{$homePage.Visible=$true;$homePage.BringToFront()};'advanced'{$advanced.Visible=$true;$advanced.BringToFront()};'running'{$running.Visible=$true;$running.BringToFront()};'finish'{$finish.Visible=$true;$finish.BringToFront()}}
 Update-Buttons
}
function Set-Stage([int]$index,[string]$detail){
 $script:stage=$index
 for($i=0;$i -lt $steps.Count;$i++){
  $steps[$i].BackColor=if($i -eq $index){$teal}else{$navy}
  $steps[$i].ForeColor=if($i -eq $index){$white}elseif($i -lt $index -and $i -lt 4 -and $phaseStatus[$i].Text -in @('Checked','Verified','Installed')){[Drawing.Color]::FromArgb(132,207,181)}else{[Drawing.Color]::FromArgb(173,190,205)}
 }
 $status.Text=$detail
}
function Phase([int]$index,[string]$text,[Drawing.Color]$color=$muted){$phaseStatus[$index].Text=$text;$phaseStatus[$index].ForeColor=$color}
function Has-GpgCandidate {
 foreach($root in @([Environment]::GetFolderPath('ProgramFiles'),[Environment]::GetFolderPath('ProgramFilesX86'))){
  if(-not $root){continue}
  foreach($rel in @('GnuPG\bin\gpg.exe','Gpg4win\bin\gpg.exe')){if([IO.File]::Exists((Join-Path $root $rel))){return $true}}
 }
 return $false
}
function Observe-Services {
 $svc=Get-Service -Name LinkScope -ErrorAction SilentlyContinue
 $journal=Get-Service -Name LinkScopeUsn -ErrorAction SilentlyContinue
 $script:servicePresent=($null -ne $svc);$script:serviceRunning=($null -ne $svc -and $svc.Status -eq 'Running');$script:usnRunning=($null -ne $journal -and $journal.Status -eq 'Running')
 $state.Text=if($svc){'LinkScope detected | '+$svc.Status}else{'New installation | no LinkScope service detected'}
}
function Update-Buttons {
 $busy=($null -ne $script:job -or $script:checking -or $script:autoActive)
 $install.Visible=($script:page -eq 'home');$install.Enabled=(-not $busy)
 if($install.Visible -and $install.Enabled){$form.AcceptButton=$install}else{$form.AcceptButton=$null}
 $install.Text=if($script:servicePresent){'Upgrade automatically'}else{'Install automatically'}
 $advancedButton.Visible=($script:page -ne 'running');$advancedButton.Enabled=(-not $busy)
 $advancedButton.Text=if($script:page -eq 'advanced'){'Back to automatic'}elseif($script:page -eq 'finish'){'Installation options'}else{'Advanced / manual'}
 $close.Enabled=($null -eq $script:job -and -not $script:autoActive)
 $pwa.Enabled=(-not $busy)
 $manualInstall.Enabled=(-not $busy);$remove.Enabled=(-not $busy -and $script:servicePresent)
 $endpointPermissions.Enabled=(-not $busy -and $script:servicePresent)
 $clamButton.Enabled=(-not $busy -and -not $script:rebootRequired -and $script:clamCheck -in @(3,4,5,7,8,9))
 $update.Enabled=(-not $busy -and -not $script:rebootRequired -and $script:clamCheck -in @(0,9))
 $providers.Enabled=$update.Enabled;$clamRemove.Enabled=(-not $busy -and -not $script:rebootRequired -and $script:clamCheck -in @(0,4,5,6,7,8,9))
 $checkButton.Enabled=(-not $busy);$dashboard.Enabled=($script:serviceRunning -and -not $busy)
 $debugButton.Enabled=(-not $busy);$gpgButton.Enabled=(-not $busy);$vendorButton.Enabled=(-not $busy)
 $desktopRepair.Enabled=(-not $busy -and $script:servicePresent);$registerPwa.Enabled=$desktopRepair.Enabled;$manualDashboard.Enabled=$dashboard.Enabled
}
function Refresh-Plan {
 $clamState.ForeColor=$amber
 switch($script:clamCheck){
  0 {$clamState.Text='Antivirus ready | ClamD and FreshClam verified; official definitions current.';$clamState.ForeColor=$green}
  3 {$clamState.Text='Antivirus not installed | Automatic setup will authenticate the package, install and configure the engine.'}
  4 {$clamState.Text='Antivirus installed | Missing or example configuration; repair planned.'}
  5 {$clamState.Text='Antivirus installed | Engine not ready; repair planned.'}
  6 {$clamState.Text='Custom antivirus configuration detected | Automatic takeover is blocked.'}
  7 {$clamState.Text='Antivirus responding | Updater or startup requires repair.'}
  8 {$clamState.Text='Partial antivirus installation | Verified package repair required.'}
  9 {$clamState.Text='Engine responding | Official signature currency or reload is not confirmed.'}
  13 {$clamState.Text=if($script:lastCheckWasElevated){'ClamAV configuration could not be read even by the elevated check. Review the administrator log.'}else{'Private antivirus configuration | Administrator readiness check required.'}}
  default {$clamState.Text='Antivirus readiness unknown | A fresh administrator check is required.'}
 }
 if($script:rebootRequired){$clamState.Text='Windows restart required. Restart before continuing the guided installation.'}
 if($script:clamCheck -in @(3,8)){
  if([IO.File]::Exists($msi) -xor [IO.File]::Exists($sig)){$plan.Text='Blocked: local deployment contains only one of the MSI/signature pair. Supply both matching files or remove both for official online acquisition.'}
  elseif(-not (Has-GpgCandidate)){$plan.Text='Prerequisite: install administrator-managed GnuPG (Gpg4win) in Program Files. Open Advanced / manual for the vendor link. Setup will not bypass package authentication.'}
  elseif([IO.File]::Exists($msi)){$plan.Text='Plan: authenticate the local signed MSI, configure ClamAV, install LinkScope and verify service readiness.'}
  else{$plan.Text='Plan: acquire the official stable x64 MSI and detached signature from Cisco Talos, authenticate the package, configure ClamAV, then install LinkScope. Internet access required.'}
 }elseif($script:clamCheck -eq 0){$plan.Text='Plan: retain the verified antivirus engine, install or upgrade LinkScope, then verify services. Existing protection policy is preserved.'}
 else{$plan.Text='Plan: inspect antivirus readiness with administrator access, repair standard configuration or update signatures when needed, then deploy LinkScope. Unsafe or incomplete prerequisites stop the automatic workflow.'}
 $manualState.Text=$state.Text+' | '+$clamState.Text
 $clamButton.Text=if($script:clamCheck -in @(3,8)){'Repair / reinstall ClamAV'}else{'Configure / repair ClamAV'}
}
function Update-State([bool]$elevatedCheck=$false,[string]$after='') {
 if($script:checking -or $script:job){return}
 $script:checking=$true;$script:afterCheck=$after;$script:checkWasElevated=$elevatedCheck
 $clamState.Text='Checking ClamAV configuration and services...';Update-Buttons
 try {
  Observe-Services
  $checkArgs=@{FilePath=$exe;ArgumentList='--check-clamav';PassThru=$true;ErrorAction='Stop'}
  if($elevatedCheck){$checkArgs.Verb='RunAs'}
  $script:checkProcess=Start-Process @checkArgs
  $script:checkDeadline=[DateTime]::UtcNow.AddSeconds(25);$checkTimer.Start()
 } catch {Write-DebugLog ('Readiness check could not start: '+$_.Exception.Message);$script:clamCheck=14;Complete-State}
}
function Record([string]$message){$script:results+=((Get-Date).ToUniversalTime().ToString('HH:mm:ss')+' UTC  '+$message);Write-DebugLog $message}
function Complete-State {
 $script:checking=$false;$script:lastCheckWasElevated=$script:checkWasElevated
 if($script:autoActive -or $script:page -eq 'running'){$elapsedLabel.Text='Elapsed: '+[int]([DateTime]::UtcNow-$script:startedAt).TotalSeconds+' s'}
 try{Observe-Services}catch{Write-DebugLog $_.Exception.Message;$script:serviceRunning=$false;$script:usnRunning=$false}
 Refresh-Plan
 $after=$script:afterCheck;$script:afterCheck=''
 Write-DebugLog ('Readiness result: '+$script:clamCheck+' elevated='+$script:lastCheckWasElevated+' continuation='+$after)
 if($after -eq 'install'){Begin-LinkScopeInstall}
 elseif($after -eq 'operation'){Complete-Operation}
 elseif($after -eq 'manual'){$manualState.Text=$state.Text+' | '+$clamState.Text;Update-Buttons}
 else{Update-Buttons}
}
$checkTimer.Add_Tick({
 if(-not $script:checkProcess){$checkTimer.Stop();return}
 try {
  if(-not $script:checkProcess.HasExited -and [DateTime]::UtcNow -lt $script:checkDeadline){return}
  if($script:checkProcess.HasExited){$script:clamCheck=$script:checkProcess.ExitCode}
  else{try{$script:checkProcess.Kill()}catch{};$script:clamCheck=14}
 }catch{$script:clamCheck=14}
 $checkTimer.Stop();$script:checkProcess.Dispose();$script:checkProcess=$null
 Complete-State
})
function Begin-Report {
 $script:startedAt=[DateTime]::UtcNow;$script:results=@();$script:autoUsedUpdate=$false
 for($i=0;$i -lt 4;$i++){Phase $i 'Pending'}
 $progress.Style='Marquee';$elapsedLabel.Text='Elapsed: 0 s';$runTitle.Text='Preparing installation';$status.Text='Checking prerequisites...'
}
function End-Report([string]$title,[string]$message,[bool]$complete=$false){
 $wasAuto=$script:autoActive;$script:autoActive=$false
 $progress.Style='Blocks';$progress.Value=if($complete){100}else{0}
 Set-Stage 4 $message
 $finishTitle.Text=$title;$finishTitle.ForeColor=if($complete){$green}else{$amber}
 $finishNote.Text=$message
 $seconds=[Math]::Round(([DateTime]::UtcNow-$script:startedAt).TotalSeconds,1)
 $kind=if($wasAuto){'Automatic installation'}else{'Manual maintenance'}
 $lines=@('LINKSCOPE  |  V81 INSTALLATION REPORT',$kind,('Completed UTC: '+[DateTime]::UtcNow.ToString('o')),('Elapsed: '+$seconds+' s'),('Outcome: '+$title),'') + @($script:results) + @('',('LinkScope service running: '+$script:serviceRunning),('NTFS journal service running: '+$script:usnRunning),('ClamAV readiness code: '+$script:clamCheck),('Restart required: '+$script:rebootRequired),'',('Administrator logs: '+$logFolder),'Desktop: app launcher provisioning is recorded in administrator logs; Edge policy application requires browser launch. No service executable shortcut is created.','Windows audit: install/upgrade provisions Process Creation success auditing and service-SID Security log read access. Elevated logs contain policy readback and ACL outcomes; live coverage is verified in the dashboard. Historical gaps remain recorded.','Setup readiness is not endpoint protection certification. New application scope, initial sign-in and Test Center validation are separate. Existing policy is preserved.')
 $script:previousReport=$lines -join "`r`n";$reportBox.Text=$script:previousReport
 Show-Page 'finish'
}
function Stop-Automatic([string]$message){Record ('STOPPED: '+$message);Phase ([Math]::Min($script:stage,3)) 'Attention' $amber;End-Report 'Installation needs attention' $message}
function Start-Operation($verb){
 if($script:job -or $script:checking){return $false}
 if($verb -eq '--uninstall' -and [Windows.Forms.MessageBox]::Show($form,'Remove LinkScope? Configuration, history and ClamAV are retained.','Confirm removal','YesNo','Warning','Button2') -ne 'Yes'){return $false}
 try {
  if($verb -eq '--upgrade' -and $pwa.Checked){$verb='--upgrade-pwa'}
  if(-not $script:autoActive){Begin-Report;Set-Stage 0 'Manual maintenance in progress.';Phase 0 'Manual action' $teal;$runTitle.Text='Running maintenance'}
  $script:operation=$verb;$script:operationStarted=[DateTime]::UtcNow
  Record ('Starting '+$verb)
  Show-Page 'running'
  $script:job=Start-Process -FilePath $exe -ArgumentList @($verb) -Verb RunAs -PassThru -ErrorAction Stop
  $progress.Style='Marquee';$status.Text='Elevated worker running. Complete any administrator or package approval prompt.';$timer.Start();Update-Buttons
  return $true
 }catch{
  $script:job=$null;Record ('Worker could not start: '+$_.Exception.Message)
  if($script:autoActive){Stop-Automatic 'Operation could not start or administrator approval was declined.'}else{End-Report 'Maintenance not completed' 'Operation could not start or administrator approval was declined.'}
  return $false
 }
}
function Start-CoreInstall {
 Phase 1 'Verified' $green;Set-Stage 2 'Deploying LinkScope, configuring process audit prerequisites and preserving existing configuration.';Phase 2 'Installing...' $teal;$runTitle.Text='Installing LinkScope'
 [void](Start-Operation '--upgrade')
}
function Begin-LinkScopeInstall {
 Record ('Administrator preflight ClamAV readiness code '+$script:clamCheck)
 if($script:rebootRequired){Stop-Automatic 'Restart Windows before running setup again.';return}
 if($script:clamCheck -in @(13,14)){Stop-Automatic 'Antivirus readiness could not be established. Review administrator logs and retry.';return}
 Phase 0 'Checked' $green;Set-Stage 1 'Preparing antivirus prerequisites.';$runTitle.Text='Preparing antivirus engine'
 if($script:clamCheck -eq 0){Record 'Existing antivirus engine verified; no antivirus installation needed.';Start-CoreInstall;return}
 if($script:clamCheck -eq 6){Stop-Automatic 'Custom ClamAV installation detected. It has not been changed. Review it in Advanced / manual.';return}
 if($script:clamCheck -in @(3,8)){
  if([IO.File]::Exists($msi) -xor [IO.File]::Exists($sig)){Stop-Automatic 'Local package pair is incomplete. Supply both matching files or remove both for online acquisition.';return}
  if(-not (Has-GpgCandidate)){Stop-Automatic 'Trusted GnuPG is required. Install Gpg4win from the official website, then rerun Setup.';return}
  Phase 1 'Installing...' $teal
  if([IO.File]::Exists($msi)){[void](Start-Operation '--install-clamav')}else{[void](Start-Operation '--install-clamav-online')};return
 }
 if($script:clamCheck -in @(4,5,7)){Phase 1 'Repairing...' $teal;[void](Start-Operation '--configure-clamav');return}
 if($script:clamCheck -eq 9){$script:autoUsedUpdate=$true;Phase 1 'Updating...' $teal;[void](Start-Operation '--update-clamav');return}
 Stop-Automatic 'Unrecognized antivirus readiness state. Review the logs.'
}
$timer.Add_Tick({
 if(-not $script:job){$timer.Stop();return}
 $elapsedLabel.Text='Elapsed: '+[int]([DateTime]::UtcNow-$script:startedAt).TotalSeconds+' s'
 if(-not $script:job.HasExited){return}
 $timer.Stop();$rc=$script:job.ExitCode;$script:job.Dispose();$script:job=$null
 $op=$script:operation;Record ('Worker exit: '+$op+' = '+$rc)
 if((Is-ClamOperation $op) -and ($rc -eq 3010 -or $rc -eq 1641)){$script:rebootRequired=$true}
 $script:completedOperation=$op;$script:completedCode=$rc
 if($script:autoActive -and -not (Is-ClamOperation $op)){Set-Stage 3 'Checking service status and antivirus readiness.';Phase 3 'Checking...' $teal;$runTitle.Text='Verifying installation'}
 Update-State ($script:lastCheckWasElevated -or (Is-ClamOperation $op)) 'operation'
})
function Complete-Operation {
 $op=$script:completedOperation;$rc=$script:completedCode
 Record ('Post-operation antivirus readiness code '+$script:clamCheck)
 if($script:autoActive){
  if(Is-ClamOperation $op){
   if($script:rebootRequired){Stop-Automatic 'Antivirus installation requires a Windows restart. Restart and rerun automatic setup; existing changes are retained.';return}
   if($rc -eq 0 -and $script:clamCheck -eq 0){Start-CoreInstall;return}
   # One official signature update may be needed after a successful engine configuration. No infinite retries.
   if($rc -in @(0,9) -and $script:clamCheck -eq 9 -and -not $script:autoUsedUpdate){$script:autoUsedUpdate=$true;Phase 1 'Updating...' $teal;[void](Start-Operation '--update-clamav');return}
   Stop-Automatic ('Antivirus not verified (operation exit '+$rc+', readiness '+$script:clamCheck+'). LinkScope deployment was not started. Review logs or use Advanced / manual.');return
  }
  if($rc -ne 0 -and $rc -ne 21){Stop-Automatic ('LinkScope operation returned exit '+$rc+'. Installation may be partially applied; inspect administrator logs before retrying.');return}
  Phase 2 'Installed' $green
  if($script:serviceRunning -and $script:usnRunning -and $script:clamCheck -eq 0 -and $rc -eq 0){
   Phase 3 'Verified' $green;Record 'LinkScope and LinkScopeUsn running; ClamAV readiness and audit prerequisite configuration checks completed.'
   End-Report 'Installation completed' 'Core services verified. Sign in, configure application protection as required and run the Test Center for acceptance.' $true;return
  }
  Record 'Installation worker completed; service/readiness or permission review remains.'
  Phase 3 'Review required' $amber
  End-Report 'Installed - review required' 'LinkScope was deployed, but audit prerequisites, permissions, journal availability or engine readiness require review. See the report and administrator logs.';return
 }
 if($script:rebootRequired){End-Report 'Restart required' 'Restart Windows before continuing antivirus maintenance.';return}
 if($rc -eq 21){End-Report 'Installed - review required' 'LinkScope installed; endpoint permissions require review (including web process audit prerequisites). See elevated setup log.';return}
 if($rc -eq 1602){End-Report 'Maintenance cancelled' 'The requested operation was not completed.';return}
 if($rc -ne 0){End-Report 'Maintenance needs attention' ('Worker exit '+$rc+'. Review administrator logs.');return}
 if($op -in @('--install-clamav','--install-clamav-online','--configure-clamav','--update-clamav') -and $script:clamCheck -ne 0){End-Report 'Engine review required' 'The operation returned success, but antivirus readiness is not verified.';return}
 if($op -in @('--upgrade','--upgrade-pwa') -and -not $script:serviceRunning){End-Report 'Service review required' 'The worker returned success, but the LinkScope service is not running.';return}
 End-Report 'Maintenance completed' 'The selected operation returned success. See the reported service and engine observations; this is not protection certification.' $true
}
$install.Add_Click({
 if($script:job -or $script:checking -or $script:autoActive){return}
 if($script:rebootRequired){[void][Windows.Forms.MessageBox]::Show($form,'Restart Windows before continuing.','Restart required');return}
 $script:autoActive=$true;Begin-Report;Set-Stage 0 'Administrator preflight in progress.';Phase 0 'Checking...' $teal;Show-Page 'running';Update-State $true 'install'
})
$advancedButton.Add_Click({if($script:page -eq 'advanced'){Set-Stage 0 '';Show-Page 'home'}elseif($script:page -eq 'finish'){Set-Stage 0 '';Show-Page 'home'}else{Show-Page 'advanced'}})
$manualInstall.Add_Click({if($script:clamCheck -ne 0 -and [Windows.Forms.MessageBox]::Show($form,'Install LinkScope only, without requiring a ready antivirus engine? Endpoint protection may be unavailable.','Manual installation','YesNo','Warning','Button2') -ne 'Yes'){return};[void](Start-Operation '--upgrade')})
$clamButton.Add_Click({if($script:clamCheck -in @(3,8)){if([IO.File]::Exists($msi) -and [IO.File]::Exists($sig)){[void](Start-Operation '--install-clamav')}elseif(-not [IO.File]::Exists($msi) -and -not [IO.File]::Exists($sig)){if([Windows.Forms.MessageBox]::Show($form,'Acquire the official signed ClamAV package from Cisco Talos and install it after verification?','Online antivirus acquisition','YesNo','Question','Button2') -eq 'Yes'){[void](Start-Operation '--install-clamav-online')}}else{[void][Windows.Forms.MessageBox]::Show($form,'Provide both local package files, or remove both before online acquisition.','Incomplete package')}}else{[void](Start-Operation '--configure-clamav')}})
$update.Add_Click({[void](Start-Operation '--update-clamav')})
$clamRemove.Add_Click({[void](Start-Operation '--uninstall-clamav')})
$providers.Add_Click({[void](Start-Operation '--clamav-providers')})
$endpointPermissions.Add_Click({[void](Start-Operation '--endpoint-permissions')})
$checkButton.Add_Click({if(-not $script:job){Update-State $true 'manual'}})
$remove.Add_Click({[void](Start-Operation '--uninstall')})
$debugButton.Add_Click({try{Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\notepad.exe') -ArgumentList ('"'+$debugLog+'"')}catch{[void][Windows.Forms.MessageBox]::Show($form,$_.Exception.Message,'Debug log')}})
function Open-Vendor([string]$url){
 $principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
 if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){[void][Windows.Forms.MessageBox]::Show($form,('Open this address in your normal browser: '+$url),'Vendor website');return}
 Start-Process $url
}
$gpgButton.Add_Click({Open-Vendor 'https://www.gpg4win.org/'})
$vendorButton.Add_Click({Open-Vendor 'https://www.clamav.net/downloads'})
function Test-AppShortcut([string]$path){
 # Only open an installer-owned web launcher, never a service executable or arbitrary shell link.
 try {
  if(([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint) -ne 0){return $false}
  if($path.EndsWith('.url',[StringComparison]::OrdinalIgnoreCase)){
   if((Get-Item -LiteralPath $path).Length -gt 16384){return $false}
   $lines=[IO.File]::ReadAllLines($path);if($lines.Length -lt 3 -or $lines[0] -ne '; LinkScope Setup managed shortcut'){return $false}
   $urls=@($lines | Where-Object {$_ -like 'URL=*'});if($urls.Count -ne 1){return $false}
   $origin=$urls[0].Substring(4)
  }else{
   $shell=$null;$link=$null
   try{
    $shell=New-Object -ComObject WScript.Shell;$link=$shell.CreateShortcut($path)
    if($link.Description -ne 'LinkScope desktop application (managed by LinkScope Setup)'){return $false}
    $browsers=@();foreach($root in @([Environment]::GetFolderPath('ProgramFiles'),[Environment]::GetFolderPath('ProgramFilesX86'))){if($root){$browsers+=Join-Path $root 'Microsoft\Edge\Application\msedge.exe';$browsers+=Join-Path $root 'Google\Chrome\Application\chrome.exe'}}
    if($link.TargetPath -notin $browsers -or -not [IO.File]::Exists($link.TargetPath)){return $false}
    if($link.Arguments -notmatch '^--app="([^"\r\n]+)"$'){return $false};$origin=$Matches[1]
   }finally{if($link){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($link)};if($shell){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)}}
  }
  $uri=$null;if(-not [Uri]::TryCreate($origin,[UriKind]::Absolute,[ref]$uri)){return $false}
  return (($uri.Scheme -eq 'https' -or ($uri.Scheme -eq 'http' -and $uri.IsLoopback)) -and [string]::IsNullOrEmpty($uri.UserInfo))
 }catch{return $false}
}
function Open-LinkScopeApp {
 # Use the installed common Start menu launcher with the configured origin, not a hardcoded port.
 if(([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){[void][Windows.Forms.MessageBox]::Show($form,'Open the LinkScope shortcut from your normal Windows desktop. Do not start a browser from an elevated Setup session.','Open LinkScope');return}
 try{foreach($folder in @([Environment]::GetFolderPath('CommonPrograms'),[Environment]::GetFolderPath('CommonDesktopDirectory'))){foreach($name in @('LinkScope.lnk','LinkScope.url')){$path=Join-Path $folder $name;if([IO.File]::Exists($path) -and (Test-AppShortcut $path)){Start-Process -FilePath $path;return}}};[void][Windows.Forms.MessageBox]::Show($form,'Open LinkScope using its configured dashboard address. No verified app shortcut was found. Use Advanced / manual > Repair app shortcut.','Open LinkScope')}catch{[void][Windows.Forms.MessageBox]::Show($form,$_.Exception.Message,'Open LinkScope')}
}
$dashboard.Add_Click({Open-LinkScopeApp})
$manualDashboard.Add_Click({Open-LinkScopeApp})
$desktopRepair.Add_Click({[void](Start-Operation '--desktop-app')})
$registerPwa.Add_Click({if([Windows.Forms.MessageBox]::Show($form,'Register LinkScope as a managed Edge PWA on this computer? Existing organization policies are preserved. Edge applies the policy at browser launch.','Managed PWA','YesNo','Question','Button2') -eq 'Yes'){[void](Start-Operation '--register-pwa')}})
$saveReport.Add_Click({
 $dialog=New-Object Windows.Forms.SaveFileDialog;$dialog.Filter='Text report (*.txt)|*.txt';$dialog.FileName='LinkScope-Setup-Report.txt';$dialog.OverwritePrompt=$true
 try{if($dialog.ShowDialog($form) -eq 'OK'){[IO.File]::WriteAllText($dialog.FileName,$script:previousReport,[Text.Encoding]::UTF8)}}catch{[void][Windows.Forms.MessageBox]::Show($form,$_.Exception.Message,'Save report')}finally{$dialog.Dispose()}
})
$close.Add_Click({$form.Close()})
$form.Add_FormClosing({param($sender,$e)
 if($script:autoActive -or $script:job){$e.Cancel=$true;return}
 if($script:checking){$checkTimer.Stop();if($script:checkProcess){try{if(-not $script:checkProcess.HasExited){$script:checkProcess.Kill()}}catch{};$script:checkProcess.Dispose();$script:checkProcess=$null};$script:checking=$false}
})
[Windows.Forms.Application]::add_ThreadException({param($sender,$eventArgs)
 Write-DebugLog $eventArgs.Exception.ToString()
 if(-not $script:job -and -not $script:checkProcess){$timer.Stop();$checkTimer.Stop();$script:checking=$false;Record ('Wizard error: '+$eventArgs.Exception.Message);End-Report 'Setup needs attention' 'A wizard error occurred. Review the debug log.'}else{$status.Text='Wizard error. A worker is still running; see the debug log.'}
})
$form.Add_Shown({Set-Stage 0 '';Show-Page 'home';Update-State})
[void]$form.ShowDialog()
Write-DebugLog 'Wizard closed';$checkTimer.Stop();$checkTimer.Dispose();$timer.Dispose();$brand.Image.Dispose();$form.Dispose()
