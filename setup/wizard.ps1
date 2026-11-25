$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
$exe=$env:LINKSCOPE_SETUP_EXE
if(-not [IO.File]::Exists($exe)){throw 'Setup executable not found.'}
$form=New-Object Windows.Forms.Form
$form.Text='LinkScope Setup'; $form.ClientSize=New-Object Drawing.Size(620,410); $form.StartPosition='CenterScreen'; $form.FormBorderStyle='FixedDialog'; $form.MaximizeBox=$false
$form.Font=New-Object Drawing.Font('Segoe UI',10)
function Label($text,$x,$y,$w,$h){$l=New-Object Windows.Forms.Label;$l.Text=$text;$l.SetBounds($x,$y,$w,$h);$form.Controls.Add($l);return $l}
function Button($text,$x,$y,$w){$b=New-Object Windows.Forms.Button;$b.Text=$text;$b.SetBounds($x,$y,$w,34);$form.Controls.Add($b);return $b}
$head=Label 'LinkScope | Installation wizard' 0 0 620 70
$head.BackColor=[Drawing.Color]::FromArgb(19,49,65);$head.ForeColor=[Drawing.Color]::White;$head.Font=New-Object Drawing.Font('Segoe UI',19,[Drawing.FontStyle]::Bold);$head.TextAlign='MiddleCenter'
$intro=Label 'Choose an operation. Administrator approval is requested before changes are made.' 24 88 572 52
$installed=Get-Service -Name LinkScope -ErrorAction SilentlyContinue
$state=Label $(if($installed){'Existing service: '+$installed.Status}else{'No existing LinkScope service detected.'}) 24 145 572 28
$install=Button $(if($installed){'Upgrade / repair'}else{'Install LinkScope'}) 24 183 190
$remove=Button 'Uninstall service' 226 183 170
$remove.Enabled=($null -ne $installed)
$dashboard=Button 'Open default dashboard' 408 183 188
$note=Label 'Installation uses the standard Program Files location. Configuration, credentials and monitoring history are retained. Network and HTTPS settings are managed in the dashboard.' 24 230 572 76
$progress=New-Object Windows.Forms.ProgressBar;$progress.SetBounds(24,310,572,16);$form.Controls.Add($progress)
$status=Label 'Ready.' 24 337 470 50
$close=Button 'Close' 506 350 90
$timer=New-Object Windows.Forms.Timer;$timer.Interval=500
$script:job=$null
function Start-Operation($verb){
 if($verb -eq '--uninstall' -and [Windows.Forms.MessageBox]::Show('Remove the LinkScope service? Configuration and history are retained.','Confirm uninstall','YesNo','Warning') -ne 'Yes'){return}
 try {
  $script:job=Start-Process -FilePath $exe -ArgumentList $verb -Verb RunAs -PassThru
  $install.Enabled=$false;$remove.Enabled=$false;$dashboard.Enabled=$false;$close.Enabled=$false
  $progress.Style='Marquee';$status.Text='Running elevated installer. See its console for detailed progress.';$timer.Start()
 } catch {$status.Text='Operation could not start: '+$_.Exception.Message}
}
$install.Add_Click({Start-Operation '--upgrade'})
$remove.Add_Click({Start-Operation '--uninstall'})
$dashboard.Add_Click({Start-Process 'http://127.0.0.1:9876/'})
$close.Add_Click({$form.Close()})
$form.Add_FormClosing({param($sender,$e) if($script:job -and -not $script:job.HasExited){$e.Cancel=$true}})
$timer.Add_Tick({
 if(-not $script:job.HasExited){return}
 $timer.Stop();$rc=$script:job.ExitCode;$script:job.Dispose();$script:job=$null
 $progress.Style='Blocks';$progress.Value=0
 if($rc -eq 0){$progress.Value=100;$status.Text='Operation completed successfully.'}else{$status.Text='Setup failed (exit '+$rc+'). See installer console or Windows event logs.'}
 $svc=Get-Service -Name LinkScope -ErrorAction SilentlyContinue
 $state.Text=if($svc){'Existing service: '+$svc.Status}else{'No existing LinkScope service detected.'}
 $install.Text=if($svc){'Upgrade / repair'}else{'Install LinkScope'}
 $install.Enabled=$true;$remove.Enabled=($null -ne $svc);$dashboard.Enabled=$true;$close.Enabled=$true
})
[void]$form.ShowDialog()
$timer.Dispose();$form.Dispose()
