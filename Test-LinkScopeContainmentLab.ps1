# Windows PowerShell 5.1. Local, disposable lab only; never alters LinkScope policy.
[CmdletBinding(SupportsShouldProcess=$true)]
param([string]$LabRoot,[switch]$TerminateChild,[switch]$Eicar,[switch]$AutomaticWriter)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'Use Windows PowerShell 5.1.'}
# Automatic mode is invoked only by the service with its own pinned, CREATE_NEW marker.
# No generated executable, command input, policy changes or termination in this mode.
if($AutomaticWriter){
    if($TerminateChild -or $Eicar -or $LabRoot){throw 'Automatic writer is a fixed benign exercise.'}
    $marker=[Environment]::GetEnvironmentVariable('LINKSCOPE_LAB_MARKER','Process')
    if(!$marker -or $marker -notmatch '^[A-Za-z]:\\.+\\LinkScope-Audit-Probe-[0-9a-f]{32}\.txt$' -or [IO.Path]::GetFullPath($marker) -ine $marker){throw 'Invalid service marker.'}
    $identity=[Environment]::GetEnvironmentVariable('LINKSCOPE_LAB_IDENTITY','Process')
    if($identity -notmatch '^[0-9A-F]{8}:[0-9A-F]{8}:[0-9A-F]{8}$'){throw 'Invalid service file identity.'}
    # Load the installed assembly without invoking its entry point. The method executes in
    # THIS PowerShell PID, verifies the physical file identity on its own handle, then writes.
    $assemblyPath=[IO.Path]::Combine([IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($PSCommandPath)),'LinkScope.exe')
    $type=[Reflection.Assembly]::LoadFrom($assemblyPath).GetType('LinkScope.LabProbeWriter',$true)
    $null=$type.GetMethod('WriteMarker').Invoke($null,[object[]]@($marker,$identity))
    [Console]::WriteLine('LINKSCOPE_MARKER:'+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($marker)))
    [Console]::Out.Flush()
    # Parent closes stdin after evidence collection; EOF also releases this process if the service exits.
    $null=[Console]::ReadLine()
    exit 0
}
if([string]::IsNullOrWhiteSpace($LabRoot)){throw 'Specify an existing disposable LabRoot.'}

$root=[IO.Path]::GetFullPath($LabRoot).TrimEnd('\')
if($root -notmatch '^[A-Za-z]:\\.+'){throw 'Choose an existing local disposable directory, not a drive root.'}
$drive=New-Object IO.DriveInfo ([IO.Path]::GetPathRoot($root))
if($drive.DriveType -ne [IO.DriveType]::Fixed){throw 'Use a fixed local drive.'}
foreach($system in @($env:windir,$env:ProgramFiles,${env:ProgramFiles(x86)},$env:ProgramData,$env:USERPROFILE)){
    if(!$system){continue};$system=[IO.Path]::GetFullPath($system).TrimEnd('\')
    if($root.Equals($system,[StringComparison]::OrdinalIgnoreCase) -or $system.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase) -or ($system -ne $env:USERPROFILE -and $root.StartsWith($system+'\',[StringComparison]::OrdinalIgnoreCase))){throw 'Use a dedicated non-system test folder, not a system or profile root.'}
}
$check=Get-Item -LiteralPath $root -Force
if(!$check.PSIsContainer){throw 'LabRoot must be an existing directory.'}
for($d=$check;$null -ne $d;$d=$d.Parent){if($d.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse points are not allowed.'}}
$folder=Join-Path $root ('LinkScope-Containment-Lab-'+[Guid]::NewGuid().ToString('N'))
if(!$PSCmdlet.ShouldProcess($folder,'Create isolated test writer and marker; optionally terminate only that child and create EICAR')){return}
if(Test-Path -LiteralPath $folder){throw 'Unexpected existing lab directory.'}
New-Item -ItemType Directory -Path $folder | Out-Null
$exe=Join-Path $folder 'LinkScopeLab.exe';$marker=Join-Path $folder 'audit-marker.txt'
$code=@'
using System;
using System.IO;
using System.Text;
using System.Threading;
public static class LinkScopeLabWriter {
    public static int Main(){
        string path=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"audit-marker.txt");
        byte[] text=Encoding.ASCII.GetBytes("LinkScope isolated audit marker. Harmless test only.\r\n");
        using(var file=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.Read)){file.Write(text,0,text.Length);file.Flush(true);}
        Thread.Sleep(50000);return 0;
    }
}
'@
Add-Type -TypeDefinition $code -Language CSharp -OutputAssembly $exe -OutputType ConsoleApplication
$started=[DateTime]::UtcNow;$proc=Start-Process -FilePath $exe -WorkingDirectory $folder -PassThru -WindowStyle Hidden
$pidOfChild=$proc.Id;$exitKind='Not verified';$auditState='Not verified';$auditRecords=@();$eicarState='Not requested';$errors=@()
try{
    # Hold the handle for the exact child that this invocation created.
    $null=$proc.Handle
    Write-Host "Lab marker: $marker" -ForegroundColor Cyan
    Write-Host "Child PID: $pidOfChild. Paste the marker into Test Center and run diagnostics within 30 seconds."
    if($TerminateChild){
        if($proc.WaitForExit(40000)){$exitKind='Exited before local termination; inspect evidence'}
        else{$proc.Kill();if($proc.WaitForExit(5000)){$exitKind='Local child termination observed'}else{$exitKind='Local child exit not verified'}}
    }else{if($proc.WaitForExit(60000)){$exitKind='Child exited without local termination; inspect exit code'}else{$exitKind='Child exit not verified'}}
    try{
        $auditRecords=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4663;StartTime=$started.ToLocalTime()} -MaxEvents 512 -ErrorAction Stop | ForEach-Object {
            $xml=[xml]$_.ToXml();$fields=@{};foreach($item in $xml.Event.EventData.Data){$fields[[string]$item.Name]=[string]$item.'#text'}
            if($fields.ObjectName -ieq $marker -and $fields.ProcessName -ieq $exe -and $fields.ProcessId -match '^0x[0-9a-f]+$' -and [Convert]::ToInt64($fields.ProcessId.Substring(2),16) -eq $pidOfChild -and $fields.AccessMask -match '^0x[0-9a-f]+$' -and ([Convert]::ToInt64($fields.AccessMask.Substring(2),16) -band 0x10046)){
                [pscustomobject]@{record=$_.RecordId;utc=$_.TimeCreated.ToUniversalTime().ToString('o');path=$marker;image=$exe;pid=$pidOfChild;accessMask=$fields.AccessMask}
            }
        })
        $auditState=if($auditRecords.Count){'Matching local audit event recorded'}else{'No matching event in returned records'}
    }catch{$auditState='Local audit query unavailable or empty';$errors+=$_.Exception.Message}
    if($Eicar){
        # Official harmless 68-byte antivirus test string. Only the new lab path is written.
        $eicarPath=Join-Path $folder 'eicar.com';$bytes=[Text.Encoding]::ASCII.GetBytes('X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')
        try{$f=[IO.File]::Open($eicarPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$f.Write($bytes,0,$bytes.Length)}finally{$f.Dispose()};$eicarState='Write completed; check exact path in LinkScope evidence and vault'}catch{$eicarState='Write blocked or failed; do not assume LinkScope detection';$errors+=$_.Exception.Message}
    }
}finally{
    $exitCode=$null;try{if($proc.HasExited){$exitCode=$proc.ExitCode}}catch{}
    $proc.Dispose()
    $report=[ordered]@{kind='Local lab only; not production containment';startedUtc=$started.ToString('o');finishedUtc=[DateTime]::UtcNow.ToString('o');folder=$folder;marker=$marker;childPid=$pidOfChild;childExit=$exitKind;childExitCode=$exitCode;localAudit=$auditState;auditRecords=$auditRecords;eicar=$eicarState;errors=$errors}
    $reportPath=Join-Path $folder 'lab-report.json';$json=$report|ConvertTo-Json -Depth 6;$f=[IO.File]::Open($reportPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$b=[Text.Encoding]::UTF8.GetBytes($json);$f.Write($b,0,$b.Length)}finally{$f.Dispose()}
    Write-Host "Report: $reportPath"; $report
}
