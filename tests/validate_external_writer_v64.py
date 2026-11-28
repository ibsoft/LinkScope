"""Static source assertions; not a native Windows execution test."""
from pathlib import Path
r=Path(__file__).resolve().parents[1]
cs=(r/'src/EndpointResponse.cs').read_text(); web=(r/'src/Web.cs').read_text(); ps=(r/'Test-LinkScopeContainmentLab.ps1').read_text(); js=(r/'src/app.js').read_text()
writer=cs.split('internal static void WriteExternalMarker(',1)[1].split('internal static object LiveAuditProbe(',1)[0]
assert 'CreateFile(path,0x40000080U,7,IntPtr.Zero,3,0x00200000' in writer
assert writer.index('VerifyHandle(handle,path)')<writer.index('ProbeIdentity(info),expectedIdentity')<writer.index('file.Write(text')
assert 'info.SizeHigh!=0||info.SizeLow!=0' in writer and 'SafeScope(path)' in writer
probe=cs.split('internal static object LiveAuditProbe(',1)[1].split('static void Confirmed(',1)[0]
for key in ('scriptLock=new FileStream(script,FileMode.Open,FileAccess.Read,FileShare.Read)','VerifyHandle(scriptLock.SafeFileHandle,script)','Program.Resource("Test-LinkScopeContainmentLab.ps1")','SequenceEqual(embedded)','Environment.SystemDirectory,"WindowsPowerShell","v1.0","powershell.exe"','-NoLogo -NoProfile -NonInteractive -File','-AutomaticWriter','UseShellExecute=false','LINKSCOPE_LAB_IDENTITY','ProbeIdentity(original)','pid==servicePid','GetProcessTimes(childQuery','eventUtc<childCreated','LiveImage(childQuery,image)','baselineRecord=baseline.RecordId.Value','ev.RecordId.Value<=baselineRecord','line.Wait(6000)','child.StandardInput.Close()','child.WaitForExit(3000)&&child.ExitCode==0','exitedCleanly','FileNotFoundException'):
    assert key in probe,key
for forbidden in ('ExecutionPolicy Bypass','TerminateProcess(','child.Kill(','File.Delete(','Directory.Delete(','SetAccessControl(','-Command '): assert forbidden not in probe,forbidden
branch=ps.split('if($AutomaticWriter){',1)[1].split('if([string]::IsNullOrWhiteSpace($LabRoot))',1)[0]
for key in ('if($TerminateChild -or $Eicar -or $LabRoot)','LINKSCOPE_LAB_MARKER','LINKSCOPE_LAB_IDENTITY','GetType(\'LinkScope.LabProbeWriter\'','GetMethod(\'WriteMarker\').Invoke','ToBase64String','[Console]::ReadLine()','exit 0'): assert key in branch,key
for forbidden in ('Invoke-Expression','Start-Process','Add-Type','Remove-Item','Eicar-STANDARD'): assert forbidden not in branch,forbidden
route=web.split('else if(post&&(r.Path=="/ui/endpoint-audit-probe"||r.Path=="/ui/endpoint-external-probe"))',1)[1].split('else if(r.Path==',1)[0]
for key in ('if(!session.IsAdmin)Deny()','ResponsePaths.Contains(input.directory','Program.ServiceMode','lastExternalAuditProbe','r.AuditAction=','LiveAuditProbe(settings.Endpoint,input.directory,external)'):assert key in route,key
assert 'endpoint-external-probe' not in web.split('static readonly HashSet<string> ViewerReads',1)[1].split('internal static bool ViewerAllowed',1)[0]
assert 'Access.Equal(session.Csrf,r.Header("X-CSRF-Token"))' in web
assert 'm.pid!==m.servicePid' in js and 'created<=Date.parse(p.eventUtc)' in js
print('PASS: static fixed-script, embedded-byte verification, scope, physical identity before write, independent process, watermark, exact event proof, normal exit, admin/CSRF/rate-limit and no arbitrary command/production response checks')
