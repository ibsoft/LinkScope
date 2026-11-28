"""Static source contracts, not actual native Windows process termination."""
from pathlib import Path
r=Path(__file__).resolve().parents[1]
response=(r/'src/EndpointResponse.cs').read_text();ep=(r/'src/EndpointProtection.cs').read_text();web=(r/'src/Web.cs').read_text();js=(r/'src/app.js').read_text();html=(r/'src/endpoint.html').read_text()
helper=response.split('static bool TerminateAndObserve(',1)[1].split('internal static object OwnedChildTerminationProbe',1)[0]
assert helper.index('WaitForSingleObject(process,0)!=258U')<helper.index('TerminateProcess(process,expectedExitCode)')<helper.index('WaitForSingleObject(process,2000U)!=0U')<helper.index('GetExitCodeProcess(process,out code)')
assert 'return code==expectedExitCode;' in helper
probe=response.split('internal static object OwnedChildTerminationProbe(',1)[1].split('[DllImport("kernel32.dll",SetLastError=true)] static extern bool IsProcessCritical',1)[0]
for key in ('Environment.SystemDirectory,"WindowsPowerShell","v1.0","powershell.exe"','GetFinalPathNameByHandle(executable.SafeFileHandle','GetFileInformationByHandle(executable.SafeFileHandle','FileAccess.Read,FileShare.Read','Start-Sleep -Seconds 10','UseShellExecute=false','child=Process.Start(psi)','new SafeFileHandle(child.Handle,false)','GetProcessId(owned)','handlePid!=(uint)pid','pid==servicePid','GetProcessTimes(owned','IsProcessCritical(owned','line.Wait(4000)','LINKSCOPE_TERMINATION_READY','!authorized()','TerminateAndObserve(owned,labExitCode','child.WaitForExit(15000)','observedExitCode.Value==labExitCode','0x4C530068U'):
    assert key in probe,key
for forbidden in ('OpenProcess(','GetProcessById(','child.Kill(','Contain(c,','Confirmed(','ExecutionPolicy Bypass','ContainmentExecutables','File.Delete(','Directory.Delete('):assert forbidden not in probe,forbidden
assert probe.index('if(stop.WaitOne(0)||!authorized())')<probe.index('child=Process.Start(psi)')<probe.index('new SafeFileHandle(child.Handle,false)')<probe.index('TerminateAndObserve(owned,labExitCode')
assert probe.rindex('if(stop.WaitOne(0)||!authorized())')<probe.index('TerminateAndObserve(owned,labExitCode')
prod=response.split('internal static string Contain(',1)[1].split('public static class LabProbeWriter',1)[0]
for key in ('!EligibleContainmentTarget(c,a)','OpenProcess(0x101001,false,a.Pid)','DateTime.FromFileTimeUtc(created)>a.Utc','IsProcessCritical','SessionId==0','Confirmed(EndpointProtection.Command','VerifyEngine(c,tcp)','if(!authorized()||stop.WaitOne(0))','TerminateAndObserve(process,1,out observedExitCode)','exitVerified?200:409'):
    assert key in prod,key
assert prod.index('Confirmed(EndpointProtection.Command')<prod.index('TerminateAndObserve(process,1,out observedExitCode)')
assert 'a.Pid!=Process.GetCurrentProcess().Id' in response
assert ep.count('EndpointResponse.Contain(c,a,stop,authorized,out exitVerified)')==2
assert ep.count('exitVerified?"info":"warning"')==2
assert ep.count('EndpointResponse.OwnedChildTerminationProbe(stop,authorized,add)')==1
lab=ep.split('internal object RunProtectionLab(',1)[1].split('internal object QuarantineStatus()',1)[0]
assert lab.index('PinProtectionLab(c,directory)')<lab.index('OwnedChildTerminationProbe(stop,authorized,add)')
assert 'if(!stop.WaitOne(0)&&authorized())termination=' in lab
assert 'if(!session.IsAdmin)Deny();var input=Decode<ProtectionLabInput>(r);' in web and '!input.confirmed' in web
assert 'owned-child termination test' in js and 'epOwnedTerminationProof' in js and 'Production malicious-process termination' in js and 'No production termination verdict.' in js
assert 'Actual malicious-process termination is not automated.' in html
print('PASS: V68 fixed owned child only, original handle, identity/lifetime/criticality, consent, shared termination and observed exit code, production gates and warning preserved (static)')
