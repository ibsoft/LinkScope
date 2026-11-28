"""V67 static trust-boundary checks. No native Windows validation or process termination."""
from pathlib import Path
r=Path(__file__).resolve().parents[1]
cs=(r/'src/EndpointProtection.cs').read_text(); response=(r/'src/EndpointResponse.cs').read_text(); js=(r/'src/app.js').read_text(); html=(r/'src/endpoint.html').read_text()
probe=cs.split('internal object RunEnrolledCanaryProbe(',1)[1].split('internal object RunProtectionLab(',1)[0]
for key in ('INSERT INTO canaries(path,hash) VALUES(?,?)','DELETE FROM canaries WHERE path=? AND hash=?','SELECT 1 FROM canaries WHERE path=?','ChangeEnrolledLabCanary','CleanupEnrolledLabCanary',"seq>? AND path=? COLLATE NOCASE AND hash=? AND change='Canary integrity violation'",'auditRecord>eventBefore','pid==expectedPid','source=="watcher"','EligibleContainmentTarget','baselineRemoved'):
    assert key in probe,key
for forbidden in ('INSERT INTO incidents','Issue(db,','CheckFile(','ScanWatcher(','Contain(c,','Quarantine(','File.Delete(','CanaryPaths=','TestPaths='):
    assert forbidden not in probe,forbidden
assert 'bool canary=c.CanaryPaths.Contains(p,StringComparer.OrdinalIgnoreCase)||ActiveLabCanary(c,p)!=null' in cs
assert 'watcherInspectionPath=work.ObservedWatcher?work.Path:null;try{finished=CheckFile' in cs
assert 'if(CanaryContentChanged(expected,hash))CanaryIssue' in cs
assert 'ObservedWatcher=true' in cs and 'ObservedWatcher=string.Equals(watcherInspectionPath,path,StringComparison.OrdinalIgnoreCase)' in cs
assert 'if(controlled!=null&&string.Equals(controlled.Path,path,StringComparison.OrdinalIgnoreCase))return;' in cs
assert 'if(publish)auditStatus=' in cs
read=response.split('internal static EndpointWriter FindIncidentWriter(',1)[1].split('internal static long SecurityWatermark',1)[0]
for key in ('PathType.LogName,"*"','ev.Id!=4663','(mask&0x6)==0','found.Pid!=(int)pid','boundary?found:null'): assert key in read,key
assert 'TerminateProcess' not in read
contain=response.split('internal static string Contain(',1)[1].split('public static class LabProbeWriter',1)[0]
for key in ('!EligibleContainmentTarget(c,a)','DateTime.FromFileTimeUtc(created)>a.Utc','IsProcessCritical','SessionId==0','Confirmed(EndpointProtection.Command','VerifyEngine(c,tcp)','if(!authorized()||stop.WaitOne(0))','TerminateProcess(process,1)'): assert key in contain,key
assert 'a.Pid!=Process.GetCurrentProcess().Id' in response
assert 'ep-suite-full' in html and 'ep-suite-production' in html and 'epEnrolledProof' in js
assert 'Production process containment' in js and 'No production termination verdict.' in js
print('PASS: V67 normal watcher path, no fabricated incident, temporary enrollment cleanup, bounded unambiguous correlation, unchanged production termination prerequisites, report coverage (static)')
