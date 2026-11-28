"""Source wiring and DNS ABI layout fixtures; actual C# tests are in SelfCheck."""
from pathlib import Path
import ctypes, re
r=Path(__file__).resolve().parents[1]
w=(r/'src/ClamUpdateWorker.cs').read_text(); e=(r/'src/EndpointProtection.cs').read_text(); js=(r/'src/app.js').read_text(); s=(r/'src/SelfCheck.cs').read_text()
class DnsTxtRecord64(ctypes.Structure):
    _fields_=[('Next',ctypes.c_uint64),('Name',ctypes.c_uint64),('Type',ctypes.c_uint16),('DataLength',ctypes.c_uint16),('Flags',ctypes.c_uint32),('Ttl',ctypes.c_uint32),('Reserved',ctypes.c_uint32),('Count',ctypes.c_uint32),('FirstString',ctypes.c_uint64)]
assert DnsTxtRecord64.Count.offset==32 and DnsTxtRecord64.FirstString.offset==40
for part in ['EntryPoint="DnsQuery_W"','EntryPoint="DnsFree"','FreeDnsRecords(records,1)','Marshal.OffsetOf(typeof(DnsTxtRecord),"FirstString")','fields[2]','fields[3]','age>=-300&&age<=10800','TaskScheduler.Default','TaskCreationOptions.LongRunning','HarvestOfficialDns()','dnsTask.Result.Item2','task.Wait(3000)','if(wait&&!task.IsCompleted)','TotalMinutes>=(validCached?10:2)','TotalMinutes>15','if(advertised<=0)return "Unknown"','if(loaded<advertised)','if(loaded>advertised)','ageStatus=="Unknown"||loaded<=0','if(changed||DailyReloadNeeded(log))','loaded>=disk']:
    assert part in w,part
assert 'CompareOfficialDefinition(ageStatus,loadedDatabase,false,out signatureComparison)' in e
assert 'diskDaily>loadedDatabase' in e and 'signatureComparison=online?signatureComparison' in e
assert 'lastSignatureComparison>=5' in e and 'lastSignatureComparison==0' in e
refresh=e.split('void RefreshSignatureComparison(',1)[1].split('internal object Tick(',1)[0]
assert 'CompareOfficialDefinition(ageStatus,loadedDatabase,false,out signatureComparison)' in refresh and 'lastSignatureCheck=' not in refresh
assert e.index('RefreshSignatureComparison(db,c);')>e.index('lastSignatureCheck=History.Now();')
assert 'r.signatureComparison' in js and 'result.signatureComparison' in js
for part in ['current advertised version with old publication date','newer advertised daily version overrides young age','unavailable DNS retains age warning','stale DNS advertisement rejected','future DNS advertisement rejected','malformed DNS advertisement rejected']:
    assert part in s
assert int((r/'source-build-version.txt').read_text().strip().lstrip('V'))>=57
print('PASS: static source wiring, x64 DNS struct layout model, cached async resolver, version comparison / fallback / reload gates, UI detail and native self-test registration. Windows API and C# execution not performed.')
