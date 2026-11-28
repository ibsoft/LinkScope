"""Portable V38 contracts and real SQLite migration; not Windows runtime tests."""
from pathlib import Path
import sqlite3,re,json,xml.etree.ElementTree as ET
r=Path(__file__).resolve().parents[1]
e=(r/'src/EndpointProtection.cs').read_text(); u=(r/'src/UsnJournal.cs').read_text(); b=(r/'src/EndpointDiskBudget.cs').read_text(); j=(r/'src/app.js').read_text(); html=(r/'src/settings.html').read_text()
def sql(prefix):return re.search(r'db\.(?:Exec|Rows)\("('+re.escape(prefix)+r'[^"\n]*)"',e)[1]
# Exercise upgrade of V37 table with actual SQL used by V38.
db=sqlite3.connect(':memory:');db.execute(sql('CREATE TABLE IF NOT EXISTS clean_verdict_cache'))
db.execute('INSERT INTO clean_verdict_cache VALUES(?,?,?,?,?)',('old','C:\\test','a'*64,'b'*64,1000));db.execute(sql('ALTER TABLE clean_verdict_cache ADD COLUMN'))
assert db.execute('SELECT stamp FROM clean_verdict_cache').fetchone()==(None,)
path=r'C:\\Apps\\app.dll';h='c'*64;gen='d'*64;stamp='e'*64
save=sql('INSERT OR REPLACE INTO clean_verdict_cache'); lookup=sql('SELECT hash,generation,stamp FROM clean_verdict_cache')
db.execute(save,('p',path,h,gen,2000,stamp)); assert db.execute(lookup,('p',path.lower(),1000,2001)).fetchone()==(h,gen,stamp)
assert db.execute(lookup,('different-policy',path,1000,2001)).fetchone() is None
assert db.execute(lookup,('p',path,2000,2001)).fetchone() is None
assert db.execute('SELECT verified FROM clean_verdict_cache WHERE policy=\'p\'').fetchone()==(2000,)
db.execute(sql('DELETE FROM clean_verdict_cache WHERE path=?'),(path,));assert db.execute(lookup,('p',path,1000,2001)).fetchone() is None
local=e.split('bool CheckFile(',1)[1].split('internal static string SizeLimitDetail',1)[0]
assert local.index('VerifyScanPath(file.SafeFileHandle,p)')<local.index('MetadataEligible(db,c,p,candidate)')<local.index('FileHash(file,budget)')
assert 'stamp==UsnJournalService.FileChangeStamp(file.SafeFileHandle,p)' in local
assert 'verifiedGeneration!=null&&stamp!=null&&stamp==UsnJournalService.FileChangeStamp' in local
assert 'if(CacheEligible(c,full,canary))generation=ClamUpdateWorker.CacheGeneration' in local
assert 'full&&!canary&&Program.ServiceMode&&c.Port==3310&&online' in e
for term in ['c.MetadataFastCache','!journalGapDuringScan','!baselineResumed','!rescan','usn.Covers(p)','USN journal coverage gap','SELECT 1 FROM files WHERE scope=? AND path=? AND hash=?']:
    assert term in e.split('bool MetadataEligible(',1)[1].split('bool CheckFile(',1)[0],term
for term in ['GetVolumeNameForVolumeMountPoint','GetFinalPathNameByHandle(file','GetFileInformationByHandleEx','info.Links!=1','0x000900eb','BitConverter.ToUInt16(record,4)!=2','usn<first','usn>=tail','afterId!=id','usn<afterFirst','basic.Change','basic.Write']:
    assert term in u,term
helper=u.split('ScanBatch ReadScan(',1)[1].split('void ScanRun(',1)[0]
assert helper.index('LocalScanPath(path,c)')<helper.index('MetadataCached=true')<helper.index('FileHash(file,budget)')
assert 'stamp==FileChangeStamp(handle,path)' in helper and 'generation==expectedGeneration' in helper
assert 'result.Stamp!=stamp' in u and 'candidate.Stamp!=result.Stamp' in e
assert 'UPDATE files SET seen=? WHERE scope=? AND path=?' in e
for term in ['EndpointReadBudget','stop.WaitOne','0x00010000','0x00020000','PhysicalDisk','% Idle Time','high>=2','low>=2','GetSystemPowerStatus']:
    assert term in b,term
assert 'full&&!canary?new EndpointReadBudget' in local and 'null,budget)' in local
assert 'WatchCounts()[0]==0&&usn.ReadyDepth(db)==0' in e
assert 'string.IsNullOrEmpty(baselineThrottleReason)' in e
assert e.index('ScanWatcher(db,c,stop,authorized,0);')<e.index('baselineThrottleReason=running?')
assert 'metadataCachedChecks=metadataCachedChecks' in e and 'Metadata-only cache hits' in j
cfg=json.loads((r/'src/default.json').read_text())['Endpoint'];assert cfg['BackgroundReadMiB']==10 and cfg['MetadataFastCache'] and cfg['BackgroundPauseOnBusyDisk'] and not cfg['BackgroundPauseOnBattery']
for key in ['BackgroundReadMiB','MetadataFastCache','BackgroundPauseOnBusyDisk','BackgroundPauseOnBattery']:
    assert key in e and key in j and 'id="Endpoint'+key+'"' in html
ns={'m':'http://schemas.microsoft.com/developer/msbuild/2003'}
assert any(x.attrib['Include']==r'src\EndpointDiskBudget.cs' for x in ET.parse(r/'LinkScope.csproj').findall('.//m:Compile',ns))
assert 'EndpointDiskBudget.cs' in (r/'tools/RequiredSources.txt').read_text().splitlines()
assert 'EndpointDiskBudget.cs' not in (r/'setup/LinkScope.Setup.csproj').read_text()
print('PASS: V37 SQLite migration, cache age/policy/stamp and deletion; NTFS metadata and fallback guards, scoped helper response contract, pacing, priority and settings wiring. Windows API behavior not executed.')
