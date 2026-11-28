"""Portable SQL execution and source-contract tests. Native Windows tests required."""
from pathlib import Path
import sqlite3,re
root=Path(__file__).resolve().parents[1]
e=(root/'src/EndpointProtection.cs').read_text(); u=(root/'src/UsnJournal.cs').read_text(); j=(root/'src/app.js').read_text()
assert 'catch(ScanReparseException ex){return RecordReparseBoundary' in e
assert 'if(result.Kind=="Reparse"){return RecordReparseBoundary' in e
helper=u.split('ScanBatch ReadScan(',1)[1].split('void ScanRun(',1)[0]
assert helper.index('LocalScanPath(path,c)')<helper.index('catch(EndpointProtection.ScanReparseException')<helper.index('CreateFile(path')
assert 'if(result.Kind=="Reparse"&&(mode>1' in u
boundary=e.split('bool RecordReparseBoundary(',1)[1].split('void RecordLocked(',1)[0]
assert 'ScanIssue(db,c,path,"File scan error",text)' in boundary and 'if(full)errors++' in boundary
assert 'return true;' in boundary and 'RetryLocked(' not in boundary and 'Resolve(' not in boundary and 'CanaryIssue(' not in boundary
assert 'Activity(db,path,full,"Reparse boundary"' in boundary
assert 'SizeLimitDetail(result.Size,c.MaxFileMiB)' in e and 'Size=file.Length' in u
assert 'traversalLimitReached=true' in e and 'if(!traversalLimitReached)Resolve' in e
assert 'baselineDiscoveredPending=pending.Count' in e and 'baselineVisited=visited.Count' in e
assert 'protected-scope membership unknown' in u
assert 'Last finished baseline attempt' in j and 'Durable ready:' in j
# Run real category aggregation SQL against representative records. No routine
# or explicit-root warning is rewritten; only the aggregate query is tested.
db=sqlite3.connect(':memory:')
db.execute('CREATE TABLE findings(change TEXT,detail TEXT,active INT,severity TEXT)')
rows=[('File scan error','Deferred: file in use',1,'coverage'),('File scan error','Reparse boundary: target not followed',1,'coverage'),('File scan error','Reparse boundary: target not followed',1,'coverage'),('File scan limited','100 MiB',1,'coverage'),('Engine scan incomplete','offline',1,'coverage'),('File scan error','denied',1,'coverage'),('File scan error','denied',0,'coverage'),('Malware signature detected','signature',1,'critical')]
db.executemany('INSERT INTO findings VALUES(?,?,?,?)',rows)
q=re.search(r'var coverageBreakdown=db.Rows\("([^"\n]+)"',e)[1]
assert dict(db.execute(q))=={'Deferred — file in use':1,'Reparse boundary — target unverified':2,'Size limit':1,'Engine incomplete':1,'File scan error':1}
for table in ['usn_pending','usn_retry']:
 db.execute(re.search(r'db.Exec\("(CREATE TABLE IF NOT EXISTS '+table+r'\([^"\n]+)"',u)[1])
db.executemany('INSERT INTO usn_pending VALUES(?,?)',[('a','locked'),('a','ready'),('b','other')]);db.execute('INSERT INTO usn_retry VALUES(?,?,?)',('a','locked',100))
q=re.search(r'internal int ReadyDepth\(Sqlite db\).*?db.Rows\("([^"\n]+)"',u)[1]
assert db.execute(q,('a',99)).fetchone()==(1,)
assert db.execute(q,('a',100)).fetchone()==(2,)
print('PASS: boundary handling source contracts; actual SQLite coverage category and ready queue queries; Windows runtime not executed.')
