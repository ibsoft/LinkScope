"""V29 regression checks: actual SQLite statements, source contracts; native runtime not run."""
from pathlib import Path
import re, sqlite3, tempfile
r=Path(__file__).resolve().parents[1]
e=(r/'src/EndpointProtection.cs').read_text(); u=(r/'src/UsnJournal.cs').read_text(); j=(r/'src/app.js').read_text(); h=(r/'src/endpoint.html').read_text()
assert 'faultedWatchers[p]=instance' in e and 'ReferenceEquals(current,fault.Value)' in e
assert 'localWatchers.Remove(fault.Key);watchers.Remove(current);current.Dispose()' in e
assert 'ConsumeWatcherFaults();SyncPrivilegedWatchers(c);var privilegedSnapshot' in e
assert 'if(journalGap){if(running){journalGapDuringScan=true;rescan=true;}else nextScan=0;return;}' in e
assert 'if(!usn.RetainWatcher(db,work.Path,work.Priority))' in e
assert e.index('usn.RetainWatcher(db,work.Path,work.Priority)') < e.index('bool finished=CheckFile(db,c,work.Path')
assert 'MarkEngineTransportFailed(db,ex.Message)' in e and 'if(online&&running&&pending.Count>0)' in e
assert 'ClamUpdateWorker.VerifyScanServiceOwner' in e
assert 'UsnJournalService.VerifyScanPath(file.SafeFileHandle,p)' in e
assert 'rootCoverage=rootCoverage' in e and 'fullScanComplete=complete' in e
assert 'endpoint-root-coverage' in j and 'endpoint-root-coverage' in h
assert 'string.Equals(reply,"stream: OK",StringComparison.Ordinal)' in e
# Run real SQL from durable watcher insertion and deferral against on-disk database.
schema=re.findall(r'db\.Exec\("(CREATE TABLE IF NOT EXISTS usn_[^"\n]+)"',u)
body=u.split('internal bool RetainWatcher(',1)[1].split('internal void Defer(',1)[0]
insert=re.findall(r'db\.Exec\("(INSERT OR IGNORE INTO usn_[^"\n]+)"',body)
defer=re.search(r'db\.Exec\("(INSERT OR REPLACE INTO usn_retry\(scope,path,ready\)[^"\n]+)"',u)[1]
query=re.search(r'db\.Rows\("(SELECT path FROM usn_pending p WHERE scope=\? AND NOT EXISTS[^"\n]+ORDER BY rowid LIMIT \?)"',u)[1]
with tempfile.TemporaryDirectory() as d:
 p=Path(d)/'state.db'; db=sqlite3.connect(p)
 for sql in schema: db.execute(sql)
 a=r'C:\Users\Example\Documents\test.txt';b=r'D:\Apps\app.dll'
 for path in (a,b,a):
  for sql in insert: db.execute(sql,('scope',path))
 db.execute(defer,('scope',a,130));db.commit();db.close();db=sqlite3.connect(p)
 assert db.execute('SELECT COUNT(*) FROM usn_pending').fetchone()==(2,)
 assert db.execute(query,('scope',100,10)).fetchall()==[(b,)]
 assert db.execute(query,('scope',130,10)).fetchall()==[(a,),(b,)]
 assert db.execute(query,('other',130,10)).fetchall()==[]
 db.close()
print('PASS: root faults, recovery scheduling, strict verdict, scan pause, per-folder evidence, and durable deduplicated SQLite retries; Windows runtime pending.')
