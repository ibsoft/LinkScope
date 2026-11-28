"""SQLite fixture and source integration checks; not native C# execution."""
from pathlib import Path
import sqlite3,re
root=Path(__file__).resolve().parents[1]
s=(root/'src/EndpointProtection.cs').read_text(); p=(root/'src/Program.cs').read_text()
assert 'if(verb=="--endpoint-scan-file"){try{RequireAdmin();' in p
assert 'case "--endpoint-engine-self-test": RequireAdmin(); return EndpointProtection.TestEngineSignature();' in p
assert 'UsnJournalMonitor.Schema(db);ProbeSchema(db);return db;' in s
body=s.split('void ProcessFileProbe(',1)[1].split('internal static int TestEngineSignature()',1)[0]
assert 'if(stop.WaitOne(0)||!authorized())return;' in body
assert 'if(!c.Enabled||!c.Paths.Any(x=>Under(path,x))||Excluded(c,path))' in body
assert 'CheckFile(db,c,path,stop,()=>false,false,MaxLockedRetries);' in body
assert 'WHERE seq>? AND path=? COLLATE NOCASE' in body
assert 'if(full)errors++;ScanIssue(db,c,p,"Engine scan incomplete","ClamAV offline; no signature verdict")' in s
assert '&& !HasWatcher' in s or '&& !HasWatcher' .replace(' ','') in s
assert 'ex is UnauthorizedAccessException||stage=="ClamAV INSTREAM"' in s
assert s.index('ProcessFileProbe(db,c,stop,authorized);')<s.index('ScanWatcher(db,c,stop,authorized,0);')
assert s.index('CheckFile(db,c,canary,stop,authorized,false)')<s.index('ProcessFileProbe(db,c,stop,authorized);')
db=sqlite3.connect(':memory:')
db.execute(re.search(r'db.Exec\("(CREATE TABLE IF NOT EXISTS endpoint_probe[^"\n]+)"',s).group(1))
db.execute(re.search(r'db.Exec\("(CREATE TABLE IF NOT EXISTS scan_activity[^"\n]+)"',s).group(1))
path=r'C:\Users\User\Downloads\test.txt'
db.execute('INSERT INTO endpoint_probe(id,path,created) VALUES(?,?,?)',('a',path,100))
db.execute('INSERT INTO endpoint_probe(id,path,created) VALUES(?,?,?)',('b',path,101))
assert db.execute('SELECT id,path FROM endpoint_probe WHERE finished IS NULL ORDER BY created,rowid LIMIT 1').fetchone()==('a',path)
db.execute('INSERT INTO scan_activity(utc,path,source,result,durationMs,detail) VALUES(?,?,?,?,?,?)',(90,path,'Real-time / canary','Clean',1,'old result'))
before=db.execute('SELECT COALESCE(MAX(seq),0) FROM scan_activity').fetchone()[0]
db.execute('INSERT INTO scan_activity(utc,path,source,result,durationMs,detail) VALUES(?,?,?,?,?,?)',(102,path,'Real-time / canary','Failed',1,'open file for reading: UnauthorizedAccessException'))
result,detail=db.execute('SELECT result,detail FROM scan_activity WHERE seq>? AND path=? COLLATE NOCASE ORDER BY seq DESC LIMIT 1',(before,path.lower())).fetchone()
assert result=='Failed' and 'UnauthorizedAccessException' in detail
db.execute('UPDATE endpoint_probe SET finished=?,result=?,detail=? WHERE id=?',(103,result,detail,'a'))
assert db.execute('SELECT finished,result,detail FROM endpoint_probe WHERE id=?',('a',)).fetchone()==(103,result,detail)
assert db.execute('SELECT id FROM endpoint_probe WHERE finished IS NULL ORDER BY created,rowid LIMIT 1').fetchone()==('b',)
# Verify the in-memory standard fixture length without storing an EICAR file.
engine=s.split('internal static int TestEngineSignature()',1)[1].split('internal static void DiagnoseFile',1)[0]
parts=re.search(r'Encoding.ASCII.GetBytes\(@"([^"]+)"\+"([^"]+)"\)',engine).groups()
assert len(''.join(parts).encode('ascii'))==68
assert 'new MemoryStream(test,false)' in engine and 'Command(c.Port,"INSTREAM",stream,stop)' in engine
print('PASS: service probe authorization, queue persistence, fresh verdict selection, retry/coverage checks, EICAR memory fixture length. Windows runtime not executed.')
