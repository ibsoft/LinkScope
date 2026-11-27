"""SQLite diagnostic queries and source wiring; not native Windows execution."""
from pathlib import Path
import sqlite3,re
root=Path(__file__).resolve().parents[1]
s=(root/'src/EndpointProtection.cs').read_text(); p=(root/'src/Program.cs').read_text()
assert 'if(verb=="--endpoint-file-status"){try{RequireAdmin();' in p
assert 'EndpointProtection.DiagnoseFile(args[1])' in p
body=s.split('internal static void DiagnoseFile(',1)[1].split('void Activity(',1)[0]
assert 'new Sqlite(fileDb,true)' in body and 'db.Exec(' not in body
assert 'NOT the LinkScope service identity' in body and 'if(!c.Enabled||!inScope||excluded)' in body
assert 'Command(c.Port,"INSTREAM",file,stop)' in body
assert 'stage="open file for reading"' in s and 'stage="ClamAV INSTREAM"' in s
assert 'Activity(db,p,full,"Failed",activityTimer,reply);if(!full&&!canary)RetryLocked(c,p,retries);return false;' in s
assert 'download!=bestDownload?download:item.First<best.First' in s
c=sqlite3.connect(':memory:')
for table in ['scan_activity','findings']:
 q=re.search(r'db.Exec\("(CREATE TABLE IF NOT EXISTS '+table+r'\([^"\n]+)"\)',s).group(1);c.execute(q)
u=(root/'src/UsnJournal.cs').read_text();c.execute(re.search(r'db.Exec\("(CREATE TABLE IF NOT EXISTS usn_pending[^"\n]+)"',u).group(1))
path=r'C:\Users\User\Downloads\eicar.com.txt'
c.execute('INSERT INTO scan_activity(utc,path,source,result,durationMs,detail) VALUES(?,?,?,?,?,?)',(123,path,'Real-time / canary','Failed',1,'open file for reading: UnauthorizedAccessException'))
c.execute('INSERT INTO scan_activity(utc,path,source,result,durationMs,detail) VALUES(?,?,?,?,?,?)',(124,r'C:\other.txt','Scheduled / manual','Clean',1,'stream: OK'))
c.execute('INSERT INTO usn_pending VALUES(?,?)',('active',path))
queries=re.findall(r'db.Rows\("(SELECT [^"\n]+)"',body)
assert c.execute(queries[0],(path.lower(),)).fetchall()==[(123,'Real-time / canary','Failed','open file for reading: UnauthorizedAccessException')]
assert c.execute(queries[1],(path,)).fetchall()==[]
assert c.execute(queries[2],('active',path.lower())).fetchone()==(1,)
assert c.execute(queries[2],('other',path)).fetchone() is None
print('PASS: exact-path read-only diagnostics, SQLite case-insensitive query and scope guard, engine error retries, priority fairness source wiring. Native Windows runtime not executed.')
