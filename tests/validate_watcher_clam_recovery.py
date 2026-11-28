"""Portable source assertions and actual SQLite retry persistence; not Windows I/O."""
from pathlib import Path
import sqlite3, re, tempfile
r=Path(__file__).resolve().parents[1]
e=(r/'src/EndpointProtection.cs').read_text(); u=(r/'src/UsnJournal.cs').read_text()
assert 'new Thread(PrivilegedWatcherLoop)' in e and 'privilegedWatcherThread.Start()' in e
pump=e.split('void PrivilegedWatcherLoop()',1)[1].split('Dictionary<string,PrivilegedWatcherState> PrivilegedWatcherSnapshot',1)[0]
assert 'FetchWatcher(root)' in pump and 'ReferenceEquals(saved,privilegedWatcherPolicy)' in pump and 'Sqlite' not in pump
assert 'state.Verified=batch.WatchGap?0:completed' in pump
assert 'PrivilegedWatcherStartupSeconds=15' in e and 'PrivilegedWatcherFreshSeconds=30' in e
assert 'ClamScanDeadlineMs=30000,ClamControlDeadlineMs=5000' in e
command=e.split('internal static string Command(',1)[1].split('internal static bool Malware',1)[0]
assert 'ConnectAsync' in command and 'WriteAsync' in command and 'ReadAsync' in command and 'ReceiveTimeout=5000' not in command
assert 'if(verifyPeer!=null)verifyPeer(c)' in command and 'Incomplete engine reply' in command
assert 'ScanIssue(db,c,p,"Engine scan incomplete",transport)' in e and 'else usn.Defer(db,path)' in e
assert 'Resolve(db,p,"Engine scan incomplete");lastFileScan' in e
schema=re.findall(r'db\.Exec\("(CREATE TABLE IF NOT EXISTS usn_[^"\n]+)"',u)
queries=re.findall(r'db\.Rows\("(SELECT path FROM usn_pending[^"\n]+)"',u)
defer=re.search(r'db\.Exec\("(INSERT OR REPLACE INTO usn_retry\(scope,path,ready\)[^"\n]+)"',u)[1]
ack=re.search(r'db\.Exec\("(DELETE FROM usn_retry WHERE scope=\? AND path=\?)"',u)[1]
with tempfile.TemporaryDirectory() as d:
 p=Path(d)/'q.db';db=sqlite3.connect(p)
 for sql in schema:db.execute(sql)
 a=r'C:\Users\User\Downloads\blocked.txt';b=r'C:\Users\User\Downloads\next.txt'
 db.executemany('INSERT INTO usn_pending VALUES(?,?)',[('s',a),('s',b)])
 db.execute(defer,('s',a,130));db.commit();db.close();db=sqlite3.connect(p)
 assert db.execute(queries[0],('s',100,4)).fetchall()==[(b,)]
 assert db.execute(queries[0],('s',130,4)).fetchall()==[(a,),(b,)]
 assert db.execute('SELECT COUNT(*) FROM usn_pending').fetchone()==(2,)
 db.execute(ack,('s',a));assert db.execute('SELECT COUNT(*) FROM usn_retry').fetchone()==(0,)
 db.close()
print('PASS: independent watcher heartbeat, shared bounded ClamD transport source, and durable SQLite deferral/recovery. Native Windows transport and watcher not run.')
