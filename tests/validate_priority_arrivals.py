"""Portable source assertions, actual SQLite ordering and scheduler model (not native Windows I/O)."""
from pathlib import Path
import re, sqlite3
r=Path(__file__).resolve().parents[1]
s=(r/'src/EndpointProtection.cs').read_text(); u=(r/'src/UsnJournal.cs').read_text()
assert 'w.Created+=(s,e)=>Enqueue(c,e.FullPath,true)' in s
assert 'Enqueue(c,e.OldFullPath);Enqueue(c,e.FullPath,true)' in s
assert 'w.Changed+=(s,e)=>Enqueue(c,e.FullPath)' in s
assert 'priority=priority||DownloadPriority(path)' in s
assert 'now-item.Last).TotalMilliseconds<750' in s and 'now-item.First).TotalSeconds<5' in s
assert 'MaxLockedRetries=3' in s and 'now.AddSeconds(2<<retries)' in s
assert '(LockedFile(ex)||ex is UnauthorizedAccessException||stage=="ClamAV INSTREAM")&&RetryLocked(c,p,retries)' in s and 'if(retry)return false' in s
assert 'if(HasWatcher(path))continue;' in s
assert 'FileShare.Read' in s and '"INSTREAM",file,stop' in s
assert 'preferRecent=!preferRecent' in u
# Existing database layout and actual queries: no migration required.
db=sqlite3.connect(':memory:')
for table in ['usn_pending','usn_retry']:
    db.execute(re.search(r'db.Exec\("(CREATE TABLE IF NOT EXISTS '+table+r'[^"\n]+)"',u).group(1))
for i in range(3000): db.execute('INSERT INTO usn_pending VALUES(?,?)',('active',rf'C:\old\file{i}.txt'))
for p in [r'C:\Users\User\Downloads\eicar.com.txt',r'C:\unx\newly-copied.bin',r'D:\copy\new.exe']: db.execute('INSERT INTO usn_pending VALUES(?,?)',('active',p))
db.execute('INSERT INTO usn_pending VALUES(?,?)',('other',r'C:\Downloads\excluded-scope.txt'))
queries=re.findall(r'db.Rows\("(SELECT path FROM usn_pending[^"\n]+)"',u)
fifo=[x[0] for x in db.execute(queries[0],('active',100,4))]
downloads=[x[0] for x in db.execute(queries[1],('active',100,'\\downloads\\'))]
recent=[x[0] for x in db.execute(queries[2],('active',100,2))]
assert fifo[0]==r'C:\old\file0.txt' and downloads==[r'C:\Users\User\Downloads\eicar.com.txt']
assert recent==[r'D:\copy\new.exe',r'C:\unx\newly-copied.bin']
fast=list(dict.fromkeys(downloads+recent+fifo))[:4]
slow=list(dict.fromkeys(fifo[:1]+downloads+recent+fifo))[:4]
assert fast[0]==downloads[0] and slow[0]==fifo[0] and set(recent)<=set(fast) and set(recent)<=set(slow)
# Reference model of debounce: quiet 750 ms, bounded five-second wait, retry backoff.
def ready(first,last,not_before,now): return now>=not_before and (now-last>=.75 or now-first>=5)
assert not ready(0,.5,0,1.0) and ready(0,.5,0,1.25)
assert ready(0,4.9,0,5) and not ready(0,0,2,1.99) and ready(0,0,2,2)
assert [2<<i for i in range(3)]==[2,4,8]
print('PASS: watcher creation/rename priority wiring, debounce/retry guards, actual SQLite ordering with 3,000 old items, recent copied files and Downloads, bounded retry reference model.')
print('NOT RUN: Windows copy/download events, EICAR detection, ACL access, native C# build or actual latency.')
