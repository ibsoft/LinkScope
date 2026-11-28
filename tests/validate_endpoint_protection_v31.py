"""Exercise actual SQLite statements against a persisted database; scheduling model is not native C#."""
from pathlib import Path
import re, sqlite3, tempfile
r=Path(__file__).resolve().parents[1]
u=(r/'src/UsnJournal.cs').read_text(); e=(r/'src/EndpointProtection.cs').read_text(); j=(r/'src/app.js').read_text()
def sql(prefix):
    return re.search(r'db\.(?:Exec|Rows)\("('+re.escape(prefix)+r'[^"\n]*)"',u)[1]
with tempfile.TemporaryDirectory() as d:
    db=sqlite3.connect(Path(d)/'retry.db')
    for stmt in re.findall(r'db\.Exec\("(CREATE TABLE IF NOT EXISTS usn_[^"\n]+)"',u):db.execute(stmt)
    a=r'C:\Users\Example\locked.db'; b=r'D:\Apps\app.dll'; scope='test'
    for p in (a,b):db.execute(sql('INSERT OR IGNORE INTO usn_pending'),(scope,p))
    ready=sql('SELECT 1 FROM usn_retry WHERE scope=? AND path=? AND ready>?')
    attempts=sql('SELECT attempts FROM usn_retry_attempts WHERE scope=? AND path=?')
    pending=sql('SELECT path FROM usn_pending p WHERE scope=? AND NOT EXISTS')
    def defer(now):
        if db.execute(ready,(scope,a,now)).fetchone():return
        old=db.execute(attempts,(scope,a)).fetchone(); n=min(6,old[0]+1) if old else 1
        db.execute(sql('INSERT OR REPLACE INTO usn_retry_attempts'),(scope,a,n))
        db.execute(sql('INSERT OR REPLACE INTO usn_retry(scope,path,ready)'),(scope,a,now+min(900,30 << min(5,max(0,n-1)))))
        db.commit()
    now=100
    for n,delay in enumerate((30,60,120,240,480,900,900),1):
        defer(now); defer(now+1)
        assert db.execute(attempts,(scope,a)).fetchone()==(min(n,6),)
        assert db.execute(pending,(scope,now,10)).fetchall()==[(b,)]
        assert db.execute(pending,(scope,now+delay,10)).fetchall()==[(a,),(b,)]
        now+=delay
    db.close(); db=sqlite3.connect(Path(d)/'retry.db')
    assert db.execute(attempts,(scope,a)).fetchone()==(6,)
    for table in ('usn_pending','usn_arrivals','usn_retry','usn_retry_attempts'):
        db.execute(sql('DELETE FROM '+table+' WHERE scope=? AND path=?'),(scope,a))
    assert db.execute(attempts,(scope,a)).fetchone() is None
    assert db.execute(pending,(scope,now,10)).fetchall()==[(b,)]
    db.close()
assert 'RetryDelay(int attempts){return Math.Min(900,30 << Math.Min(5,Math.Max(0,attempts-1)));}' in u
assert 'usn.RetryWaiting(db,work.Path)' in e and 'usn.RetryWaiting(db,x.Entry.Path)' in e
locked=e.split('void RecordLocked(',1)[1].split('void RecordFileIdentity(',1)[0]
assert 'RetryLocked(' not in locked and 'usn.Defer(db,path)' in locked
assert 'if(full&&!canary&&usn.RetryWaiting(db,p)){errors++;return false;}' in e
assert 'deferredQueueDepth=usn.DeferredDepth(db)' in e and 'Durable cooldown:' in j
print('PASS: durable backoff SQLite, duplicate deferral, restart persistence, FIFO eligibility, acknowledgement cleanup, and source wiring; Windows runtime not executed.')
