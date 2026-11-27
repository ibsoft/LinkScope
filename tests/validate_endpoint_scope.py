"""Portable scope regression: SQL executed against SQLite, policy predicates modeled in Python.
Native C# predicate and transaction fixture are also in SelfCheck.cs (run on Windows).
"""
from pathlib import Path
import ntpath, re, sqlite3, fnmatch
root=Path(__file__).resolve().parents[1]
s=(root/'src/EndpointProtection.cs').read_text(); native=(root/'src/SelfCheck.cs').read_text()
method=s.split('internal static int ReconcileCoverageScope',1)[1].split('internal void Publish',1)[0]
select=re.search(r'db.Rows\("(SELECT id,path,change FROM findings.*?)"\)',method).group(1)
close=re.search(r'db.Exec\("(INSERT INTO endpoint_outbox.*?)",History.Now\(\),id\)',method).group(1)
update=re.search(r'db.Exec\("(UPDATE findings SET active=0 WHERE id=\?)",id\)',method).group(1)
assert 'scopeReconcilePending=true' in s and 'if(scopeReconcilePending){int retired=ReconcileCoverageScope' in s
assert s.index('if(scopeReconcilePending){int retired=ReconcileCoverageScope')<s.index('var maintenance=ClamUpdateState.Read();',s.index('internal object Tick'))
assert 'CheckEndpointScope(dir)' in native
assert 'if(!c.Paths.Any(root=>Under(path,root))||Excluded(c,path))return;' in s
assert 'if(!c.Paths.Any(x=>Under(p,x)))return true;if(Excluded(c,p))' in s
assert 'Resolve(db,p,"File scan error");Resolve(db,p,"Protected path unavailable");}else' in s
# Mirror C# path rules, with explicit boundary and case-insensitive scope.
def under(p,r):
    p=p.lower().rstrip('\\');r=r.lower().rstrip('\\');return p==r or p.startswith(r+'\\')
paths=[r'C:\unx']; excluded=[r'C:\unx\skip']
def obsolete(path,change):
    if change in ('USN journal unavailable','USN journal coverage gap'):return not any(ntpath.splitdrive(p)[0].lower()+'\\'==path.lower() for p in paths)
    excluded_here=any(under(path,p) for p in excluded) or fnmatch.fnmatchcase(ntpath.basename(path).lower(),'*.tmp')
    if change=='Protected path unavailable':return path.lower() not in [p.lower() for p in paths] or excluded_here
    return not any(under(path,p) for p in paths) or excluded_here
rows=[('old',r'C:\Users\user\Desktop','File scan error'),('live',r'c:\UNX\file.txt','File scan error'),('prefix',r'C:\unx2','File scan limited'),('excluded',r'C:\unx\skip\x','File scan error'),('pattern',r'C:\unx\a.tmp','Engine scan incomplete'),('threat',r'C:\Users\user\Desktop\bad.exe','Malware signature detected'),('canary',r'C:\Users\user\Documents\Reference_Notes.txt','Canary integrity violation'),('volume','C:\\','USN journal coverage gap'),('removedvolume','D:\\','USN journal unavailable'),('oldroot',r'C:\unx\sub','Protected path unavailable')]
db=sqlite3.connect(':memory:',isolation_level=None)
for table in ['findings','incidents','endpoint_outbox']:
    sql=re.search(r'db.Exec\("(CREATE TABLE IF NOT EXISTS '+table+r'\(.*?)"\)',s).group(1);db.execute(sql)
for id,p,c in rows:
    db.execute('INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,1)',(id,p,c,'warning','detail','',1,1));db.execute('INSERT INTO incidents(utc,id,path,change,severity,detail,hash) VALUES(?,?,?,?,?,?,?)',(1,id,p,c,'warning','detail',''))
def reconcile():
    db.execute('BEGIN IMMEDIATE')
    for id,p,c in db.execute(select).fetchall():
        if obsolete(p,c):db.execute(close,(2,id));db.execute(update,(id,))
    db.execute('COMMIT')
reconcile();reconcile()
assert {r[0] for r in db.execute('SELECT id FROM findings WHERE active=0')}=={'old','prefix','excluded','pattern','removedvolume','oldroot'}
assert {r[0] for r in db.execute('SELECT id FROM findings WHERE active=1')}=={'live','threat','canary','volume'}
assert db.execute('SELECT COUNT(*) FROM endpoint_outbox WHERE active=0').fetchone()==(6,)
assert db.execute('SELECT COUNT(*) FROM incidents').fetchone()==(len(rows),)
print('PASS: portable SQLite scope retirement, idempotency, boundary/exclusion model, preserved threats and historical incidents; native self-test added (not run).')
