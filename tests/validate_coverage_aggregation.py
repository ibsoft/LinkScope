"""Exercise actual SQLite statements from scanner and central alert migration.
Policy selection is modeled here; native service execution still requires Windows.
"""
from pathlib import Path
import sqlite3,re
root=Path(__file__).resolve().parents[1]
s=(root/'src/EndpointProtection.cs').read_text(); a=(root/'src/Alerts.cs').read_text()
record=s.split('internal static void RecordCoverage',1)[1].split('void ScanIssue',1)[0]
migrate=s.split('internal static int ConsolidateCoverage',1)[1].split('void CoverageSummary',1)[0]
close=a.split('if(consolidated){',1)[1].split('if(old!=null)',1)[0]
def sql(source,prefix):
    return re.search(r'db.Exec\("('+re.escape(prefix)+r'[^"\n]*)"',source).group(1)
db=sqlite3.connect(':memory:',isolation_level=None)
for name in ['findings','incidents','endpoint_outbox']:
    db.execute(sql(s,'CREATE TABLE IF NOT EXISTS '+name))
for name in ['alert_events']:
    db.execute(sql(a,'CREATE TABLE IF NOT EXISTS '+name))
db.execute('CREATE TABLE alert_mail_queue(alert_id TEXT)')
mark='Superseded by consolidated scan coverage warning'
for id,path,change,sev in [('old',r'C:\old.txt','File scan error','warning'),('outside',r'D:\file.txt','File scan limited','warning'),('canary',r'C:\canary.txt','Canary integrity violation','critical'),('canary-access',r'C:\canary.txt','File scan error','warning'),('malware',r'C:\bad.exe','Malware signature detected','critical')]:
    db.execute('INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,1)',(id,path,change,sev,'detail','',1,1))
    db.execute('INSERT INTO incidents(utc,id,path,change,severity,detail,hash) VALUES(?,?,?,?,?,?,?)',(1,id,path,change,sev,'detail',''))
    db.execute('INSERT INTO endpoint_outbox(utc,id,path,change,severity,detail,hash,active) VALUES(?,?,?,?,?,?,?,1)',(1,id,path,change,sev,'detail',''))
    db.execute('INSERT INTO alert_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(len(db.execute('SELECT seq FROM alert_events').fetchall())+1,id,'endpoint_protection/'+id,'endpoint_protection',sev,change,'detail','',1,0,0,None))
    db.execute('INSERT INTO alert_mail_queue VALUES(?)',(id,))
# Test same migration statements with representative selected rows.
for id,path,change,live in [('old',r'C:\old.txt','File scan error',1),('outside',r'D:\file.txt','File scan limited',0)]:
    db.execute('BEGIN IMMEDIATE')
    db.execute(sql(migrate,'DELETE FROM endpoint_outbox WHERE id='),(id,))
    db.execute(sql(migrate,'INSERT INTO endpoint_outbox('),(2,id,path,change,'warning',mark,''))
    db.execute(sql(migrate,"UPDATE findings SET severity='coverage',active="),(live,id))
    db.execute('COMMIT')
    key='endpoint_protection/'+id
    db.execute(sql(close,'UPDATE alert_events SET is_read=1'),(key,))
    db.execute(sql(close,'DELETE FROM alert_mail_queue'),(key,))
    db.execute('UPDATE alert_events SET resolved=1,ended=2 WHERE alert_key=?',(key,))
assert db.execute('SELECT COUNT(*) FROM incidents').fetchone()==(5,)
assert db.execute("SELECT id FROM alert_events WHERE is_read=0 ORDER BY id").fetchall()==[('canary',),('canary-access',),('malware',)]
assert db.execute('SELECT alert_id FROM alert_mail_queue ORDER BY alert_id').fetchall()==[('canary',),('canary-access',),('malware',)]
assert db.execute("SELECT COUNT(*) FROM endpoint_outbox WHERE id IN ('old','outside') AND active=1").fetchone()==(0,)
# Many distinct failures and repeated observation produce no per-file transitions.
for i in range(1000):
    path='C:\\profile\\file'+str(i); args=(str(i),path,'File scan error','coverage','denied','',3,3)
    for _ in range(2):
        db.execute(sql(record,'INSERT OR IGNORE INTO findings VALUES'),args)
        db.execute(sql(record,"UPDATE findings SET severity='coverage'"),('denied',3,str(i)))
assert db.execute("SELECT COUNT(*) FROM findings WHERE active=1 AND severity='coverage'").fetchone()==(1001,)
assert db.execute('SELECT COUNT(*) FROM endpoint_outbox').fetchone()==(5,)
assert 'return change=="Engine scan incomplete"||' in s and '!c.Paths.Contains(path,StringComparer.OrdinalIgnoreCase)&&!c.CanaryPaths.Contains(path,StringComparer.OrdinalIgnoreCase)' in s
assert 'if(wasCoverage)continue;' in migrate
assert 'CoverageSummary(db,coverageCount)' in s and 'severity<>\'coverage\' ORDER BY' in s
assert 'coverageDetails' in (root/'src/app.js').read_text()
print('PASS: 1,000 unique paths, repeated failures, migration and acknowledgement SQL, preserved malware/canary alerts; source checks for aggregation and UI.')
