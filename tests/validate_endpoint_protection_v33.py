"""Exercise the exact SQL statements in V33; source contracts, not native runtime tests."""
from pathlib import Path
import re, sqlite3, tempfile
root=Path(__file__).resolve().parents[1]
e=(root/'src/EndpointProtection.cs').read_text(); a=(root/'src/Alerts.cs').read_text(); u=(root/'src/UsnJournal.cs').read_text(); delivery=(root/'src/AlertDelivery.cs').read_text(); web=(root/'src/Web.cs').read_text(); js=(root/'src/app.js').read_text(); tele=(root/'src/Telemetry.cs').read_text(); html=(root/'src/settings.html').read_text()
local=e.split('internal void ProcessHistoryReset(',1)[1].split('internal EndpointProtection()',1)[0]
central=a.split('internal long ResetEndpointHistory()',1)[1].split('internal void Trim(',1)[0]
statements=lambda x: re.findall(r'db\.Exec\("([^"\n]+)"',x)
def schema(db,s):
    for q in statements(s):
        if q.startswith('CREATE TABLE IF NOT EXISTS '):db.execute(q)
with tempfile.TemporaryDirectory() as d:
    ep=sqlite3.connect(Path(d)/'endpoint.sqlite'); alerts=sqlite3.connect(Path(d)/'alerts.sqlite')
    schema(ep,e);schema(ep,u);schema(alerts,a);schema(alerts,delivery)
    for id,change,severity,active in [('old','Malware signature detected','critical',0),('live','Malware signature detected','critical',1),('canary','Canary integrity violation','critical',1),('gap','USN journal coverage gap','warning',1),('coverage','File scan error','coverage',1),('incomplete','Scan incomplete','warning',1)]:
        ep.execute('INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,?)',(id,id,change,severity,'detail','hash',1,2,active))
    ep.execute("INSERT INTO scan_activity(utc,path,source,result,durationMs,detail) VALUES(1,'old','real-time','Clean',1,'old')")
    ep.execute("INSERT INTO incidents(utc,id,path,change,severity,detail,hash) VALUES(1,'old','old','old','warning','detail','hash')")
    ep.execute("INSERT INTO files VALUES('scope','file','hash',0,1),('scope','live','hash',0,1)")
    ep.execute("INSERT INTO canaries VALUES('canary','original')")
    ep.execute("INSERT INTO quarantine_deletions VALUES('vault','file','hash','admin',1,2)")
    ep.execute("INSERT INTO usn_pending VALUES('scope','queued')")
    ep.execute("INSERT INTO usn_checkpoint VALUES('scope','C:',1,123)")
    ep.execute("INSERT INTO endpoint_probe(id,path,created,finished) VALUES('done','file',1,2),('pending','file',1,NULL)")
    ep.execute("INSERT INTO endpoint_outbox(utc,id,path,change,severity,detail,hash,active) VALUES(1,'old','old','old','warning','detail','hash',1)")
    ep.commit()
    # Execute exact worker statements through the local transaction and reopen as after a restart.
    for q in statements(local):
        if q=='ROLLBACK' or q.startswith('DELETE FROM endpoint_metadata'):continue
        ep.execute(q, (100,) if q.startswith('INSERT INTO endpoint_outbox') else ('reset-id',) if q.startswith('INSERT OR REPLACE INTO endpoint_metadata') else ())
    ep.close();ep=sqlite3.connect(Path(d)/'endpoint.sqlite')
    assert ep.execute("SELECT value FROM endpoint_metadata WHERE name='history-reset-pending'").fetchone()==('reset-id',)
    assert set(ep.execute('SELECT id FROM findings'))=={('live',),('canary',),('gap',)}
    assert set(ep.execute('SELECT id FROM endpoint_outbox WHERE active=1'))=={('live',),('canary',),('gap',)}
    assert all(ep.execute('SELECT COUNT(*) FROM '+t).fetchone()==(0,) for t in ('scan_activity','incidents'))
    assert ep.execute('SELECT path FROM files').fetchall()==[('live',)]
    assert ep.execute('SELECT hash FROM canaries').fetchone()==('original',)
    assert ep.execute('SELECT id FROM quarantine_deletions').fetchone()==('vault',)
    assert ep.execute('SELECT cursor FROM usn_checkpoint').fetchone()==(123,)
    assert ep.execute('SELECT path FROM usn_pending').fetchone()==('queued',)
    assert ep.execute('SELECT id FROM endpoint_probe').fetchone()==('pending',)
    alerts.execute('INSERT INTO alert_sequence VALUES(1,3)')
    for n,cat in [(1,'endpoint_protection'),(2,'cpu'),(3,'endpoint_protection')]:
        alerts.execute('INSERT INTO alert_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(n,str(n),cat+'/'+str(n),cat,'warning','title','message','rev',1,0,0,None))
        alerts.execute('INSERT INTO alert_search_index VALUES(?,?)',(n,'word'))
        alerts.execute('INSERT INTO alert_mail_queue(job,alert_id,kind,subject,body) VALUES(?,?,?,?,?)',(str(n),str(n),'open','subject','body'))
    alerts.commit()
    # Central purge is idempotent and leaves unrelated records and monotonic cursor intact.
    for _ in range(2):
        for q in statements(central):
            if q!='ROLLBACK':alerts.execute(q)
    assert alerts.execute('SELECT seq,category FROM alert_events').fetchall()==[(2,'cpu')]
    assert alerts.execute('SELECT seq FROM alert_search_index').fetchall()==[(2,)]
    assert alerts.execute('SELECT alert_id FROM alert_mail_queue').fetchall()==[('2',)]
    assert alerts.execute('SELECT last_seq FROM alert_sequence').fetchone()==(3,)
    ep.execute(next(q for q in statements(local) if q.startswith('DELETE FROM endpoint_metadata')));ep.commit()
    assert ep.execute("SELECT value FROM endpoint_metadata WHERE name='history-reset-pending'").fetchone() is None
    ep.close();alerts.close()
route=web.split('else if(r.Path=="/ui/endpoint-history-reset")',1)[1].split('else if',1)[0]
assert 'if(!session.IsAdmin)Deny()' in route and 'if(!post)return' in route and 'RESET ENDPOINT HISTORY' in route
assert 'X-CSRF-Token' in web and 'EndpointHistoryReset' in html and 'confirmAction(' in js and 'Delete endpoint history\',true)' in js
assert 'endpoint.ProcessHistoryReset(alerts);resetReady=true;result=endpoint.Tick' in tele and 'if(resetReady){endpoint.Publish' in tele
assert local.index('INSERT OR REPLACE INTO endpoint_metadata')<local.index('alerts.ResetEndpointHistory()')<local.index('DELETE FROM endpoint_metadata')
assert 'current.Remove(key)' in central and 'alert_sequence' not in central
print('PASS: actual SQLite endpoint reset, retained active evidence/queues/canaries, restart marker, idempotent category-scoped central purge, monotonic alert sequence and admin/confirmation wiring; Windows runtime not executed.')
