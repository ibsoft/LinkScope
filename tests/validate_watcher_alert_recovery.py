"""Portable wiring plus actual alert-update SQL; native C# self-test remains required."""
from pathlib import Path
import re, sqlite3
r=Path(__file__).resolve().parents[1]
a=(r/'src/Alerts.cs').read_text(); e=(r/'src/EndpointProtection.cs').read_text(); c=(r/'src/SelfCheck.cs').read_text()
assert 'foreach(var root in failedWatchers.Keys)' in e
assert 'privilegedWatcherStates.Where(x=>x.Value.Next<=now)' in e
assert 'failedWatchers.Where(x=>!usn.Covers(x.Key)&&!PrivilegedWatcherCovers(watcherState(x.Key),now))' in e
assert 'alerts.RefreshEndpointWatcherFinding(watcherId,watcher==null?null:' in e
assert 'SELECT detail FROM findings WHERE id=? AND active=1' in e
assert 'old.Title!="Watcher coverage incomplete"||old.Severity!="warning"' in a
assert 'Signal(cat,id,old.Severity,old.Title,message,old.Revision)' in a
assert 'list.RemoveAll(x=>x.Key==cat+"/coverage")' in a
assert 'Rows(group).Where(e=>!IsOwnEndpointEvent(channel,S(e,"provider"),S(e,"eventId")))' in a
assert 'eventId=="4201"' in a and 'string.Equals(channel,"Application"' in a
assert 'external application event retained' in c and 'watcher alert refreshed without reopening' in c
schema=re.search(r'db\.Exec\("(CREATE TABLE IF NOT EXISTS alert_events\(.*?)"\)',a).group(1)
update=re.search(r'db\.Exec\("(UPDATE alert_events SET title=\?,message=\? WHERE id=\?)"',a).group(1)
db=sqlite3.connect(':memory:');db.execute(schema)
db.execute('INSERT INTO alert_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(1,'watch','endpoint_protection/watch','endpoint_protection','warning','Watcher coverage incomplete','old','rev',100,1,0,None))
db.execute('INSERT INTO alert_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(2,'malware','endpoint_protection/malware','endpoint_protection','critical','Malware signature detected','evidence','rev',101,0,0,None))
db.execute(update,('Watcher coverage incomplete','helper: actual reason','watch'))
assert db.execute('SELECT seq,id,message,since,is_read,resolved FROM alert_events ORDER BY seq').fetchall()==[(1,'watch','helper: actual reason',100,1,0),(2,'malware','evidence',101,0,0)]
print('PASS: watcher redundancy, genuine coverage predicate, exact alert refresh SQL and own-event filter wiring; Windows runtime not executed.')
