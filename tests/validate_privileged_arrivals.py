"""Portable regression checks; no native Windows execution is claimed."""
from pathlib import Path
import sqlite3,re
from pygments import lex
from pygments.lexers.dotnet import CSharpLexer
from pygments.token import String,Comment
r=Path(__file__).resolve().parents[1]
e=(r/'src/EndpointProtection.cs').read_text(); u=(r/'src/UsnJournal.cs').read_text(); w=(r/'src/Web.cs').read_text(); c=(r/'src/ClamUpdateWorker.cs').read_text(); j=(r/'src/app.js').read_text()
for file in ['EndpointProtection.cs','UsnJournal.cs','ClamUpdateWorker.cs','Web.cs','Telemetry.cs']:
    stack=[]
    for t,v in lex((r/'src'/file).read_text(),CSharpLexer()):
        if t in String or t in Comment: continue
        for x in v:
            if x in '([{': stack.append(x)
            elif x in ')]}': assert stack and stack.pop()=={')':'(',']':'[','}':'{'}[x], file
    assert not stack,file
assert 'catch(UnauthorizedAccessException ex) when' not in e # project targets C# 5
assert 'ex is UnauthorizedAccessException&&(stage=="path metadata"' in e
assert 'UsnJournalService.FetchScan(p,full)' in e and 'RecordVerdict(db,c,p,result.Hash,result.Verdict' in e
assert 'RecordFileIdentity(db,c,p,result.Hash' in e and 'VerifyScanPath(handle,path);EndpointResponse.VerifyHandle(handle,path)' in u
assert 'Config.Load().Endpoint;if(!LocalScanPath(path,c))' in u and 'policy.Paths.Any' in u and 'DriveType.Fixed' in u
assert 'ScanPipeName' in u and 'Program.ServiceSid()' in u and 'WellKnownSidType.NetworkSid' in u
assert 'VerifyPrivilegedScanPeer(tcp)' in u and 'OwnsConnection(client,pid)' in c and 'proc.MainModule.FileName' in c
assert 'FileAccess.Read' in u and 'FileAccess.Write' not in u and 'Process.Start(' not in u
assert 'reason&0x2100u' in u and 'b.Arrivals.Contains(p)' in u
assert 'downloads.Concat(arrivals).Concat(recent)' in u
assert 'watcherRootsCoveredByJournal' in e and 'failedWatchers.Where(x=>!usn.Covers(x.Key)&&!PrivilegedWatcherCovers(watcherState(x.Key),now))' in e
assert 'r.Path=="/ui/endpoint-reset"){if(!session.IsAdmin)Deny()' in w
assert 'const currentKind=independent' in j and 'canaryState' in j and '/ui/endpoint-reset' in j
reset=e[e.index('if(Interlocked.Exchange(ref resetRequested'):e.index('if(scopeReconcilePending)ConsolidateCoverage')]
assert 'DELETE FROM' not in reset and "severity='warning'" in reset and 'Malware signature detected' not in reset and 'Canary integrity violation' not in reset
# Actual SQLite statements, migration from existing queue, case-insensitive arrival upgrade and atomic acknowledgement.
db=sqlite3.connect(':memory:',isolation_level=None)
for q in re.findall(r'db\.Exec\("(CREATE TABLE IF NOT EXISTS usn_[^"\n]+)"',u):db.execute(q)
for i in range(3000):db.execute('INSERT INTO usn_pending VALUES(?,?)',('s',rf'C:\old\file{i}.txt'))
insert=re.search(r'db\.Exec\("(INSERT OR IGNORE INTO usn_pending[^"\n]+)"',u)[1];arrival=re.search(r'db\.Exec\("(INSERT OR IGNORE INTO usn_arrivals[^"\n]+)"',u)[1]
path=r'C:\Users\User\Desktop\network-copy.txt';db.execute('BEGIN IMMEDIATE');db.execute(insert,('s',path));db.execute(arrival,('s',path));db.execute('ROLLBACK');assert not db.execute('SELECT * FROM usn_arrivals').fetchall()
db.execute('BEGIN IMMEDIATE');db.execute(insert,('s',path));db.execute(arrival,('s',path.upper()));db.execute(arrival,('s',path));db.execute('COMMIT')
query=re.search(r'db\.Rows\("(SELECT p.path FROM usn_pending p JOIN usn_arrivals[^"\n]+)"',u)[1];assert db.execute(query,('s',100,4)).fetchall()==[(path,)]
db.execute('BEGIN IMMEDIATE');db.execute('DELETE FROM usn_pending WHERE scope=? AND path=?',('s',path));db.execute('DELETE FROM usn_arrivals WHERE scope=? AND path=?',('s',path));db.execute('COMMIT');assert not db.execute(query,('s',100,4)).fetchall() and db.execute('SELECT COUNT(*) FROM usn_pending').fetchone()==(3000,)
print('PASS: restricted privileged scan source wiring, shared verdict path, priority arrival persistence/rollback/dedup/ack, reset scope and independent metric source checks. Native Windows compilation and EICAR testing NOT RUN.')
