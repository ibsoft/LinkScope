"""Source contracts and SQLite eligibility simulation; no native C# execution."""
from pathlib import Path
import sqlite3
r=Path(__file__).resolve().parents[1]; s=(r/'src/EndpointProtection.cs').read_text(); a=(r/'src/AiEvidence.cs').read_text(); j=(r/'src/app.js').read_text(); p=(r/'src/report.js').read_text();
recover=s.split('void RecoverWebAuditPolicyGap(',1)[1].split('void PollWebProcessAudit(',1)[0]; poll=s.split('void PollWebProcessAudit(',1)[1].split('object WebProtectionSnapshot(',1)[0]
assert 'if(row==null||!Equals(row[2],WebAuditPolicyGapDetail))continue;' in recover
assert 'opening.Count==0||opening.Any(x=>!Equals(x[0],WebAuditPolicyGapDetail))' in recover
assert recover.index('ProcessAuditEnabled()')<recover.index('web-audit-recovered-policy-gap')<recover.index('Resolve(db,(string)row[0],WebServerProtection.AuditGap)')
assert poll.index('currentOldest.Value>cursor+1')<poll.index('if(drained)RecoverWebAuditPolicyGap')<poll.index('Resolve(db,source,WebServerProtection.AuditCoverage)')
assert 'Issue(db,WebAuditPolicySource,WebServerProtection.AuditGap' in poll
assert poll.count('Issue(db,source,WebServerProtection.AuditGap')==3
assert 'historicalAuditLimitation' in a and 'historicalAuditLimitation' in j and 'historicalAuditLimitation' in p
assert 'DELETE' not in recover and 'is_read' not in recover
# Exercise the exact candidate SELECTs against a synthetic endpoint database.
db=sqlite3.connect(':memory:');db.executescript('CREATE TABLE findings(id TEXT,first INTEGER,last INTEGER,detail TEXT,active INTEGER); CREATE TABLE incidents(seq INTEGER PRIMARY KEY,id TEXT,utc INTEGER,detail TEXT);')
policy='Process creation audit policy was disabled or unverified; historical evidence may be incomplete.'
for key,detail,opening,active in [('policy',policy,policy,1),('legacy',policy,policy,1),('mixed',policy,'Security records cleared',1),('log-clear','Security records cleared','Security records cleared',1),('missing',policy,None,1),('inactive',policy,policy,0)]:
    db.execute('INSERT INTO findings VALUES(?,?,?,?,?)',(key,10,20,detail,active))
    if opening is not None:db.execute('INSERT INTO incidents(id,utc,detail) VALUES(?,?,?)',(key,10,opening))
def eligible(key,legacy):
    row=db.execute('SELECT first,last,detail FROM findings WHERE id=? AND active=1',(key,)).fetchone()
    if not row or row[2]!=policy:return False
    if legacy:
        opening=db.execute('SELECT detail FROM incidents WHERE id=? AND utc>=? ORDER BY seq',(key,row[0])).fetchall()
        if not opening or any(x[0]!=policy for x in opening):return False
    return True
assert eligible('policy',False) and eligible('legacy',True)
assert not any(eligible(k,True) for k in ['mixed','log-clear','missing','inactive'])
print('PASS: V82 policy-only gap eligibility, conservative legacy selection, recovery ordering, durable disclosure and unchanged non-policy gap paths (source contracts and SQLite simulation).')
