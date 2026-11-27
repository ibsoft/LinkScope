"""Portable regression checks. The real Windows firewall parser and NTFS deletion
APIs are exercised only by Windows self-tests / the acceptance checklist."""
from pathlib import Path
import ipaddress, re, sqlite3, subprocess
ROOT=Path(__file__).resolve().parents[1];SRC=ROOT/'src'
scanner=(SRC/'EndpointProtection.cs').read_text(); response=(SRC/'EndpointResponse.cs').read_text();web=(SRC/'Web.cs').read_text();app=(SRC/'app.js').read_text()
# Check actual SQLite journal and conditional active-finding resolution SQL.
db=sqlite3.connect(':memory:')
for q in re.findall(r'db\.Exec\("(CREATE (?:TABLE|INDEX) IF NOT EXISTS [^"\n]+)"',scanner):db.execute(q)
for q in re.findall(r'db\.(?:Rows|Exec)\("([^"\n]*(?:quarantine_deletions|WHERE id=\? AND hash=\? AND active=1)[^"\n]*)"',scanner):
    if not q.startswith('CREATE'):db.execute('EXPLAIN '+q,[None]*q.count('?'))
resolve_insert=re.search(r'db\.Exec\("(INSERT INTO endpoint_outbox[^"\n]+WHERE id=\? AND hash=\? AND active=1)"',scanner)[1]
resolve_update=re.search(r'db\.Exec\("(UPDATE findings SET active=0 WHERE id=\? AND hash=\? AND active=1)"',scanner)[1]
for id,path,hash in [('one','a.exe','a'*64),('two','b.exe','a'*64),('three','a.exe','b'*64)]:db.execute('INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,1)',(id,path,'Malware signature detected','critical','test',hash,1,1))
for q,args in [(resolve_insert,(2,'one','a'*64)),(resolve_update,('one','a'*64))]:db.execute(q,args)
assert db.execute('SELECT id,active FROM findings ORDER BY id').fetchall()==[('one',0),('three',1),('two',1)]
assert db.execute('SELECT id,active FROM endpoint_outbox').fetchall()==[('one',0)]
# Journal / payload order and admin, CSRF and strict evidence identifier gates.
deletion=scanner[scanner.index('internal object DeleteQuarantine('):scanner.index('  string Correlate(')]
assert deletion.index('INSERT OR IGNORE INTO quarantine_deletions')<deletion.index('EndpointResponse.DeleteSealedPayload')<deletion.index('UPDATE quarantine_deletions SET completed')
assert 'id.Length==32' in scanner and 'ids.Any(id=>!EvidenceId(id))' in deletion
assert 'Only completed quarantines may be deleted' in deletion and 'Cannot confirm removal of sealed payload' in deletion
assert 'VerifyHandle(handle,path)' in response[response.index('internal static void DeleteSealedPayload'):]
assert 'if(!session.IsAdmin)Deny();var input=Decode<QuarantineDeleteInput>' in web and 'X-CSRF-Token' in web
assert 'activeMalware' in app and 'activeHeuristic' in app and "result.infectedChecks?'fail'" not in app
assert 'quarantineDeletions' in (SRC/'report.js').read_text() and 'quarantineDeletedCount' in (SRC/'AiEvidence.cs').read_text()
# CIDR reference cases: model only, actual C# rules are covered by SelfCheck.Run.
fw=(SRC/'ClientFirewall.cs').read_text();checks=(SRC/'SelfCheck.cs').read_text()
assert 'prefix<1' in fw and 'IPAddress.IsLoopback(address)' in fw and 'Matches(address,Parse(entry))' in fw
assert 'ClientFirewall.Allows(ip,next.AllowedClientIPs)' in web and 'ClientFirewall.Allows(ip,settings.AllowedClientIPs)' in web
assert 'CIDR canonical network and mapped IPv4' in checks
for net,inside,outside in [('192.168.1.0/24','192.168.1.254','192.168.2.1'),('10.20.30.0/25','10.20.30.127','10.20.30.128'),('2001:db8:1::/64','2001:db8:1::ffff','2001:db8:2::1')]:
    n=ipaddress.ip_network(net);assert ipaddress.ip_address(inside) in n and ipaddress.ip_address(outside) not in n
assert '192.168.1.0/24' in (SRC/'settings.html').read_text()
print('PASS: actual quarantine SQL syntax, matched-hash recovery, journal ordering, authorization/source checks and CIDR reference cases; Windows APIs and C# CIDR execution not tested.')
