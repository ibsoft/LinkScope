"""Portable regression checks for USN journal wiring and SQLite durability.
The native reader, parser fixtures and SCM/pipe permissions require a Windows build.
"""
from pathlib import Path
import sqlite3, re, tempfile
from pygments import lex
from pygments.lexers.dotnet import CSharpLexer
from pygments.token import String, Comment
root=Path(__file__).resolve().parents[1]
s=(root/'src/UsnJournal.cs').read_text(); p=(root/'src/Program.cs').read_text(); ep=(root/'src/EndpointProtection.cs').read_text()
stack=[]
for token,value in lex(s,CSharpLexer()):
    if token in String or token in Comment: continue
    for c in value:
        if c in '([{': stack.append(c)
        elif c in ')]}': assert stack and stack.pop()=={')':'(',']':'[','}':'{'}[c]
assert not stack
assert '0x000900f4' in s and '0x000900bb' in s and 'FSCTL_CREATE' not in s
assert 'PipeAccessRights.ReadWrite|PipeAccessRights.Synchronize' in s and 'Program.ServiceSid()' in s and 'IsReader(pipe.SafePipeHandle)' in s
assert 'WellKnownSidType.NetworkSid' in s and 'AccessControlType.Deny' in s
assert 'Config.Load()' not in s[s.index('static Batch Read('):s.index('internal sealed class UsnJournalMonitor')] and 'Process.Start(' not in s
assert 'var c=Config.Load().Endpoint;if(!LocalScanPath(path,c))' in s
assert 'StopUsn();\n                Console.WriteLine("Setup: deploy service executable")' in p
assert 'RemoveUsn();\n            RunSetupScript' in p and 'case "--usn-self-test"' in p
assert 'NT AUTHORITY\\\\LocalService' in p and 'obj=","LocalSystem"' in p
assert 'usn.Poll(db,c' in ep and 'usn.Ack(db,path)' in ep and 'usnVolumes=usn.Status()' in ep
assert 'if(CheckFile(db,c,path,stop,authorized,false))usn.Ack(db,path)' in ep
assert s.index('if(queued+ b.Paths.Count>Capacity)')<s.index('db.Exec("BEGIN IMMEDIATE")')
assert s.index('gap(v.Root,detail)')<s.index('db.Exec("BEGIN IMMEDIATE")')
assert 'if(journal!=id||cursor<first||cursor>tail)' in s
assert 'if(count==MaxRecords){b.Next=usn;return;}' in s
assert 'endpoint-usn-state' in (root/'src/endpoint.html').read_text()
def sql(prefix):
    return re.search(r'db\.Exec\("('+re.escape(prefix)+r'[^"\n]*)"',s).group(1)
with tempfile.TemporaryDirectory() as d:
    dbpath=Path(d)/'journal.sqlite'; db=sqlite3.connect(dbpath,isolation_level=None)
    for query in re.findall(r'db\.Exec\("(CREATE TABLE IF NOT EXISTS usn_[^"\n]+)"',s): db.execute(query)
    insert=sql('INSERT OR IGNORE INTO usn_pending'); checkpoint=sql('INSERT OR REPLACE INTO usn_checkpoint'); ack=sql('DELETE FROM usn_pending WHERE scope=? AND path=?')
    db.execute('BEGIN IMMEDIATE'); db.execute(insert,('scope',r'C:\a.txt')); db.execute(checkpoint,('scope','C:',123,512));db.execute('ROLLBACK')
    assert db.execute('SELECT * FROM usn_pending').fetchall()==[] and db.execute('SELECT * FROM usn_checkpoint').fetchall()==[]
    db.execute('BEGIN IMMEDIATE');db.execute(insert,('scope',r'C:\a.txt'));db.execute(insert,('scope',r'c:\A.TXT'));db.execute(checkpoint,('scope','C:',123,512));db.execute('COMMIT');db.close()
    db=sqlite3.connect(dbpath,isolation_level=None);assert db.execute('SELECT cursor FROM usn_checkpoint').fetchone()==(512,);assert db.execute('SELECT COUNT(*) FROM usn_pending').fetchone()==(1,)
    db.execute(ack,('scope',r'C:\a.txt'));assert db.execute('SELECT COUNT(*) FROM usn_pending').fetchone()==(0,);assert db.execute('SELECT cursor FROM usn_checkpoint').fetchone()==(512,);db.close()
print('PASS: USN source, privilege separation, service lifecycle, dashboard, parser guard wiring, transactional rollback, durable checkpoint/queue across reopen, deduplication and acknowledgement SQL.')
print('NOT RUN: Windows C# compilation, native IOCTLs, SCM, named pipe permissions, parser executable fixtures and end-to-end throughput.')
