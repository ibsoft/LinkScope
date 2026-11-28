"""Portable source contracts only; native Windows verification is separate."""
from pathlib import Path
from pygments import lex
from pygments.lexers.dotnet import CSharpLexer
from pygments.token import String, Comment
r=Path(__file__).resolve().parents[1]
s=(r/'setup/EndpointPermissions.cs').read_text(); setup=(r/'setup/Setup.cs').read_text(); wizard=(r/'setup/wizard.ps1').read_text(); w=(r/'src/WebServerProtection.cs').read_text(); u=(r/'src/UsnJournal.cs').read_text(); ep=(r/'src/EndpointProtection.cs').read_text()
p=s.split('static int ProvisionWebAuditAfterInstall(',1)[1].split('static Dictionary<string,object> ReadInstallEndpointPolicy',1)[0]
assert '0cce922b-69ae-11d9-bed3-505054503030' in s and '0cce922b-69ae-11d9-bed3-505054503030' in w
assert 'if((before&1)==0)' in p and ' /success:enable' in p and '/failure:' not in p
assert p.index('ReadProcessCreationAuditFlags()')<p.index('RunHidden(')<p.index('uint after=ReadProcessCreationAuditFlags()')
assert '(after&1)==0||(before&2)!=(after&2)' in p
assert 'ApplyPermission("channel","",sid)' in p and 'EndpointServiceSid()' in p and 'FileShare.None' in p
assert 'return failures==0?0:EndpointPermissionReview;' in p and 'failures++' in p
assert 'int webAudit=ProvisionWebAuditAfterInstall(log);' in setup and 'return webAudit!=0?webAudit:endpoint;' in setup
assert 'bool installOperation=verb=="--install"||verb=="--upgrade"||verb=="--upgrade-pwa";' in setup
assert 'catch(System.ComponentModel.Win32Exception){if(!Program.ServiceMode)throw;return UsnJournalService.FetchProcessAuditPolicy();}' in w
assert "request[0]==(byte)'!'&&request.Skip(1).All(x=>x==0)" in u
assert 'WebServerProtection.QueryProcessAuditPolicy()?1:0' in u and 'new byte[]{76,83,80,65,state}' in u
client=u.split('internal static bool FetchProcessAuditPolicy()',1)[1].split('internal static Batch Fetch(',1)[0]
assert 'IsReader(pipe.SafePipeHandle)' in client and 'TokenImpersonationLevel.Identification' in client and 'reply[4]>1' in client and 'return reply[4]==1;' in client
assert 'catch(Exception){Issue(db,WebAuditPolicySource,WebServerProtection.AuditGap' in ep
assert 'Resolve(db,source,WebServerProtection.AuditCoverage)' in ep and 'Resolve(db,source,WebServerProtection.AuditGap)' not in ep  # V82 only retires explicitly verified policy-gap candidates
assert 'machine-wide Process Creation success auditing' in wizard and 'Historical gaps remain recorded' in wizard
for src in (s,setup,w,u,ep):
    stack=[]
    for tok,value in lex(src,CSharpLexer()):
        if tok in String or tok in Comment: continue
        for ch in value:
            if ch in '([{':stack.append(ch)
            elif ch in ')]}': assert stack and stack.pop()=={')':'(',']':'[','}':'{'}[ch],ch
    assert not stack
print('PASS: automatic prerequisite wiring, localized GUID, readback, failure-policy preservation, service SID ACL, bounded fixed helper query, historical gaps retained (static).')
