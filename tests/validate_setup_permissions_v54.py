"""Static source integration checks. Native Windows setup, ACL and restart require integration tests."""
from pathlib import Path
from pygments import lex
from pygments.lexers.dotnet import CSharpLexer
from pygments.token import String,Comment
r=Path(__file__).resolve().parents[1]
s=(r/'setup/EndpointPermissions.cs').read_text(); setup=(r/'setup/Setup.cs').read_text(); wizard=(r/'setup/wizard.ps1').read_text()
assert 'bool installOperation=verb=="--install"||verb=="--upgrade"||verb=="--upgrade-pwa";' in setup
assert setup.index('int result=RunHidden(exe,verb,stage,log);')<setup.index('if(result==0&&installOperation)return ProvisionEndpointPermissionsAfterInstall(log,logPath);')
assert 'return result;' in setup
p=s.split('static int ProvisionEndpointPermissionsAfterInstall(',1)[1].split('static int EndpointPermissionWizard(',1)[0]
assert p.index('if(!AutomaticResponseEnabled(ep))')<p.index('SecureDirectory(PermissionStore)')<p.index('ConfirmInstallPermissions(summary)')<p.index('ApplyPermission(step.Kind,step.Path,sid,step)')
assert 'return PolicyFlag(ep,"Enabled")&&(mode=="protect"||mode=="contain")' in s
assert 'if(correlate)' in p and 'Values(ep,"ResponsePaths")' in p and 'OrderByDescending(x=>x.Length)' in p
assert 'CheckInstallPermissionStep(kind,path,stamp)' in p and 'CheckInstallPermissionStep(step.Kind,step.Path,stamp)' in p
assert 'PermissionPolicyStamp(current)!=stamp' in s and 'CheckResponseDirectory(path)' in s
assert 'steps.Add(new PermissionChange' in p and 'if(before==after)' in p
assert 'approved.DirectoryIdentity!=pin.Identity' in s and 'approved.Before!=before||approved.After!=after' in s
assert 'catch(Exception ex){blocked++' in p and 'catch(Exception ex){failed++' in p
assert 'if(!ConfirmInstallPermissions(summary))' in p and 'No new ACL rules applied' in p
assert 'if(attempted>0)' in p and 'RestartAfterInstallPermissionChanges(log)' in p
assert 'service.Stop();service.WaitForStatus(ServiceControllerStatus.Stopped' in s and 'service.Start();service.WaitForStatus(ServiceControllerStatus.Running' in s
assert 'No effective-access or containment verdict inferred' in p
assert 'EndpointPermissionReview=21' in s and '$rc -eq 21' in wizard and 'LinkScope installed; endpoint permissions require review' in wizard
assert 'form.CancelButton=skip;form.ActiveControl=skip;' in s
assert 'FileShare.None' in p and 'DirectoryPin(PermissionStore)' in p
assert '/set /subcategory:' not in s and 'TerminateProcess' not in s
assert 'C:\\Apache24' not in p and 'C:\\Users' not in p
assert int((r/'source-build-version.txt').read_text().strip().removeprefix('V'))>=54
for src in (s,setup):
    stack=[]
    for token,value in lex(src,CSharpLexer()):
        if token in String or token in Comment:continue
        for ch in value:
            if ch in '([{':stack.append(ch)
            elif ch in ')]}': assert stack and stack.pop()=={')':'(',']':'[','}':'{'}[ch],ch
    assert not stack
print('PASS: setup integration, explicit mode/scope gate, independent preflight, exact approval snapshots, cancellation/partial result, bounded restart, and delimiter checks (static).')
