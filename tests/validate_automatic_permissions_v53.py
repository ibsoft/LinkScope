"""Static source wiring only; Windows ACL and installer execution require Windows."""
from pathlib import Path
from pygments import lex
from pygments.lexers.dotnet import CSharpLexer
from pygments.token import String, Comment
r=Path(__file__).resolve().parents[1]
s=(r/'setup/EndpointPermissions.cs').read_text()
a=s.split('automatic.Click+=',1)[1].split('inspect.Click+=',1)[0]
assert 'if(kind!="channel")CheckResponseDirectory(path)' in a
assert 'new DirectoryPin(kind=="channel"?null:path)' in a
assert 'new[]{"channel","audit","access"}' in a
assert 'automatic.Enabled=true' in s
assert 'eligible.Add(kind)' in a and 'foreach(string kind in eligible)' in a
assert a.index('PlanPermission(kind,target,before,sid)')<a.index('MessageBox.Show')<a.index('ApplyPermission(kind,')
assert 'MessageBoxDefaultButton.Button2' in a and 'DialogResult.Yes' in a
assert 'if(eligible.Count==0)' in a
assert 'catch(Exception ex){preview.Add(kind+' in a
assert 'catch(Exception ex){failed++;write("Apply "+kind+' in a
assert 'Earlier successful changes can be rolled back individually' in a
assert 'Effective service access is not yet proven' in a and 'No readiness success inferred' in a
assert '/set /subcategory:' not in s and 'No termination privileges granted' in a
assert 'Directory overlaps an excluded path:' in s
assert 'Permission wizard opened for service SID' in s
assert 'Automatic repair' in (r/'src/endpoint.html').read_text()
version=(r/'source-build-version.txt').read_text().strip()
assert version.startswith('V') and version[1:].isdigit() and int(version[1:])>=53
stack=[]
for token,value in lex(s,CSharpLexer()):
    if token in String or token in Comment: continue
    for ch in value:
        if ch in '([{': stack.append(ch)
        elif ch in ')]}': assert stack and stack.pop()=={')':'(',']':'[','}':'{'}[ch]
assert not stack
print('PASS: independent preflight/apply, explicit eligible-step confirmation, backed-up scoped writes, failure reporting and C# delimiters (static).')
