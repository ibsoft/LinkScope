"""Static source wiring only; Windows ACL and installer execution require Windows."""
from pathlib import Path
from pygments import lex
from pygments.lexers.dotnet import CSharpLexer
from pygments.token import String, Comment
r=Path(__file__).resolve().parents[1]
s=(r/'setup/EndpointPermissions.cs').read_text()
a=s.split('automatic.Click+=',1)[1].split('inspect.Click+=',1)[0]
assert 'CheckResponseDirectory(path)' in a and 'new DirectoryPin(path)' in a
assert 'new[]{"channel","audit","access"}' in a
assert a.index('PlanPermission(kind,target,before,sid)')<a.index('MessageBox.Show')<a.index('ApplyPermission(kind,')
assert 'MessageBoxDefaultButton.Button2' in a and 'DialogResult.Yes' in a and 'return;' in a
assert 'kind=="channel"?"":path' in a and 'SavedResponseDirectories()' in s
assert 'Earlier successful changes can be rolled back individually' in a
assert 'effective service access is not yet proven' in a and 'No readiness success inferred' in a
assert '/set /subcategory:' not in s and 'No termination privileges granted' in a
assert 'Automatic repair' in (r/'src/endpoint.html').read_text()
assert (r/'source-build-version.txt').read_text().strip()=='V52'
stack=[]
for token,value in lex(s,CSharpLexer()):
    if token in String or token in Comment: continue
    for ch in value:
        if ch in '([{': stack.append(ch)
        elif ch in ')]}': assert stack and stack.pop()=={')':'(',']':'[','}':'{'}[ch]
assert not stack
print('PASS: selected scope, all-three preflight, confirmation before mutation, existing backed-up apply, explicit failure and verification boundary, C# delimiters (static).')
