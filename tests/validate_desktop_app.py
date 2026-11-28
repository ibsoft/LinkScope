"""Portable compile-scope and desktop-app source checks, not Windows runtime tests."""
from pathlib import Path
import re, xml.etree.ElementTree as ET
from pygments import lex
from pygments.lexers.dotnet import CSharpLexer
from pygments.token import Comment, String, Whitespace
root=Path(__file__).resolve().parents[1]
ns={'m':'http://schemas.microsoft.com/developer/msbuild/2003'}
proj=ET.parse(root/'LinkScope.csproj')
setup=(root/'setup/Setup.cs').read_text()
program=(root/'src/Program.cs').read_text()
app=(root/'src/DesktopApp.cs').read_text()
wizard=(root/'setup/wizard.ps1').read_text()
engine=(root/'src/EndpointProtection.cs').read_text()
# Inspect lexical namespace/type depth, not merely the presence of a type name.
# The scanner is deliberately a source check, not a substitute for C# compilation.
def declarations(source):
    depth=0; previous=None; seen={}
    for tok, value in lex(source,CSharpLexer()):
        if tok in Comment or tok in String or tok in Whitespace or not value.strip():continue
        if previous=='class': seen[value]=depth
        previous=value
        if value=='{':depth+=1
        elif value=='}':depth-=1;assert depth>=0
    assert depth==0
    return seen
scope=declarations(engine)
response_scope=declarations((root/'src/EndpointResponse.cs').read_text())
assert scope['EndpointProtection']==response_scope['EndpointResponse']==response_scope['EndpointWriter']==1,(scope,response_scope)
assert 'EndpointResponse' not in scope and 'EndpointWriter' not in scope
assert declarations(app)['DesktopApp']==1
for p in list((root/'src').glob('*.cs'))+list((root/'setup').glob('*.cs')):
    assert not re.search(r'\bnew\s+TimeoutException\s*\(',p.read_text()),p
assert 'new System.TimeoutException(' in (root/'setup/ClamSetup.cs').read_text()
assert proj.find('.//m:Compile[@Include="src\\DesktopApp.cs"]',ns) is not None and (root/'src/DesktopApp.cs').is_file()
assert 'src\\*.cs' in (root/'Build.cmd').read_text()
for term in ['case "--install": case "-install": Install(false); DesktopApp.Provision(false);', 'case "--upgrade": Install(true); DesktopApp.Provision(false);', 'case "--upgrade-pwa": Install(true); DesktopApp.Provision(true);', 'case "--uninstall": case "-uninstall": Uninstall(); DesktopApp.Remove();','case "--desktop-app": RequireAdmin();','case "--register-pwa": RequireAdmin();']:
    assert term in program,term
for verb in ['--upgrade-pwa','--desktop-app','--register-pwa']:assert 'verb=="'+verb+'"' in setup
for term in ['CommonDesktopDirectory','CommonPrograms','Program.Resource("linkscope.ico")','Config.Load().Origin()','uri.IsLoopback','BuiltinUsersSid','--app=','msedge.exe','chrome.exe','LinkScope.url','OwnedShortcut(shell,dest)','File.Replace(tmp,dest,null)','WebAppInstallForceList','RegistryView.Registry32','RegistryView.Registry64','current user has an existing Edge web-app policy','existing organization or third-party Edge policy preserved','create_desktop_shortcut=false','default_launch_container="window"','Config.Json().Deserialize<string>','Config.Save(PolicyRecord,value)','String.Equals(key.GetValue(PolicyValue) as string,owned,StringComparison.Ordinal)']:
    assert term in app,term
assert '--ignore-certificate-errors' not in app
assert '$pwa.Checked=$true' in wizard and "$verb -eq '--upgrade' -and $pwa.Checked" in wizard
assert "--upgrade-pwa" in wizard
assert 'local policy; optional' in wizard
assert 'window.isSecureContext' in (root/'src/pwa.js').read_text()
assert 'caches.' not in (root/'src/sw.js').read_text()
print('PASS: response type shares correct namespace in a separately compiled source; all timeout constructions qualified; installer shortcut and optional managed PWA wiring; policy ownership guards; non-caching PWA. Windows compilation, COM shortcuts and policy application not executed.')
