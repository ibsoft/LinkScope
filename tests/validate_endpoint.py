"""Portable source/SQL smoke checks. Does NOT execute the C# scanner or Windows APIs."""
from pathlib import Path
import json, re, sqlite3, subprocess, xml.etree.ElementTree as ET
from html.parser import HTMLParser
ROOT = Path(__file__).resolve().parent.parent
src = ROOT / 'src'
for file in src.glob('*.js'):
    subprocess.run(['node','--check',str(file)],check=True,capture_output=True)
print('PASS: all JavaScript files parse with Node.js')
config = json.loads((src/'default.json').read_text())['Endpoint']
assert config['Enabled'] is False and config['Mode']=='monitor' and config['ResponsePaths']==[]
assert config['TrustedEnginePath']==config['TrustedEngineSha256']==''
print('PASS: default endpoint policy is disabled, monitor-only, no response targets or engine pin')
ns={'m':'http://schemas.microsoft.com/developer/msbuild/2003'}
project=ET.parse(ROOT/'LinkScope.csproj')
for res in project.findall('.//m:EmbeddedResource',ns):
    name=res.attrib['Include']; assert name==r'obj\LinkScopeVersion.txt' or (ROOT/name.replace('\\','/')).is_file(), name
    assert '/resource:'+name+','+res.find('m:LogicalName',ns).text in (ROOT/'Build.cmd').read_text(),name
for ref in project.findall('.//m:Reference',ns): assert '/reference:'+ref.attrib['Include']+'.dll' in (ROOT/'Build.cmd').read_text()
print('PASS: project XML, resource existence and Build.cmd parity')
# Verify the explicit IDE source entries. The real build also refreshes the list from disk.
patterns = [e.attrib['Include'].replace('\\','/') for e in project.findall('./m:ItemGroup/m:Compile',ns)]
compiled = [f.relative_to(ROOT).as_posix() for pattern in patterns for f in ROOT.glob(pattern)]
assert len(compiled) == len(set(compiled)), 'Duplicate C# compile items'
assert set(compiled) == {f.relative_to(ROOT).as_posix() for f in src.glob('*.cs')}, 'C# source/project mismatch'
assert 'src/EndpointResponse.cs' in compiled
response = (src/'EndpointResponse.cs').read_text()
assert not re.search(r'\bclass\s+EndpointResponse\b', (src/'EndpointProtection.cs').read_text())
assert all('// Endpoint source layout: split-response-v2' in (src/name).read_text() for name in ['EndpointResponse.cs','EndpointProtection.cs'])
assert 'Assert-EndpointSources.ps1' in (ROOT/'Build.cmd').read_text()
assert 'Assert-EndpointSources.ps1' in (ROOT/'LinkScope.csproj').read_text()
assert len(re.findall(r'\binternal\s+static\s+class\s+EndpointResponse\b', response)) == 1
assert re.search(r'namespace\s+LinkScope\s*\{', response)
assert re.search(r'internal\s+static\s+class\s+EndpointResponse\b', response)
for name in set(re.findall(r'EndpointResponse\.(\w+)\(', (src/'EndpointProtection.cs').read_text())):
    assert re.search(r'\bstatic\s+\w+(?:\[\])?\s+'+name+r'\s*\(', response), name
assert 'if not exist "src\\EndpointProtection.cs"' in (ROOT/'Build.cmd').read_text()
assert any(e.attrib.get('Name')=='VerifyEndpointProtectionSource' for e in project.findall('.//m:Target',ns))
print('PASS: all C# sources discovered exactly once; EndpointResponse declaration, references and missing-file diagnostics checked')

class IDs(HTMLParser):
    def __init__(self): super().__init__(); self.ids=[]
    def handle_starttag(self,tag,attrs): self.ids.extend(v for k,v in attrs if k=='id')
parser=IDs(); parser.feed((src/'settings.html').read_text()); assert len(parser.ids)==len(set(parser.ids))
for k in ['Enabled','WriteEvents','RealTime','ProcessCorrelation','Interval','Threshold','Port','MaxFileMiB','BehaviorWindowSeconds','Mode','Paths','ExcludedPaths','ExcludedPatterns','CanaryPaths','ResponsePaths','ContainmentExecutables','TrustedEnginePath','TrustedEngineSha256']:
    assert 'Endpoint'+k in parser.ids,k
print('PASS: endpoint settings fields exist, HTML IDs unique')
s=(src/'EndpointProtection.cs').read_text()
db=sqlite3.connect(':memory:')
for sql in re.findall(r'db\.Exec\("(CREATE (?:TABLE|INDEX) IF NOT EXISTS [^"\n]+)"',s): db.execute(sql)
# Use the actual SQL literals from the C# source to exercise the persistent detection and outbox schema.
def sql(prefix):
    m=re.search(r'db\.Exec\("('+re.escape(prefix)+r'[^"\n]*)"',s); assert m,prefix;return m.group(1)
db.execute(sql('INSERT INTO endpoint_stream SELECT'),('test-stream',))
db.execute(sql('INSERT INTO endpoint_stream SELECT'),('another-stream',))
assert db.execute('SELECT id FROM endpoint_stream').fetchall()==[('test-stream',)]
db.execute(sql('INSERT OR REPLACE INTO files VALUES'),('scope',r'C:\Test\file.txt','a'*64,0.0,100))
db.execute(sql('INSERT INTO canaries VALUES'),(r'C:\Test\file.txt','a'*64))
assert db.execute('SELECT hash FROM files WHERE scope=? AND path=?',('scope',r'c:\test\FILE.txt')).fetchone()==('a'*64,)
args=('id',r'C:\Test\file.txt','Canary integrity violation','critical','test only','b'*64,10,10)
db.execute(sql('INSERT OR REPLACE INTO findings VALUES'),args)
db.execute(sql('INSERT INTO incidents(utc'),(10,*args[:6]))
db.execute(sql('INSERT INTO endpoint_outbox(utc,id,path,change,severity,detail,hash,active) VALUES'),(10,*args[:6]))
db.execute(sql('INSERT INTO endpoint_outbox(utc,id,path,change,severity,detail,hash,active) SELECT'),(11,'id'))
db.execute(sql('UPDATE findings SET active=0'),('id',))
assert db.execute('SELECT active FROM findings').fetchone()==(0,)
assert db.execute('SELECT active FROM endpoint_outbox ORDER BY seq').fetchall()==[(1,),(0,)]
assert db.execute('SELECT hash FROM canaries').fetchone()==('a'*64,)
db.execute(sql('DELETE FROM endpoint_outbox WHERE seq<='),(1,))
assert db.execute('SELECT seq,active FROM endpoint_outbox').fetchall()==[(2,0)]
print('PASS: actual SQLite schema and SQL literals for file state, canary baseline, incident/open-close outbox and bounded deletion')
# Validate balanced C# delimiters using a lexer; this is NOT a compiler or type check.
try:
    from pygments import lex
    from pygments.lexers.dotnet import CSharpLexer
    from pygments.token import String, Comment
except ImportError:
    print('SKIP: C# delimiter check (Pygments unavailable)')
else:
    for name in ['EndpointProtection.cs','EndpointResponse.cs','ClamUpdateWorker.cs','Program.cs','Alerts.cs','Telemetry.cs','Web.cs','SelfCheck.cs']:
        stack=[]
        for token,value in lex((src/name).read_text(),CSharpLexer()):
            if token in String or token in Comment: continue
            for c in value:
                if c in '([{': stack.append(c)
                elif c in ')]}': assert stack and stack.pop()=={')':'(',']':'[','}':'{'}[c],(name,c)
        assert not stack,(name,stack)
    print('PASS: C# lexer delimiter checks (not compilation)')
print('PASS: portable validation completed; Windows compilation, runtime and security testing remain required.')
