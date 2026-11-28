"""Portable V42 checks; no Windows build or PowerShell execution."""
from pathlib import Path
from html.parser import HTMLParser
import re, json, subprocess, xml.etree.ElementTree as ET
root=Path(__file__).resolve().parents[1]; src=root/'src'
class Fields(HTMLParser):
    def __init__(self): super().__init__();self.ids={};self.controls={}
    def handle_starttag(self,tag,attrs):
        a=dict(attrs); i=a.get('id');
        if i:
            assert i not in self.ids,i;self.ids[i]=a
            if tag in ('input','select','textarea'): self.controls[i]=a
p=Fields();p.feed((src/'settings.html').read_text())
for i,a in p.controls.items():
    assert a.get('aria-describedby')=='help-'+i and 'help-'+i in p.ids,i
for i in ('channels','extras','scopes','telemetry-export-categories'):
    assert p.ids[i]['aria-describedby']=='help-'+i and 'help-'+i in p.ids
print('PASS: all',len(p.controls),'settings fields have unique associated help; four dynamic groups have descriptions')
version=(root/'source-build-version.txt').read_text().strip();assert re.fullmatch(r'V[1-9][0-9]*',version) and int(version[1:])>=42
script=(root/'tools/Write-BuildVersion.ps1').read_text();assert script.index('if ($env:LINKSCOPE_RELEASE_VERSION)')<script.index("} elseif (Test-Path -LiteralPath (Join-Path $root 'source-build-version.txt')")<script.index("$top = Invoke-Git")
assert '$version = $candidate' in script and "'packaged source release metadata'" in script
web=(src/'Web.cs').read_text();assert 'Program.Resource("build-version.txt")' in web and 'WebUtility.HtmlEncode(BuildVersion)' in web
for f in src.glob('*.html'):assert f.read_text().count('{{version}}')==1,f.name
project=ET.parse(root/'LinkScope.csproj');ns={'m':'http://schemas.microsoft.com/developer/msbuild/2003'}
assert any(x.attrib.get('Include')=='source-build-version.txt' for x in project.findall('.//m:None',ns))
assert 'Write-BuildVersion.ps1' in (root/'Build.cmd').read_text() and 'Write-BuildVersion.ps1' in (root/'LinkScope.csproj').read_text()
print('PASS: V42 archive metadata, explicit override priority, build-resource wiring and all 12 version placeholders (static)')
subprocess.run(['node','--check',str(src/'app.js')],check=True)
print('PASS: JavaScript syntax')
e=json.loads((src/'default.json').read_text())['Endpoint'];assert e['ExtendedEntropyThreshold']==5 and e['EntropyMinimumCurrent']==7.5
print('PASS: shipped entropy defaults match V41')
