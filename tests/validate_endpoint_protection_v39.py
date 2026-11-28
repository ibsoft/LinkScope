"""Targeted C# 5 source regression guard; not a compiler."""
from pathlib import Path
import re
import xml.etree.ElementTree as ET
root=Path(__file__).resolve().parents[1]
ns={'m':'http://schemas.microsoft.com/developer/msbuild/2003'}
for project in ['LinkScope.csproj','setup/LinkScope.Setup.csproj']:
    assert ET.parse(root/project).find('.//m:LangVersion',ns).text=='5',project
assert '/langversion:5' in (root/'Build.cmd').read_text()
s=(root/'src/EndpointDiskBudget.cs').read_text()
assert re.search(r'internal string Status\s*\{\s*get;\s*private set;\s*\}',s)
assert re.search(r'internal EndpointDiskPressure\(\)\s*\{\s*Status\s*=\s*"Not sampled";\s*\}',s)
# Detect the specific unsupported auto-property syntax across all C# source files.
pattern=re.compile(r'\{\s*get\s*;\s*(?:(?:private|protected|internal|public)\s+)?set\s*;\s*\}\s*=')
for p in root.rglob('*.cs'):
    assert not pattern.search(p.read_text(encoding='utf-8-sig')),str(p)
print('PASS: C# 5 build settings retained, constructor initializes Status, no matching auto-property initializers remain in C# sources (static check).')
