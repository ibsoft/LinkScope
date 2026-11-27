"""Static validation of legacy project configuration and direct MSBuild recovery wiring."""
from pathlib import Path
import re
import xml.etree.ElementTree as ET
ROOT = Path(__file__).resolve().parents[1]
ns = {'m':'http://schemas.microsoft.com/developer/msbuild/2003'}
p = ET.parse(ROOT/'LinkScope.csproj').getroot()
assert any('Microsoft.Common.props' in e.get('Project','') for e in p.findall('m:Import',ns))
guid=p.find('m:PropertyGroup/m:ProjectGuid',ns).text
assert guid != '{95E2FF2D-82C8-4163-94A6-FE293A34DF01}'
groups={}
for pg in p.findall('m:PropertyGroup',ns):
    m=re.fullmatch(r"\s*'\$\(Configuration\)\|\$\(Platform\)'\s*==\s*'([^']+)'\s*",pg.get('Condition',''))
    if m: groups[m[1]]=pg
assert set(groups)=={'Debug|x64','Release|x64'}
for key,g in groups.items():
    assert g.find('m:OutputPath',ns).text == 'bin\\'+key.split('|')[0]+'\\'
    assert g.find('m:PlatformTarget',ns).text == 'x64'
    assert g.find('m:Prefer32Bit',ns).text == 'false'
for name in ('LinkScope.sln','LinkScope-x64.sln'):
    lines=(ROOT/name).read_text(encoding='utf-8-sig').splitlines()
    assert lines[0]=='Microsoft Visual Studio Solution File, Format Version 12.00'
    assert any(line.endswith(f'"LinkScope.csproj", "{guid}"') for line in lines)
    for cfg in ('Debug','Release'):
        for platform in ('x64','x86','Any CPU'):
            for field in ('ActiveCfg','Build.0'):
                assert f'{guid}.{cfg}|{platform}.{field} = {cfg}|x64' in [line.strip() for line in lines]
    assert len([line for line in lines if '.Build.0 = ' in line])==6
assert p.find('m:Target[@Name="LinkScopeBuildStarted"]',ns).get('BeforeTargets')=='PrepareForBuild'
assert any(e.get('Files')==r'$(MSBuildProjectDirectory)\bin\$(Configuration)\LinkScopeSetup.exe' for e in p.findall('m:Target[@Name="CleanLinkScopeSetup"]/m:Delete',ns))
for name,mode in [('Build-VisualStudio.cmd','Build'),('Clean-VisualStudio.cmd','Clean'),('Rebuild-VisualStudio.cmd','Rebuild')]:
    s=(ROOT/name).read_text();assert 'Invoke-ProjectBuild.ps1' in s and f'-Mode {mode}' in s and 'exit /b %result%' in s
s=(ROOT/'tools/Invoke-ProjectBuild.ps1').read_text()
for token in ['vswhere.exe', "'LinkScope.csproj'", "'/p:Platform=x64'", "Run-Target 'Clean'", "Run-Target 'Build'", 'Clean did not remove', 'required output is missing', 'Verify-VisualStudioSetup.ps1', 'Verbosity=diagnostic','exit 1']:
    assert token in s,token
assert s.index("Run-Target 'Clean'") < s.index('Clean did not remove') < s.index("Run-Target 'Build'") < s.index('Verify-VisualStudioSetup.ps1')
s=(ROOT/'tests/Verify-SourceBuild.ps1').read_text();assert 'Solution Clean skipped the project' in s and '/t:Clean' in s and '/t:Rebuild' in s
print('PASS: explicit legacy IDE configs, fresh consistent GUIDs, six enabled solution mappings, direct clean/build wrappers, setup verification and skipped-Clean regression guard.')
print('Windows MSBuild and PowerShell execution not tested.')
