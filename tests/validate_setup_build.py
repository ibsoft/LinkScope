"""Static project/build graph validation; Windows compilation is a separate acceptance test."""
from pathlib import Path
import xml.etree.ElementTree as ET
ROOT = Path(__file__).resolve().parents[1]
ns = {'m': 'http://schemas.microsoft.com/developer/msbuild/2003'}
main = ET.parse(ROOT/'LinkScope.csproj')
setup = ET.parse(ROOT/'setup/LinkScope.Setup.csproj')
def field(tree, key):
    return tree.find('.//m:PropertyGroup/m:'+key, ns).text
assert field(main,'DisableFastUpToDateCheck') == 'true'
assert field(setup,'OutputType') == 'WinExe'
assert field(setup,'PlatformTarget') == 'x64'
assert field(setup,'AssemblyName') == 'LinkScopeSetup'
assert field(setup,'TargetFrameworkVersion') == field(main,'TargetFrameworkVersion') == 'v4.8'
assert (ROOT/'setup'/field(setup,'ApplicationIcon').replace('\\','/')).is_file()
assert [n.attrib['Include'] for n in setup.findall('.//m:Compile',ns)] == ['Setup.cs','EndpointPermissions.cs',r'..\src\CanaryTemplates.cs',r'..\src\ClamUpdateWorker.cs','ClamSetup.cs','ClamSignature.cs']
resources = {n.attrib['Include']: n.find('m:LogicalName',ns).text for n in setup.findall('.//m:EmbeddedResource',ns)}
assert resources == {'$(LinkScopePayload)':'LinkScope.exe', 'wizard.ps1':'wizard.ps1','cisco-talos.gpg':'cisco-talos.gpg'}
assert not setup.findall('.//m:ProjectReference',ns)
assert 'LinkScope.Setup.csproj' not in (ROOT/'LinkScope.sln').read_text(encoding='utf-8-sig')
target = main.find('.//m:Target[@Name="BuildLinkScopeSetup"]',ns)
assert target.attrib['AfterTargets']=='Build' and "'$(DesignTimeBuild)' != 'true'" in target.attrib['Condition']
assert not target.findall('m:Exec',ns)
msbuild = target.find('m:MSBuild',ns)
assert msbuild.attrib['Targets']=='Rebuild'
for entry in ['LinkScopePayload=$(TargetPath)','Platform=x64','OutputPath=$(_SetupStage)','OutDir=$(_SetupStage)']:
    assert entry in msbuild.attrib['Properties']
assert [n.tag.rsplit('}',1)[-1] for n in target].index('Delete') < [n.tag.rsplit('}',1)[-1] for n in target].index('MSBuild')
assert any(n.attrib.get('DestinationFiles')=='$(_SetupDestination)' for n in target.findall('m:Copy',ns))
assert any(n.attrib.get('DestinationFolder')=='$(TargetDir)deploy' and 'Exists' in n.attrib.get('Condition','') for n in target.findall('m:Copy',ns))
assert main.find('.//m:Target[@Name="CleanLinkScopeSetup"]/m:Delete',ns) is not None
assert 'BuildSetup.cmd' in (ROOT/'Build.cmd').read_text()
assert 'CreateNoWindow' in (ROOT/'setup/Setup.cs').read_text()
assert (ROOT/'tests/Verify-VisualStudioSetup.ps1').is_file()
print('PASS: MSBuild setup project, x64 GUI settings, exact payload resource, build order, conditional MSI copy, cleanup and standalone build compatibility (static checks only).')
