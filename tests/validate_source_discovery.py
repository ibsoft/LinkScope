"""Portable check of the source manifest and declaration scopes (not compilation)."""
from pathlib import Path
from collections import Counter
import xml.etree.ElementTree as ET
from pygments import lex
from pygments.lexers.dotnet import CSharpLexer
from pygments.token import Comment, String, Whitespace
ROOT=Path(__file__).resolve().parents[1]
ns={'m':'http://schemas.microsoft.com/developer/msbuild/2003'}
project=ET.parse(ROOT/'LinkScope.csproj')
patterns=[x.get('Include').replace('\\','/') for x in project.findall('./m:ItemGroup/m:Compile',ns)]
assert all(p.startswith('src/') and p.endswith('.cs') and '*' not in p for p in patterns), patterns
compiled=[p for pattern in patterns for p in ROOT.glob(pattern)]
manifest=(ROOT/'tools/RequiredSources.txt').read_text().splitlines()
assert len(manifest)==len(set(manifest))
assert Counter(p.name for p in compiled)==Counter(manifest)
expected={'CanaryTemplates':'CanaryTemplates.cs','EndpointResponse':'EndpointResponse.cs','EndpointWriter':'EndpointResponse.cs','UserAccounts':'UserAccounts.cs','UserInput':'UserAccounts.cs'}
found={name:[] for name in expected}
for path in compiled:
    depth=0;previous=None
    for tok,value in lex(path.read_text(),CSharpLexer()):
        if tok in Comment or tok in String or tok in Whitespace or not value.strip(): continue
        if previous=='class' and value in expected:found[value].append((path.name,depth))
        previous=value
        if value=='{': depth+=1
        elif value=='}': depth-=1
    if path.name in expected.values(): assert depth==0,path
for name,file in expected.items():
    assert found[name]==[(file,1)], (name,found[name])
    assert 'namespace LinkScope {' in (ROOT/'src'/file).read_text()
# Model negative cases for the required inputs and evaluated compiler list.
for filename in expected.values():
    missing=Counter(manifest)-Counter(p.name for p in compiled if p.name!=filename)
    assert missing==Counter({filename:1})
    duplicate=Counter(p.name for p in compiled)+Counter({filename:1})
    assert duplicate-Counter(manifest)==Counter({filename:1})
target=project.find('./m:Target[@Name="VerifyEndpointProtectionSource"]',ns)
assert target.get('BeforeTargets')=='CoreCompile'
assert target.get('DependsOnTargets')=='RefreshLinkScopeCompileItems'
refresh=project.find('./m:Target[@Name="RefreshLinkScopeCompileItems"]',ns)
assert refresh.get('BeforeTargets')=='BeforeCompile;CoreCompile'
assert refresh.find('./m:ItemGroup/m:_LinkScopeFreshSources',ns).get('Include')==r'$(MSBuildProjectDirectory)\src\*.cs'
assert refresh.find('./m:ItemGroup/m:Compile[@Remove]',ns).get('Remove')=='@(Compile)'
assert refresh.find('./m:ItemGroup/m:Compile[@Include]',ns).get('Include')=='@(_LinkScopeFreshSources);@(_LinkScopeOtherSources)'
# Old solution platform names remain supported as aliases, never x86 compiler targets.
for solution in ['LinkScope.sln','LinkScope-x64.sln']:
    lines=(ROOT/solution).read_text(encoding='utf-8-sig').splitlines()
    project_guid=project.find('./m:PropertyGroup/m:ProjectGuid',ns).text
    for config in ['Debug','Release']:
        for platform in ['x64','x86','Any CPU']:
            key=f'{config}|{platform}'
            assert f'{key} = {key}' in [line.strip() for line in lines],(solution,key)
            for kind in ['ActiveCfg','Build.0']:
                assert f'{project_guid}.{key}.{kind} = {config}|x64' in [line.strip() for line in lines],(solution,key,kind)
assert project.find('./m:PropertyGroup/m:PlatformTarget',ns).text=='x64' 
assert target.find('m:WriteLinesToFile',ns).get('Lines')=="@(Compile)"
assert '-CompileList' in target.find('m:Exec',ns).get('Command')
script=(ROOT/'tools/Assert-EndpointSources.ps1').read_text()
for token in ['RequiredSources.txt','Missing required C# source file(s)','actual inclusion count','split-response-v2','UserAccounts','UserInput']:
    assert token in script,token
assert 'Assert-EndpointSources.ps1' in (ROOT/'Build.cmd').read_text()
assert project.find('./m:Target[@Name="BuildLinkScopeSetup"]',ns) is not None
print(f'PASS: all {len(compiled)} required sources selected once, five security-critical declarations at namespace depth, missing/duplicate input models, evaluated-source guard and setup build wiring.')
print('Windows PowerShell guard execution and C# compilation: not run.')
