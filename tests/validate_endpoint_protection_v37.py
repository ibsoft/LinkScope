"""Build boundary regression test, not a C# compilation."""
from pathlib import Path
import re
import xml.etree.ElementTree as ET
root=Path(__file__).resolve().parents[1]
ns={'m':'http://schemas.microsoft.com/developer/msbuild/2003'}
def inputs(project):
    return [(project.parent / n.attrib['Include'].replace('\\','/')).resolve() for n in ET.parse(project).findall('./m:ItemGroup/m:Compile',ns)]
main=inputs(root/'LinkScope.csproj'); setup=inputs(root/'setup/LinkScope.Setup.csproj')
shared=root/'src/ClamUpdateWorker.cs'; cache=root/'src/ClamScanCacheGeneration.cs'
assert main.count(shared)==main.count(cache)==setup.count(shared)==1 and cache not in setup
assert all(p.is_file() for p in main+setup)
assert cache.name in (root/'tools/RequiredSources.txt').read_text().splitlines()
assert 'src\\*.cs' in (root/'Build.cmd').read_text()
batch=(root/'setup/BuildSetup.cmd').read_text()
assert 'ClamUpdateWorker.cs' in batch and cache.name not in batch
for p in (shared,cache):
    assert 'internal static partial class ClamUpdateWorker' in p.read_text()
for p in setup:
    assert not re.search(r'\b(?:EndpointResponse|EndpointProtection)\s*\.',p.read_text()),p
    assert not re.search(r'\bCacheGeneration\s*\(',p.read_text()),p
assert len(re.findall(r'\bCacheGeneration\s*\(',cache.read_text()))==1
for p in ('EndpointProtection.cs','UsnJournal.cs'):
    assert 'ClamUpdateWorker.CacheGeneration(' in (root/'src'/p).read_text()
for method in ('EndpointResponse.VerifyHandle','EndpointProtection.FileHash','EndpointProtection.Command','EndpointProtection.Hash'):
    assert method in cache.read_text()
print('PASS: shared installer source contains no service-only cache references; both main build paths include cache partial, both setup paths exclude it; cache dependencies and call sites preserved.')
