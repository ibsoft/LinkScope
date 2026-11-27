"""Portable source/SQL/log-format checks; not Windows integration tests."""
from pathlib import Path
import re, sqlite3, subprocess, xml.etree.ElementTree as ET
root=Path(__file__).resolve().parents[1]
def read(p): return (root/p).read_text(encoding='utf-8-sig')
worker=read('src/ClamUpdateWorker.cs'); scanner=read('src/EndpointProtection.cs'); web=read('src/Web.cs'); task=read('src/hardware-task.ps1'); program=read('src/Program.cs'); js=read('src/app.js'); report=read('src/report.js'); version=read('tools/Write-BuildVersion.ps1')
assert "$updateAction.Arguments='--signature-update-installed'" in task
assert '$updateAction.Path=$exe' in task and "$updateDef.Principal.UserId='SYSTEM'" in task and 'GRGX;;;$sid' in task
assert 'if(!id.IsSystem)' in program and 'ClamUpdateWorker.Update(Console.Out,true)' in program
route=web.split('else if(r.Path=="/ui/endpoint-signatures")',1)[1].split('else if(r.Path==',1)[0]
assert 'Program.QueueSignatureUpdate();' in route and 'Decode<' not in route
assert 'AttemptAge.TotalMinutes<60' in worker and 'if(changed)updatedUtc=checkedUtc' in worker
assert 'state.DownloadCompleted(changed);' in worker and 'DatabaseFingerprint()' in worker
assert 'finally{svc.Refresh();' in worker and 'VerifyClamTree(ClamRoot)' in worker
for field in ('lastSuccessfulSignatureUpdateUtc','lastSuccessfulSignatureRefreshUtc','lastReportedSignatureUpdateUtc','signatureMaintenance'):
    assert field in scanner and field in report,field
assert "signatureState.checkedUtc" in js and "signatureState.updatedUtc" in js and "r.lastReportedSignatureUpdateUtc" in js
assert 'FileMode.CreateNew' in scanner and 'CreateDirectoryW(folder,IntPtr.Zero)' in scanner and 'ExpectedHash(Path.GetFileName(p))' in scanner
assert 'EndpointResponse.SafeScope(directory)' in scanner and 'Excluded(policy,folder)' in scanner
assert 'Config.Validate(next)' in web and 'monitor.CreateEndpointCanaries(settings.Endpoint,directory)' in web
conn=sqlite3.connect(':memory:')
for name in ('canaries','endpoint_metadata'):
    ddl=re.search(r'db\.Exec\("(CREATE TABLE IF NOT EXISTS '+name+r'[^"\n]+)"\)',scanner).group(1)
    conn.execute(ddl)
conn.execute('INSERT INTO canaries(path,hash) VALUES(?,?)',('C:\\Data\\Canary.txt','trusted'))
try:
    conn.execute('INSERT INTO canaries(path,hash) VALUES(?,?)',('c:\\data\\canary.txt','replacement'))
    raise AssertionError('baseline was replaced')
except sqlite3.IntegrityError: pass
assert conn.execute('SELECT hash FROM canaries').fetchone()==('trusted',)
conn.execute("INSERT OR REPLACE INTO endpoint_metadata(name,value) VALUES('reported_signature_update',?)",('2026-11-27T10:00:00Z',))
assert conn.execute("SELECT value FROM endpoint_metadata WHERE name='reported_signature_update'").fetchone()==('2026-11-27T10:00:00Z',)
pattern=re.search(r'var match=Regex.Match\(lines\[i\]\.TrimEnd\([^)]*\),@"([^"]+)"',worker).group(1).replace('(?<stamp>','(?P<stamp>')
for text in ('Fri Nov 27 10:00:00 2026 -> daily.cld updated (version: 123, sigs: 44)', 'INFO: Fri Nov 27 10:00:00 2026 -> Database updated (123 signatures)'):
    assert re.match(pattern,text),text
for text in ('Fri Nov 27 10:00:00 2026 -> daily.cld is up-to-date (version: 123, sigs: 44)', 'ERROR: Fri Nov 27 10:00:00 2026 -> download failed','Fri Nov 27 10:00:00 2026 -> arbitrary.ndb updated (version: 123, sigs: 44)'):
    assert not re.match(pattern,text),text
assert 'IsAmbiguousTime' in worker and 'IsInvalidTime' in worker and '262144' in worker
assert 'LINKSCOPE_RELEASE_VERSION' in version and 'LINKSCOPE_GITHUB_VERSION_LOOKUP' in version and 'release-version.txt' in version and 'merge-base --is-ancestor' in version
for project in [root/'LinkScope.csproj',*root.glob('setup/*.csproj')]:
    tree=ET.parse(project)
    ns={'m':'http://schemas.microsoft.com/developer/msbuild/2003'}
    includes=[x.get('Include').replace('\\','/') for x in tree.findall('./m:ItemGroup/m:Compile',ns)]
    if project.parent==root:
        assert 'src/ClamUpdateWorker.cs' in includes and (root/'src/ClamUpdateWorker.cs').is_file(),project
    else:
        assert '../src/ClamUpdateWorker.cs' in includes and (root/'src/ClamUpdateWorker.cs').is_file(),project
for file in (root/'src').glob('*.js'):
    subprocess.run(['node','--check',str(file)],check=True,capture_output=True)
print('PASS: maintenance fixed action, state semantics, canary reservation, log patterns, version wiring, project XML and JavaScript')
