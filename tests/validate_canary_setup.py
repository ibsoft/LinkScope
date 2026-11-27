"""Portable tests for fixed canary originals, scan activity SQL and integration wiring.
These tests do not run Windows ACLs, setup, ClamAV or the scanner itself.
"""
import base64,hashlib,io,re,sqlite3,zipfile,xml.etree.ElementTree as ET
from pathlib import Path
r=Path(__file__).resolve().parents[1]
t=(r/'src/CanaryTemplates.cs').read_text(); e=(r/'src/EndpointProtection.cs').read_text(); p=(r/'src/Program.cs').read_text(); w=(r/'setup/wizard.ps1').read_text(); a=(r/'src/app.js').read_text(); rep=(r/'src/report.js').read_text()
files={name:base64.b64decode(data,validate=True) for name,data in re.findall(r'\{"(Reference_[^"]+)", "([A-Za-z0-9+/=]+)"\}',t)}
assert set(files)=={'Reference_Document.docx','Reference_Inventory.xlsx','Reference_Notes.txt'}
for name,b in files.items():
    if name.endswith(('docx','xlsx')):
        with zipfile.ZipFile(io.BytesIO(b)) as z:
            assert z.testzip() is None and '[Content_Types].xml' in z.namelist()
            assert not any('vba' in n.lower() or 'externalLink' in n for n in z.namelist())
            for part in z.namelist():ET.fromstring(z.read(part))
            assert ('word/document.xml' if name.endswith('docx') else 'xl/worksheets/sheet1.xml') in z.namelist()
    else:assert b'Synthetic' in b or b'synthetic' in b
    assert hashlib.sha256(b).digest()!=hashlib.sha256(b+b'x').digest()
print('PASS: three fixed harmless templates, valid ZIP/XML Office packages, SHA-256 changes on mutation')
try:
    from docx import Document
    from openpyxl import load_workbook
except ImportError:print('SKIP: optional python-docx/openpyxl reader tests')
else:
    assert 'security decoy' in Document(io.BytesIO(files['Reference_Document.docx'])).paragraphs[1].text
    assert 'security decoy' in load_workbook(io.BytesIO(files['Reference_Inventory.xlsx']),read_only=True).active['A2'].value
    print('PASS: Word and Excel templates opened by portable document readers')
assert 'FileMode.CreateNew' in t and 'if(registered!=null&&!repair)return 12' in t and 'Modified canary preserved' in t and 'Restoring missing original' in t
assert 'AllowParentMetadata' not in t and 'SetAccessControl(' not in t
assert 'FileSystemRights.ReadAndExecute,inherit' in t
assert 'if(!fixedCanary)SafePath(p)' in e and 'if(fixedCanary)EndpointResponse.VerifyHandle(file.SafeFileHandle,p)' in e
assert 'now-lastCanary>=10' in e
assert '$canaries.Checked=$true' in w and '--prepare-canaries' in w and 'MyDocuments' in w and 'RunAs' in w
assert p.index('EnrollSetupCanaries(canaryToken);') < p.index('try { StartAndWait(); }',p.index('EnrollSetupCanaries(canaryToken);'))
assert 'ep.CanaryPaths=ep.CanaryPaths.Concat(files)' in p and 'CanaryTemplates.Register(sid,folder)' in p
assert 'CanaryTemplates.ExpectedForPath(p)' in e and 'expected??hash' in e and 'INSERT OR IGNORE INTO canaries(path,hash)' in e
assert 'Existing canary baseline differs; no replacement permitted' in e
print('PASS: setup opt-in default, original user creation, explicit baseline seed, no overwrite/explicit recovery and fixed-original recovery wiring (source assertions)')
db=sqlite3.connect(':memory:')
for sql in re.findall(r'db\.Exec\("(CREATE (?:TABLE|INDEX) IF NOT EXISTS [^"\n]+)"',e):db.execute(sql)
def sql(prefix):return re.search(r'db\.Exec\("('+re.escape(prefix)+r'[^"\n]*)"',e).group(1)
path=r'C:\Users\Demo\Documents\LinkScope Canary Documents\Reference_Notes.txt'; expected=hashlib.sha256(files['Reference_Notes.txt']).hexdigest()
db.execute(sql('INSERT OR IGNORE INTO canaries(path,hash)'),(path,expected))
db.execute(sql('INSERT OR IGNORE INTO canaries(path,hash)'),(path,'tampered'))
assert db.execute('SELECT hash FROM canaries').fetchone()==(expected,)
for i in range(1100):
    db.execute(sql('INSERT INTO scan_activity(utc'),(i,path,'Real-time / canary','Clean',1,'stream: OK'))
    db.execute(sql('DELETE FROM scan_activity WHERE seq<='))
assert db.execute('SELECT COUNT(*),MIN(utc),MAX(utc) FROM scan_activity').fetchone()==(1000,100,1099)
assert 'CanaryIssue(db,c,p,"Canary content changed."' in e and 'CanaryIssue(db,c,p,"Canary missing."' in e
assert 'endpoint_outbox' in e and 'alerts.EndpointTransitions' in e
assert all(x in a for x in ['Registered canary files','Live file scan activity','result.scanActivity','result.canaries','Update signatures now','new Date(v).toLocaleString()']) or all(x in a for x in ['Registered canary files','Live file scan activity','result.scanActivity','result.canaries','Update signatures now','new Date(v).toLocaleString()'])
assert all(x in rep for x in ['er.canaries','er.items','er.signatureFreshness','er.cleanChecks'])
assert 'scanActivity=' in e and 'canaries=' in e and 'signatureFreshness=' in e
assert 'UpdateClamSignatures' in (r/'setup/ClamSetup.cs').read_text() and '--update-clamav' in w
assert 'svc.Start()' in (r/'setup/ClamSetup.cs').read_text()
print('PASS: immutable baseline INSERT, 1,000-row activity retention, detection outbox, dashboard/API/report data, local signature update controls')
print('Windows compilation, ACLs, Office compatibility in Microsoft Office, ClamAV runtime, notifications and PDF/API end-to-end tests remain pending.')

assert "-ArgumentList '--prepare-canaries' -Wait" not in w
assert "$prepTimer.Add_Tick" in w and "AddSeconds(30)" in w and "$script:prepProcess.Kill()" in w
setup=(r/"setup/Setup.cs").read_text()
branch=setup.split('if(verb=="--prepare-canaries"||verb=="--repair-canaries")',1)[1].split('if(verb=="--check-clamav")',1)[0]
assert "MessageBox.Show" not in branch and "LinkScope-Canary-errors.log" in branch
print("PASS: nonblocking canary worker, timeout, cancellation and noninteractive error handling (source checks)")

assert "$start.UseShellExecute=$false" in w and "[Diagnostics.Process]::Start($start)" in w
assert "Installation paused; canaries remain selected." in w
assert 'level="asInvoker"' in (r/"setup/setup.manifest").read_text()
assert "<ApplicationManifest>setup.manifest</ApplicationManifest>" in (r/"setup/LinkScope.Setup.csproj").read_text()
assert "/win32manifest:" in (r/"setup/BuildSetup.cmd").read_text()
print("PASS: direct worker execution, explicit UAC manifest on both build paths, no automatic skip on preparation failure")

assert "Repair enrolled canaries" in w and "--repair-canaries" in w and "RegisteredFolder(sid)" in p
print("PASS: explicit enrolled recovery, fixed originals only, baseline preservation wiring (source checks)")
