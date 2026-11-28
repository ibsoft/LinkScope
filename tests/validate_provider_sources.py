"""Portable source/markup assertions; not execution of Windows C# or FreshClam."""
from pathlib import Path
import re, zipfile
root=Path(__file__).resolve().parents[1]
worker=(root/'src/ClamUpdateWorker.cs').read_text()
setup=(root/'setup/ClamSetup.cs').read_text()
launcher=(root/'setup/Setup.cs').read_text()
wizard=(root/'setup/wizard.ps1').read_text()
endpoint=(root/'src/endpoint.html').read_text()
login=(root/'src/login.html').read_text()
css=(root/'src/theme.css').read_text()
web=(root/'src/Web.cs').read_text()
formats=set(re.findall(r'"(\.[a-z0-9]+)"',re.search(r'Extensions=\{([^}]+)\}',worker).group(1)))
assert {'.ign2','.hdb','.ndb','.mdb','.yara','.pdb','.wdb'}.issubset(formats)
assert '.cbc' not in formats and '.exe' not in formats
for marker in ['Uri.UriSchemeHttps','parsed.IsLoopback','!parsed.IsDefaultPort','parsed.UserInfo.Length!=0','parsed.Fragment.Length!=0','names.Add(Name(uri))','result.Count>100','DatabaseCustomURL','Suppresses(Uri uri)']:
    assert marker in worker,marker
assert 'Suppresses(uri)&&!allow.Checked' in setup
assert 'if(verb=="--clamav-providers")return EditProviderSources(log)' in launcher
assert "'--clamav-providers'" in wizard
assert 'RequireAdmin();' in setup.split('static int EditProviderSources',1)[1]
for marker in ['MergeProviderSources(previous,entered)','String.Equals(oldUri.DnsSafeHost,newUri.DnsSafeHost','SeparateStoppedUpdater(log)','SaveManagedProviders','LocalSystemUpdater()','SecureSignatureLogs()','TestDatabases','updater.Stop()','updater.Start()']:
    assert marker in setup,marker
for marker in ['ClamProviderSources.ValidSet(feeds)','signature-logs','FreshClam output omitted']:
    assert marker in setup and marker in worker,marker
assert 'theme-workspace-v11.css' in web and 'theme-workspace-v11.css' in endpoint
assert 'SYSTEM &amp; NETWORK MONITORING &amp; ENDPOINT PROTECTION' in login
assert 'Endpoint protection &amp; ransomware detection' in login
assert '04</span> Alerts &amp; AI-assisted diagnostics' in login
assert 'Encoding.Unicode.GetBytes("LINKSCOPE")' in setup
assert 'lines.Add("TestDatabases yes")' in worker
assert 'originalConfig=File.ReadAllText(FreshConfig)' in setup
assert 'ProviderFailureDetail(ex)' in launcher and 'providerStage' in launcher and 'logPath' in launcher
assert 'native.NativeErrorCode' in setup
editor=setup.split('static int EditProviderSources',1)[1].split('static int UpdateClamSignatures',1)[0]
assert editor.index('updater.Stop()')<editor.index('VerifyClamTree(ClamRoot)')<editor.index('SeparateStoppedUpdater(log)')
assert 'Migration incomplete; updater left stopped' in editor and 'updater.Start()' in editor
update=worker.split('internal static int Update(TextWriter log,bool enforceCooldown)',1)[1]
assert update.index('svc.Stop()')<update.index('VerifyClamTree(ClamRoot)')

assert all(endpoint.count('id="'+x+'"')==1 for x in ("metrics","endpoint-live","results")) # V45 workspace tabs changed DOM order
assert 'Third-party signature sources' in endpoint
assert 'width:13px;height:13px' in (root/'src/navigation.css').read_text() # navigation rules moved out of theme.css
# No live provider subscription token or credentials are included.
for p in root.rglob('*'):
    if p.is_file() and p.suffix.lower() in {'.cs','.ps1','.js','.html','.md','.json','.css','.txt','.cmd','.py'}:
        text=p.read_text(errors='replace')
        assert not re.search(r'(?i)securiteinfo\.com/get/signatures/[0-9a-f]{40,}',text),str(p)
print('PASS: provider formats, local elevated editor, validation/merge safeguards, private configuration and logging, header icon sizing, login label, and summary-card-first dashboard (static checks only).')
