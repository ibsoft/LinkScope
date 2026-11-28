"""Source wiring and security invariants, not a Windows/FreshClam execution test."""
from pathlib import Path
root=Path(__file__).resolve().parents[1];src=root/'src'
w=(src/'ClamUpdateWorker.cs').read_text();s=(root/'setup/ClamSetup.cs').read_text();e=(src/'EndpointProtection.cs').read_text();js=(src/'app.js').read_text();toast=(src/'toast.js').read_text()
assert 'securiteinfo' not in w.lower() and 'securiteinfo' not in s.lower()
assert 'ProviderHost(x.Url)' in w and 'interval<1||interval>720' in w and 'same==null?24:same.Hours' in w
assert 'Math.Max(24,interval)' in w and 'g.Max(x=>x.Next)' in w
m=w.split('internal static void SeparateStoppedUpdater',1)[1].split('static bool NativeUpdaterSystem',1)[0]
assert m.index('SaveManagedProviders(')<m.index('File.Replace(temp,FreshConfig,null)')
assert 'DatabaseCustomURL|Checks|TestDatabases|NotifyClamd' in m and 'lines.Add("Checks 24")' in m and 'ReadClamConfig(temp).Has("DatabaseCustomURL")' in m
batch=w.split('static bool RunDueProvider',1)[1].split('internal static int Update',1)[0]
assert batch.index('SaveProviderPolicy(rows)')<batch.index('RunClamTool(')
assert 'g.Max(x=>x.Next)<=now' in batch and 'AddMinutes(15).AddHours(hours)' in batch and 'Math.Max(x.Next' in batch and ' --update-db=custom' in batch and 'MaxAttempts 1' in batch
assert 'finally{long finished' in batch and 'x.Status=success?"Checked":"Failed"' in batch
assert 'PrivateProviderFileAcl()' in w and 'SetAccessRuleProtection(true,false)' in w and 'VerifyPrivateProviderPath' in w
assert 'provider=g.Key' in w and 'PublishProviders(rows.GroupBy' in w and 'public string Url' not in w.split('public sealed class ProviderUpdateView',1)[1].split('internal sealed class ProviderPolicyEntry',1)[0]
assert 'ScheduleProviders(db,c,maintenance,now,authorized)' in e and 'state.CoolingDown' in e and 'Provider update needs review' in e
assert 'SeparateStoppedUpdater(log)' in s and 'PrepareProviderUpgrade(log)' in (root/'setup/Setup.cs').read_text()
assert 'endpoint-provider-schedules' in js and 'Next eligible attempt' in js
assert 'endpoint active alert diagnostics\',endpointAlerts' in js and 'attachAlertRow(node,a,description)' in toast
# Only migration/deduplication code may reference the retired brand, never a new task, log or page title.
legacy={'certificate.ps1','hardware-task.ps1','Config.cs','Alerts.cs'}
assert {p.name for p in src.iterdir() if p.is_file() and p.suffix in {'.cs','.ps1','.html','.js','.json','.css'} and 'unixfor' in p.read_text(errors='replace').lower()}==legacy
assert 'Version {{version}}' in (src/'login.html').read_text() and int((root/'source-build-version.txt').read_text().strip().lstrip('V'))>=47
print('PASS: generic provider grouping, persistent cooldown before launch, migration ordering, private URL storage, custom-only command, provider scheduling and dashboard, retired-brand migration allowlist, alert modal wiring (static).')
