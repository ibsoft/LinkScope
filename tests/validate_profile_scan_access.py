from pathlib import Path
root=Path(__file__).resolve().parents[1]
s=(root/'src/EndpointProtection.cs').read_text(); p=(root/'Grant-LinkScopeScanAccess.ps1').read_text(); ui=(root/'src/settings.html').read_text()
assert 'var c=watchPolicy;if(c==null||failedWatchers.Count==0||now<nextWatcherRetry)return;' in s
assert 'foreach(var p in failedWatchers.Keys.ToArray())if(TryStartWatcher(c,p))recovered=true;' in s
assert 'nextWatcherRetry=now+60' in s and 'if(recovered){nextScan=0;if(running)rescan=true;' in s
assert 'RetryFailedWatchers(now);' in s and 'failedWatchers.Remove(p)' in s
assert 'if(w!=null)w.Dispose();failedWatchers[p]' in s
assert 'SupportsShouldProcess=$true' in p and '$PSCmdlet.ShouldProcess' in p
assert 'ServiceSidType -ne 1' in p and 'NT SERVICE' in p
assert 'AllowProfileRoot' in p and 'ProfileList' in p and 'config.Endpoint.Paths' in p
assert 'ReparsePoint' in p and '$target.Length -le 3' in p
assert "':(OI)(CI)(R)'" in p and '/grant $grant /L' in p
assert '/grant:r' not in p and ' /T' not in p.split('& (Join-Path $env:SystemRoot')[1]
assert 'Grant-LinkScopeScanAccess.ps1' in ui
print('PASS: source checks for explicit scope/ACL consent and bounded independent watcher retry; Windows execution not tested.')
