"""Portable source checks and reference scheduling fixtures; no Windows execution."""
from pathlib import Path
r=Path(__file__).resolve().parents[1]
e=(r/'src/EndpointProtection.cs').read_text(); u=(r/'src/UsnJournal.cs').read_text(); j=(r/'src/app.js').read_text(); h=(r/'src/endpoint.html').read_text()
assert 'Registry.LocalMachine.OpenSubKey(@"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList")' in e
assert 'Path.Combine(path,"Downloads")' in e
assert 'c.Paths.Any(x=>Under(p,x))&&!Excluded(c,p)' in e
assert 'if(c.RealTime&&authorized()){PollDownloads(c,now);ScanDownload(db,c,stop,authorized,now);}' in e
assert e.index('PollDownloads(c,now);ScanDownload')<e.index('if(c.RealTime&&online){ScanWatcher(db,c,stop,authorized,0)')
assert 'CheckPrivileged(db,c,p,stop,authorized,false,c.CanaryPaths.Contains' in e
assert 'UsnJournalService.FetchDownloads(root)' in e and 'request[0]==2?ReadDownloads(path)' in u
assert 'LocalScanPath(path,c)' in u and 'VerifyScanPath(h,path)' in u and 'EndpointProtection.Excluded(c,f.FullName)' in u
assert 'downloadWork.Count>=32768' in e and 'count>MaxDirectoryEntries' in u
assert 'work.Entry.Size==file.Size&&work.Entry.Written==file.Written&&work.Entry.Created==file.Created' in e
assert 'work.Done=row!=null&&new[]{"Clean","Infected","Heuristic","Quarantined","Limited","Excluded","Reparse boundary"}' in e
assert 'work.Next=now+15' in e and 'downloadSource??' in e
assert 'downloadLastResult' in j and 'endpoint-download-state' in h
assert 'ResetDownloads();' in e and 'downloadWork.Remove(path)' in e
print('PASS: Downloads scope discovery, independent scheduling, privileged metadata protocol, bounded retry and activity telemetry source checks. Native behavior NOT tested.')
