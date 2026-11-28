"""Portable wiring and reference coverage predicates; native Windows watcher not executed."""
from pathlib import Path
r=Path(__file__).resolve().parents[1]
u=(r/'src/UsnJournal.cs').read_text(); e=(r/'src/EndpointProtection.cs').read_text(); j=(r/'src/app.js').read_text()
assert 'WatchPipeName="LinkScope.ScopedWatch.v1"' in u
assert 'watchOnly?WatchPipeName:ScanPipeName' in u and 'mode==3?WatchPipeName:ScanPipeName' in u
assert 'if(watchOnly?request[0]!=3:(request[0]>4||request[0]==3))' in u
assert 'if(request[0]==4)' in u and 'Invalid baseline cache request' in u
assert 'Program.ServiceSid()' in u and 'IsReader(pipe.SafePipeHandle)' in u
assert 'if(!c.RealTime||!LocalScanPath(path,c)||!c.Paths.Any' in u
assert 'EndpointProtection.SafePath(path);if((File.GetAttributes(path)&FileAttributes.Directory)==0)' in u
assert 'fs.IncludeSubdirectories=true' in u and 'fs.Created+=' in u and 'fs.Renamed+=' in u
assert 'w.Lease=History.Now()+120' in u and 'PrunePrivilegedWatches()' in u
assert 'watch.Events.Count>=MaxPrivilegedWatchQueue' in u and 'watch.Gap=true' in u
assert 'MaxPrivilegedWatchBatch=256' in u and 'MaxPrivilegedWatchRoots=32' in u
assert 'result.WatchArrivals.Any(x=>!result.Children.Contains' in u
assert 'Enqueue(saved,path,batch.WatchArrivals.Contains' in e
assert 'if(batch.WatchGap)Interlocked.Exchange(ref overflow,1)' in e
assert 'state.Verified>0&&now>=state.Verified&&now-state.Verified<=PrivilegedWatcherFreshSeconds' in e
assert 'state.Verified=batch.WatchGap?0:completed' in e
assert 'failedWatchers.Where(x=>!usn.Covers(x.Key)&&!PrivilegedWatcherCovers(watcherState(x.Key),now))' in e
assert 'privilegedWatcherDetails' in j and 'Privileged watcher roots:' in j
# Reference coverage truth table: a failed native watcher is covered only by a live
# journal or a fresh successful privileged watcher response.
def uncovered(journal, verified, now):
    return not journal and not (verified>0 and now-verified<=30)
assert uncovered(False,0,100)
assert not uncovered(False,90,100)
assert uncovered(False,60,100)
assert not uncovered(True,0,100)
print('PASS: restricted watcher pipe, exact scope, metadata bounds, lease, event priority, gap handling, UI and coverage truth table. Windows runtime NOT tested.')
