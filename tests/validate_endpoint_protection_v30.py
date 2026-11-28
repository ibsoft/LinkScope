"""Portable source contracts; native runtime assertions live in SelfCheck.cs."""
from pathlib import Path
r=Path(__file__).resolve().parents[1]
e=(r/'src/EndpointProtection.cs').read_text(); u=(r/'src/UsnJournal.cs').read_text(); a=(r/'src/Alerts.cs').read_text()
assert 'changed>=threshold&&entropyIncreases>=3' in e
assert '15 << Math.Min(3,Math.Max(0,failures-1))' in e
assert 'if(engineNeedsScanProbe)' in e and 'if(!CleanVerdict(verdict))throw' in e
assert 'now>=nextEngineProbe' in e and 'return change=="Engine scan incomplete"||' in e
assert 'ex.NativeErrorCode==32||ex.NativeErrorCode==33?"Locked"' in u
assert 'if(result.Kind=="Locked")' in e and 'RecordLocked(db,c,p' in e
assert 'usn.RetainWatcher(db,path,DownloadPriority(path))' in e and '"Deferred",timer' in e
assert 'countFull++<4&&timer.ElapsedMilliseconds<500' in e
assert '"File scan coverage incomplete","Scan incomplete","Engine unavailable"' in a
print('PASS: V30 source contracts (not native runtime tests)')
