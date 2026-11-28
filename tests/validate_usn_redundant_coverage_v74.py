"""Portable source contracts and reference state-machine scenarios. Native Windows tests required."""
from pathlib import Path
import itertools, re, sqlite3
r=Path(__file__).resolve().parents[1]
u=(r/'src/UsnJournal.cs').read_text(); e=(r/'src/EndpointProtection.cs').read_text()
poll=u.split('internal void Poll(',1)[1].split('internal string[] Pending(',1)[0]
assert 'journalGap||(unresolved>0&&!(anchored&&continuous))' in u
assert 'v.WorkIndependent&&independentlyCovered(v.Root)' in poll
assert poll.index('gap(v.Root,detail);reconcile();')<poll.index('INSERT OR REPLACE INTO usn_checkpoint')<poll.index('v.IndependentAnchor=CoverageAnchored(')
assert 'next.WorkIndependent=independentlyCovered(root)' in poll
assert 'v.IndependentAnchor=false;v.WorkIndependent=false;' in u
assert 'v.IndependentAnchor=false;v.WorkIndependent=false;v.IndependentBoundary=-1;v.Status="Fallback"' in poll
assert 'v.IndependentAnchor=false;v.WorkIndependent=false;v.IndependentBoundary=-1;v.Status="Backpressure"' in poll
assert 'CoverageBoundary(v.IndependentBoundary,stillContinuous,b.Gap,b.Tail)' in poll
assert 'CoverageAnchored(v.IndependentBoundary,b.Next,stillContinuous)' in poll
assert 'IndependentlyCoveredRecords+=b.Unresolved' in poll and 'usn-redundant-coverage' in poll
assert 'Resolve(' not in poll
coverage=e.split('bool IndependentLocalCoverage(',1)[1].split('void ConsumeCoverageOverflow(',1)[0]
for term in ['roots.Length==0','foreach(var root in roots)','faultedWatchers.ContainsKey(root)','!localWatchers.TryGetValue','!w.EnableRaisingEvents','!w.IncludeSubdirectories','!Directory.Exists(root)','Interlocked.CompareExchange(ref overflow,0,0)']:
    assert term in coverage,term
assert 'PrivilegedWatcherCovers(' not in coverage and 'usn.Covers(' not in coverage
assert 'if(recovered){usn.InvalidateIndependentCoverage();' in e
assert 'if(Interlocked.Exchange(ref overflow,0)!=0){usn.InvalidateIndependentCoverage();' in e
assert e.index('ConsumeCoverageOverflow(db);',e.index('void Tick') if 'void Tick' in e else e.index('internal object Tick'))<e.index('usn.Poll(db,c')
assert e.index('ConsumeCoverageOverflow(db);',e.index('// Catch watcher loss'))<e.index('if(running&&pending.Count==0){running=false;')
assert 'if(!rescan&&!journalGapDuringScan)' in e
# Reference model mirrors the intentionally small C# predicate and anchor lifecycle.
def needs(gap, unknown, anchor, continuous):return gap or (unknown>0 and not(anchor and continuous))
def boundary_after(old, continuous, gap, tail):return -1 if not continuous else tail if gap or old<0 else old
def anchored(boundary, cursor, continuous):return continuous and boundary>=0 and cursor>=boundary
for gap,unknown,anchor,continuous in itertools.product((False,True),(0,2),(False,True),(False,True)):
    if gap or (unknown and (not anchor or not continuous)): assert needs(gap,unknown,anchor,continuous)
    else: assert not needs(gap,unknown,anchor,continuous)
# A continuously moving journal tail cannot prevent crossing a fixed boundary.
boundary=-1; a=False
for cursor,tail in [(100,300),(200,400),(300,500),(400,600)]:
    if cursor<=300: assert needs(False,2,a,True) # crossing page conservatively warns
    else: assert not needs(False,2,a,True)
    boundary=boundary_after(boundary,True,False,tail); assert boundary==300
    a=anchored(boundary,cursor,True)
assert a and needs(True,0,a,True)
# Gap, restart and watcher failure invalidate the earlier boundary.
assert boundary_after(boundary,True,True,900)==900
assert not anchored(900,400,True)
assert boundary_after(boundary,False,False,1000)==-1
assert not anchored(-1,1000,True) and not anchored(300,1000,False)
assert needs(False,2,False,True) and needs(False,2,True,False)
# Reset must not clear operational gaps or threats. Execute the exact selection SQL.
reset=e.split('if(Interlocked.Exchange(ref resetRequested,0)!=0){',1)[1].split('if(scopeReconcilePending)',1)[0]
q=re.search(r'db.Rows\("(SELECT path,change FROM findings[^\"]+)"\)',reset).group(1)
db=sqlite3.connect(':memory:');db.execute('CREATE TABLE findings(path,change,active,severity)')
changes=['File scan error','Scan incomplete','USN journal coverage gap','USN journal unavailable','Real-time queue overflow','Watcher coverage incomplete','Malware signature detected','Canary integrity violation']
for c in changes:db.execute('INSERT INTO findings VALUES(?,?,1,?)',('root',c,'critical' if c in changes[-2:] else 'warning'))
assert {row[1] for row in db.execute(q)}=={'File scan error','Scan incomplete'}
print('PASS: USN redundant watcher qualification, anchor lifecycle reference scenarios, genuine gap retention, overflow invalidation, reset selection SQL. Native Windows execution not performed.')
