"""Actual SQLite cache/checkpoint SQL, restart and rollback fixtures, C# source contracts.
Windows runtime and performance are NOT exercised by this test."""
from pathlib import Path
import sqlite3, tempfile, re, json
r=Path(__file__).resolve().parents[1]
e=(r/'src/EndpointProtection.cs').read_text(); u=(r/'src/UsnJournal.cs').read_text(); c=(r/'src/ClamUpdateWorker.cs').read_text()+(r/'src/ClamScanCacheGeneration.cs').read_text(); j=(r/'src/app.js').read_text(); t=(r/'src/Telemetry.cs').read_text()
def sql(prefix):
    return re.search(r'db\.(?:Exec|Rows)\("('+re.escape(prefix)+r'[^"\n]*)"',e)[1]
with tempfile.TemporaryDirectory() as d:
    path=Path(d)/'endpoint.db'; db=sqlite3.connect(path,isolation_level=None)
    for stmt in re.findall(r'db\.Exec\("(CREATE (?:TABLE|INDEX) IF NOT EXISTS [^"\n]+)"',e):db.execute(stmt)
    db.execute(sql('ALTER TABLE clean_verdict_cache ADD COLUMN'))
    policy='policy-1'; a=r'C:\Apps\app.dll'; b=r'C:\Apps\next.dll'; root=r'C:\Apps'; h='a'*64; gen='b'*64; age=7*86400; now=1000000
    save=sql('INSERT OR REPLACE INTO clean_verdict_cache'); lookup=sql('SELECT hash,generation,stamp FROM clean_verdict_cache'); active=sql('SELECT 1 FROM findings WHERE path=? COLLATE NOCASE'); forget=sql('DELETE FROM clean_verdict_cache WHERE path=?')
    db.execute(save,(policy,a,h,gen,now,''))
    def eligible(p,content,generation,when,pol=policy):
        if db.execute(active,(p,)).fetchone():return False
        return db.execute(lookup,(pol,p,when-age,when)).fetchone()==(content,generation,'')
    assert eligible(a.upper(),h,gen,now+1)
    assert not eligible(a,'f'*64,gen,now+1)
    assert not eligible(a,h,'e'*64,now+1)
    assert not eligible(a,h,gen,now+1,'other-policy')
    assert not eligible(a,h,gen,now+age)
    assert not eligible(a,h,gen,now-1)
    db.execute('INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,?)',('finding',a,'File scan error','coverage','locked','',1,1,1))
    assert not eligible(a,h,gen,now+1)
    db.execute('UPDATE findings SET active=0')
    db.close(); db=sqlite3.connect(path,isolation_level=None)
    assert eligible(a,h,gen,now+1)
    # Cache reads must not refresh verified time; forget invalidates all case variants.
    assert db.execute('SELECT verified FROM clean_verdict_cache').fetchone()==(now,)
    db.execute(forget,(a.upper(),)); assert not eligible(a,h,gen,now+1)
    db.execute(save,(policy,a,h,gen,now,''))
    init=sql('INSERT INTO baseline_state VALUES'); push=sql('INSERT INTO baseline_frontier'); top=sql('SELECT seq,path FROM baseline_frontier'); pop=sql('DELETE FROM baseline_frontier WHERE seq='); visit=sql('INSERT OR IGNORE INTO baseline_visited'); state=sql('UPDATE baseline_state SET')
    db.execute('BEGIN IMMEDIATE');db.execute(init,(policy,123));db.execute(push,(root,));db.execute('COMMIT')
    seq,p=db.execute(top).fetchone(); assert p==root
    # Crash during frontier transaction: original root remains, children not published.
    db.execute('BEGIN IMMEDIATE');db.execute(pop,(seq,));db.execute(visit,(root,));db.execute(push,(a,));db.execute('ROLLBACK')
    assert db.execute(top).fetchone()==(seq,root)
    assert db.execute('SELECT COUNT(*) FROM baseline_visited').fetchone()==(0,)
    db.execute('BEGIN IMMEDIATE');db.execute(pop,(seq,));db.execute(visit,(root,));db.execute(push,(a,));db.execute(push,(b,));db.execute(state,(0,0,0,0,0,0));db.execute('COMMIT')
    seq,p=db.execute(top).fetchone();assert p==b
    db.execute('BEGIN IMMEDIATE');db.execute(pop,(seq,));db.execute(visit,(p,));db.execute(state,(1,0,0,0,1,0));db.execute('COMMIT')
    db.close();db=sqlite3.connect(path,isolation_level=None)
    assert db.execute(top).fetchone()[1]==a
    assert set(db.execute('SELECT path FROM baseline_visited'))=={(root,),(b,)}
    assert db.execute('SELECT scan,scanned,cached FROM baseline_state').fetchone()==(123,1,1)
    # Reset clears only cache/frontier and retains security evidence.
    db.execute('BEGIN IMMEDIATE');db.execute(sql('DELETE FROM clean_verdict_cache'));clear=e.split('void ClearBaselineRows(',1)[1].split('void ClearBaseline(',1)[0]
    for q in re.findall(r'db.Exec\("([^"\n]+)"',clear):db.execute(q)
    db.execute('COMMIT')
    assert all(db.execute('SELECT COUNT(*) FROM '+x).fetchone()==(0,) for x in ('clean_verdict_cache','baseline_state','baseline_frontier','baseline_visited'))
    assert db.execute('SELECT COUNT(*) FROM findings').fetchone()==(1,)
    db.close()
assert 'full&&!canary&&Program.ServiceMode&&c.Port==3310&&online' in e
local=e.split('bool CheckFile(',1)[1].split('internal static string SizeLimitDetail',1)[0]
assert local.index('FileHash(file,budget)')<local.index('candidate.Hash==hash')<local.index('string reply=Command(c.Port,"INSTREAM"')
assert 'candidate.Generation==generation&&authorized()' in local and 'CleanVerdict(reply)&&generation!=null&&generation==ClamUpdateWorker.CacheGeneration' in local
assert 'if(recorded&&CleanVerdict(reply)&&authorized())SaveCached' in local
cached=e.split('bool RecordCached(',1)[1].split('bool CheckFile(',1)[0]
assert 'SaveCached(' not in cached and 'Resolve(' not in cached and 'lastFileScan=' not in cached
helper=u.split('ScanBatch ReadScan(',1)[1].split('void ScanRun(',1)[0]
assert helper.index('LocalScanPath(path,c)')<helper.index('FileHash(file,budget)')<helper.index('generation==expectedGeneration&&hash==expectedHash')
assert '!c.CanaryPaths.Contains(path,StringComparer.OrdinalIgnoreCase)' in helper
assert 'result.Hash!=candidate.Hash||result.Generation!=candidate.Generation' in e
assert 'mode!=4||result.Kind!="File"||result.Verdict!="Cached clean"' in u
assert 'CacheToken(args[1])' in u and 'VerifyScanPath(handle,path)' in u
assert 'VerifyScanServiceOwner' in c and 'QueryFullProcessImageName(proc' in c and 'configHash' in c and 'definitionsKey' in c and 'AlertExceedsMax' in c
assert 'baselineResumed=true;rescan=true;journalGapDuringScan=true' in e
assert 'online&&!baselineResumed&&!rescan' in e
assert 'CheckpointBaselineStep(db' in e and 'ClearBaselineRows(db)' in e
assert 'lastScan+Math.Min(c.IntervalSeconds,300)' in e
assert 'n=="endpoint_protection"?30:' in t
assert json.loads((r/'src/default.json').read_text())['Endpoint']['IntervalSeconds']==86400
assert 'Cached clean verifications' in j and 'Baseline recovery' in j
print('PASS: actual SQLite cache expiry, policy/hash/generation matching, active finding guard, persisted cache, rollback and LIFO restart checkpoint, reset isolation; source checks for privileged protocol, signature generation, recovery and telemetry. Native Windows tests not run.')
