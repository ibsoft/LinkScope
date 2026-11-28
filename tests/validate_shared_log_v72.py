"""Static source wiring and actual SQLite query / browser renderer checks.
Native sharing semantics and ClamD integration require Windows acceptance.
"""
from pathlib import Path
import sqlite3,re,os
from playwright.sync_api import sync_playwright
root=Path(__file__).resolve().parents[1];src=root/'src'
cs=(src/'EndpointProtection.cs').read_text();usn=(src/'UsnJournal.cs').read_text();native=(src/'SelfCheck.cs').read_text();js=(src/'app.js').read_text()
strict=cs.split('bool CheckFileCore(',1)[1].split('const int SharedLogMaxBytes',1)[0]
assert 'FileAccess.Read,FileShare.Read)' in strict
assert 'stage=="open file for reading"&&LockedFile(ex)' in strict and 'SharedLogEligible(c,p,canary)&&online' in strict
shared=cs.split('bool CheckSharedLog(',1)[1].split('internal static string SizeLimitDetail(',1)[0]
assert 'FileAccess.Read,FileShare.ReadWrite,1)' in shared and 'FileShare.Delete' not in shared
assert 'Math.Min((long)SharedLogMaxBytes,c.MaxFileMiB*1048576L)' in shared
assert 'SharedLogMaxBytes=8*1048576' in cs
assert 'new MemoryStream(snapshot,false)' in shared and 'ClamUpdateWorker.VerifyScanServiceOwner' in shared
assert shared.index('SharedSnapshotMatches(file,snapshot,budget,stop)')<shared.index('RecordFileIdentity(')
assert 'if(!CleanVerdict(reply))throw' in shared and 'RecordLocked(' in shared
assert 'ForgetCached(' in shared and all(x not in shared for x in ('SaveCached(', 'CachedCandidate(', 'RecordVerdict(', 'EndpointResponse.Quarantine(', 'EndpointResponse.Contain(', 'Resolve(db,path,"Malware signature detected")','Resolve(db,path,"Heuristic signature finding")'))
assert 'Array.Clear(snapshot,0,snapshot.Length)' in shared
eligible=cs.split('internal static bool SharedLogEligible(',1)[1].split('internal static bool SharedSnapshotMatches(',1)[0]
assert all(x in eligible for x in ('!canary','Program.ServiceMode','c.Port==3310','".log"','ContainmentExecutables'))
assert 'source.Length!=snapshot.LongLength' in cs and 'buffer[i]!=snapshot[offset+i]' in cs
stamp=usn.split('internal static string SharedReadStamp(',1)[1].split('// Never use timestamps alone.',1)[0]
assert all(x in stamp for x in ('EndpointResponse.VerifyHandle','info.Links!=1','info.Volume','info.IndexHigh','info.IndexLow','basic.Change','basic.Write'))
assert 'shared-read same-length mutation rejected' in native and 'shared-read append rejected' in native
print('PASS: narrow shared-read fallback, whole-file cap, verified peer, byte comparison, strict response/cache separation, native test registration')
q=re.search(r'activeScanIssues=Convert.ToInt64\(db.Rows\("([^"]+)"',cs).group(1)
db=sqlite3.connect(':memory:');db.execute('CREATE TABLE findings(active INTEGER,severity TEXT,change TEXT)')
db.executemany('INSERT INTO findings VALUES(?,?,?)',[(1,'coverage','File scan error'),(1,'coverage','File scan error'),(1,'warning','File scan coverage incomplete'),(1,'warning','USN journal coverage gap'),(1,'warning','Scan incomplete'),(1,'critical','Malware signature detected'),(0,'warning','Scan incomplete')])
assert db.execute(q).fetchone()==(3,)
assert db.execute("SELECT COUNT(*) FROM findings WHERE active=1 AND severity='coverage'").fetchone()==(2,)
print('PASS: actual SQLite counter query separates two path records from three scanner alerts and excludes resolved/malware records')
html=(src/'endpoint.html').read_text();css='\n'.join((src/f).read_text() for f in ('app.css','theme.css','navigation.css'))
html=re.sub(r'<script\b[^>]*>.*?</script>','',html,flags=re.S|re.I);html=re.sub(r'<link\b[^>]*>','',html,flags=re.I);html=html.replace('</head>','<style>'+css+'</style></head>').replace('{{admin-hidden}}','').replace('{{brand}}','LinkScope').replace('{{version}}','V72');js=js[:js.rindex('LinkScopeBusy.run(')]
fixture=dict(status='partial',engineOnline=True,signatureFreshness='Current',scanRunning=True,baselineThrottleReason='Low available physical memory',scannedFiles=362,cleanChecks=32,snapshotCleanChecks=2,cachedChecks=0,queueDepth=2,activeScanIssues=3,coverageIssueCount=2,activeMalware=0,activeHeuristic=0,canaryCount=3,mode='monitor',violations=3,items=[])
with sync_playwright() as pw:
    browser=pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH','/usr/bin/chromium'),args=['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']);page=browser.new_page(viewport={'width':1366,'height':768});page.set_content(html)
    page.add_script_tag(content=js+'\nwindow.LinkScopePages={attach:()=>{}};csrf="test";maintenanceLast=Date.now();setupEndpointWorkspace();')
    page.evaluate('r=>{window.sample={result:r,ageSeconds:1,collectedUtc:"2026-11-28T14:43:35Z"};request=async path=>path==="/ui/endpoint-ack"?{unread:0,activeUnread:0}:{categories:{endpoint_protection:sample},generatedUtc:"2026-11-28T14:43:35Z",alerts:[]};}',fixture)
    page.evaluate('renderHealth()');page.locator('[data-ep-tab=scan]').click()
    card=page.locator('.health-metric-card').filter(has_text='Files scanned').filter(visible=True);assert 'Paused' in card.inner_text() and 'Baseline paused' in card.inner_text() and 'restored progress' in card.inner_text()
    card=page.locator('.health-metric-card').filter(has_text='Shared log snapshot checks').filter(visible=True);assert '2' in card.inner_text() and 'no clean-cache reuse' in card.inner_text()
    card=page.locator('.health-metric-card').filter(has_text='Active scan issues').filter(visible=True);assert 'Outstanding file/path checks: 2' in card.inner_text()
    page.evaluate('sample.result.baselineThrottleReason="";sample.collectedUtc="2026-11-28T14:43:36Z";renderHealth()');card=page.locator('.health-metric-card').filter(has_text='Files scanned').filter(visible=True);assert 'Scanning' in card.inner_text() and 'Baseline running' in card.inner_text()
    browser.close()
print('PASS: actual browser pause label, restored baseline context, shared snapshot counter and distinct current/historical coverage counters')
