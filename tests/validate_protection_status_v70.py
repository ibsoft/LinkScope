"""Exercise the overview with actual renderer, and durable resolution SQL with SQLite.
Windows service/ClamD execution remains an acceptance test on Windows.
"""
from pathlib import Path
import os,re,sqlite3
from playwright.sync_api import sync_playwright
root=Path(__file__).resolve().parents[1]; src=root/'src'
cs=(src/'EndpointProtection.cs').read_text(); worker=(src/'ClamUpdateWorker.cs').read_text(); selfcheck=(src/'SelfCheck.cs').read_text()
assert 'status=="Warning"&&detail==DefinitionReview' in worker
for term in ['freshness!="Current"','checkedEpoch>now','now-checkedEpoch>90','download<attempt','checkedEpoch>new DateTimeOffset(download).ToUnixTimeSeconds()']:
    assert term in worker
assert 'Program.ServiceMode&&c.Port==3310&&!alreadyRecovered&&maintenance.CanReconcileDefinitionWarning(online&&!engineNeedsScanProbe,signatureFreshness,lastSignatureCheck,History.Now())' in cs
assert cs.index('RefreshSignatureComparison(db,c);')<cs.index('maintenance.CanReconcileDefinitionWarning(')
assert 'alreadyRecovered=maintenance.DefinitionOnlyWarning&&recoveredDefinition!=null&&Equals(recoveredDefinition[0],maintenanceKey)' in cs
assert 'if(!alreadyRecovered&&(maintenance.status=="Failed"||maintenance.status=="Warning"||maintenance.status=="Interrupted"))' in cs
assert 'signatureMaintenanceDefinitionRecovered=alreadyRecovered' in cs
for term in ['official download failure retained','updater readiness warning retained','explicit expected-version reload failure not reconciled','engine observation must postdate completed download','malformed maintenance timestamp rejected']:
    assert term in selfcheck
# Actual resolution SQL (not a test of native service execution).
def sql(text,prefix):return re.search(r'db.Exec\("('+re.escape(prefix)+r'[^"\n]*)"',text).group(1)
db=sqlite3.connect(':memory:',isolation_level=None)
for name in ['findings','incidents','endpoint_outbox']:
    db.execute(sql(cs,'CREATE TABLE IF NOT EXISTS '+name))
for id,path,change,sev in [('signature','ClamAV','Signature update needs review','warning'),('coverage',r'C:\data\locked.txt','File scan error','coverage'),('other','ClamAV','Signature database may be stale','warning'),('malware',r'C:\data\infected','Malware signature detected','critical')]:
    db.execute('INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,1)',(id,path,change,sev,'evidence','',1,1))
    db.execute('INSERT INTO incidents(utc,id,path,change,severity,detail,hash) VALUES(?,?,?,?,?,?,?)',(1,id,path,change,sev,'evidence',''))
resolve=cs.split('void Resolve(Sqlite db',1)[1].split('void ',1)[0]
db.execute('BEGIN IMMEDIATE');db.execute(sql(resolve,'INSERT INTO endpoint_outbox(utc,id,path,change,severity,detail,hash,active) SELECT'),(2,'signature'));db.execute(sql(resolve,'UPDATE findings SET active=0 WHERE id='),('signature',));db.execute('COMMIT')
assert db.execute('SELECT id FROM findings WHERE active=1 ORDER BY id').fetchall()==[('coverage',),('malware',),('other',)]
assert db.execute('SELECT COUNT(*) FROM incidents').fetchone()==(4,)
assert db.execute('SELECT id,active FROM endpoint_outbox').fetchall()==[('signature',0)]
print('PASS: narrow recovery wiring, native self-test registration, SQLite resolution retains history, other warnings and malware')
html=(src/'endpoint.html').read_text();js=(src/'app.js').read_text();css='\n'.join((src/f).read_text() for f in ('app.css','theme.css','navigation.css'))
html=re.sub(r'<script\b[^>]*>.*?</script>','',html,flags=re.S|re.I);html=re.sub(r'<link\b[^>]*>','',html,flags=re.I);html=html.replace('</head>','<style>'+css+'</style></head>').replace('{{admin-hidden}}','').replace('{{brand}}','LinkScope').replace('{{version}}','V70')
js=js[:js.rindex('LinkScopeBusy.run(')]
base=dict(status='ok',engineOnline=True,signatureFreshness='Current',activeMalware=0,activeScanIssues=0,coverageIssueCount=0,canaryCount=3,mode='contain',violations=0,items=[],fullScanComplete=True,rootCoverage=[dict(path=r"C:\Data",state="Watching",localWatcher=True)],protectedPaths=[r"C:\Data"],pendingAlertDelivery=0)
with sync_playwright() as pw:
    browser=pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH','/usr/bin/chromium'),args=['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']);page=browser.new_page(viewport={'width':1366,'height':768});page.set_content(html)
    page.add_script_tag(content=js+'\nwindow.LinkScopePages={attach:()=>{}};csrf="test";maintenanceLast=Date.now();setupEndpointWorkspace();')
    page.evaluate('r=>window.base=r',base)
    page.evaluate('endpointOverview({result:base,ageSeconds:1},[])');assert page.locator('#ep-overview').get_attribute('data-state')=='ok';assert page.locator('#ep-status-reasons').is_hidden()
    page.evaluate('endpointOverview({result:{...base,activeScanIssues:2,violations:1,items:[{change:"Signature update needs review",path:"ClamAV",severity:"warning",detail:"Earlier update awaiting reload"}]},ageSeconds:1},[])')
    assert page.locator('#ep-overview').get_attribute('data-state')=='review';assert '0 / 2' in page.locator('#ep-kpis').inner_text();assert 'Earlier update awaiting reload' in page.locator('#ep-attention').inner_text();assert '2 active scanner findings' in page.locator('#ep-attention').inner_text()
    page.locator('#ep-status-reasons').click();assert page.evaluate('document.activeElement.id')=='ep-attention'
    page.evaluate('endpointOverview({result:{...base,status:"partial",coverageIssueCount:1,coverageDetails:[{issue:"Deferred",path:"C:\\\\data\\\\locked.txt",detail:"File in use"}],fullScanComplete:false},ageSeconds:1},[])');assert 'File in use' in page.locator('#ep-attention').inner_text();assert 'Baseline reconciliation is incomplete' in page.locator('#ep-attention').inner_text()
    page.evaluate('endpointOverview({result:{...base,signatureFreshness:"Stale",signatureComparison:"Newer daily version available"},ageSeconds:1},[])');assert page.locator('#ep-overview').get_attribute('data-state')=='review';assert 'Newer daily version available' in page.locator('#ep-attention').inner_text()
    page.evaluate('endpointOverview({result:base,ageSeconds:1},[{title:"USN journal coverage gap",message:"57 unresolved historical paths",severity:"warning",resolved:false}])');assert '57 unresolved historical paths' in page.locator('#ep-attention').inner_text();assert page.locator('#ep-overview').get_attribute('data-state')=='review'
    page.evaluate('endpointOverview({result:base,ageSeconds:1},[{title:"USN journal coverage gap",message:"57 unresolved historical paths",severity:"warning",resolved:true}])');assert page.locator('#ep-overview').get_attribute('data-state')=='ok'
    page.evaluate('endpointOverview({result:{...base,items:[{severity:"critical",change:"Malware signature detected",path:"test",detail:"Confirmed signature"}]},ageSeconds:1},[])');assert page.locator('#ep-overview').get_attribute('data-state')=='fail'
    page.evaluate('endpointOverview({result:base,ageSeconds:30},[])');assert page.locator('#ep-overview').get_attribute('data-state')=='unknown'
    page.evaluate('endpointOverview({result:{...base,status:"partial",coverageIssueCount:1,coverageDetails:[{issue:"Deferred",path:"C:\\\\"+"long-directory-name".repeat(30),detail:"File in use"}]},ageSeconds:1},[])')
    for theme in ['light','dark']:
        page.evaluate('t=>document.documentElement.dataset.theme=t',theme)
        for width in [320,390,768,1366]:
            page.set_viewport_size({'width':width,'height':800});assert page.evaluate('document.documentElement.scrollWidth <= innerWidth+1'),(theme,width)
    browser.close()
print('PASS: mocked browser healthy/amber/critical/stale states, distinct counts, exact reasons, active vs resolved alerts, focus and responsive layout')
