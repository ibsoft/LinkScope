from pathlib import Path
import os,re,subprocess
from playwright.sync_api import sync_playwright
root=Path(__file__).resolve().parents[1];src=root/'src'
html=(src/'endpoint.html').read_text();js=(src/'app.js').read_text();css='\n'.join((src/f).read_text() for f in ('app.css','theme.css','navigation.css'))
# Full page markup with actual JS renderer, no network/Windows service. Stub only API and pagination.
html=re.sub(r'<script\b[^>]*>.*?</script>','',html,flags=re.S|re.I);html=re.sub(r'<link\b[^>]*>','',html,flags=re.I);html=html.replace('</head>','<style>'+css+'</style></head>');html=html.replace('{{admin-hidden}}','').replace('{{brand}}','LinkScope').replace('{{version}}','V45')
js=js[:js.rindex('LinkScopeBusy.run(')]
fixture={'status':'partial','engineOnline':True,'signatureFreshness':'Unknown','scanRunning':True,'baselineThrottleReason':'Low available physical memory','scannedFiles':20,'queueDepth':2,'realTime':True,'watcherCount':1,'activeMalware':0,'activeScanIssues':1,'coverageIssueCount':1,'canaryCount':3,'canaries':[{'path':'C:\\Apache24\\canary.txt','status':'Enrolled'}],'mode':'monitor','violations':1,'changedFiles':0,'entropyChanges':0,'extendedEntropyPeak':100,'extendedEntropyWindowSeconds':300,'extendedEntropyThreshold':5,'protectedPaths':['C:\\Apache24'],'items':[{'path':'Protected paths','change':'Possible ransomware activity (extended observation)','severity':'warning','detail':'100 observed entropy changes'}]}
with sync_playwright() as pw:
    browser=pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH','/usr/bin/chromium'),args=['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']);page=browser.new_page(viewport={'width':1366,'height':768});page.set_content(html)
    page.add_script_tag(content=js+'\nwindow.LinkScopePages={attach:()=>{}};csrf="test";maintenanceLast=Date.now();setupEndpointWorkspace();')
    page.evaluate('r=>{window.sample={result:r,ageSeconds:1,collectedUtc:"2026-11-28T07:00:00Z",activity:{phase:"Baseline: reading and hashing",phaseUtc:"2026-11-28T06:59:55Z"}};request=async path=>path==="/ui/endpoint-ack"?{unread:0,activeUnread:0}:{categories:{endpoint_protection:sample},generatedUtc:"2026-11-28T07:00:00Z",alerts:[]};}',fixture)
    page.evaluate('renderHealth()');assert page.locator('#ep-overview-title').inner_text()=='Protection needs attention';assert page.locator('#ep-kpis button').count()==4;assert not page.locator('#endpoint-live').is_visible();assert not page.locator('#results').is_visible()
    page.locator('[data-ep-tab=scan]').click();assert page.locator('#endpoint-live').is_visible();assert 'Baseline paused' in page.locator('#endpoint-live-state').inner_text();assert 'Signature freshness' in page.locator('#endpoint-scan-health').inner_text();assert 'reading and hashing' in page.locator('#endpoint-worker-state').inner_text();assert not page.locator('#ep-overview').is_visible()
    page.evaluate('sample.result.baselineThrottleReason="";sample.collectedUtc="2026-11-28T07:00:01Z";renderHealth()');assert 'Baseline verification in progress' in page.locator('#endpoint-live-state').inner_text()
    page.locator('[data-ep-tab=behavior]').click();assert page.locator('#ep-behavior-evidence').is_visible();assert '100 observed entropy changes' in page.locator('#ep-behavior-evidence').inner_text()
    page.locator('.health-metric-card').filter(has_text='Canary files').filter(visible=True).click();assert page.locator('#ep-canary-evidence').is_visible();assert page.locator('[data-ep-tab=evidence]').get_attribute('aria-pressed')=='true'
    page.evaluate('sample.ageSeconds=30;renderHealth()');assert page.locator('#endpoint-telemetry-warning').is_visible();page.locator('[data-ep-tab=overview]').click();assert 'awaiting fresh data' in page.locator('#ep-overview-title').inner_text()
    page.evaluate('sample.ageSeconds=1;renderHealth()');assert not page.locator('#endpoint-telemetry-warning').is_visible()
    for theme in ('light','dark'):
        page.evaluate('t=>document.documentElement.dataset.theme=t',theme)
        for width in (1440,1024,768,390,320):
            page.set_viewport_size({'width':width,'height':800});page.locator('[data-ep-tab=overview]').click();assert page.evaluate('document.documentElement.scrollWidth <= innerWidth+1'),(theme,width)
    for name in ('scan','behavior','maintenance','resources','evidence','quarantine'):
        page.locator('[data-ep-tab='+name+']').click();assert page.locator('[data-ep-tab='+name+']').get_attribute('aria-pressed')=='true'
    page.evaluate('sample.result={status:"disabled",items:[]};sample.ageSeconds=1;sample.collectedUtc="2026-11-28T07:00:02Z";renderHealth()')
    page.locator('[data-ep-tab=overview]').click();assert page.locator('#ep-overview-title').inner_text()=='Protection disabled';assert 'Choose protected application directories' in page.locator('#ep-overview-message').inner_text()
    assert all(x=='—' for x in page.locator('#ep-kpis button strong').all_inner_texts())
    page.locator('[data-ep-tab=scan]').click();assert 'configure application directories' in page.locator('#endpoint-live-state').inner_text()
    browser.close()
print('PASS: full endpoint UI fixture: overview, tab routing, behavioral evidence, worker status, independent pause/signature status, stale telemetry and responsive overview')
cs=(src/'EndpointProtection.cs').read_text();telemetry=(src/'Telemetry.cs').read_text();assert 'volatile WorkerFrame workerFrame' in cs and 'activity=endpoint.WorkerActivity()' in telemetry and 'WorkerPhase("Waiting for next cycle")' not in telemetry # uses conditional phase
assert 'source-build-version' in (root/'tools/Write-BuildVersion.ps1').read_text();assert re.fullmatch(r'V[0-9]+',(root/'source-build-version.txt').read_text().strip()) and int((root/'source-build-version.txt').read_text().strip()[1:])>=45
print('PASS: worker frame and version wiring (static)')
