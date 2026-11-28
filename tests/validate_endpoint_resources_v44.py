from pathlib import Path
import json,re,subprocess,os
from playwright.sync_api import sync_playwright
root=Path(__file__).resolve().parents[1];src=root/'src'
cs=(src/'EndpointProtection.cs').read_text();budget=(src/'EndpointDiskBudget.cs').read_text();js=(src/'app.js').read_text();html=(src/'endpoint.html').read_text();settings=(src/'settings.html').read_text();defaults=json.loads((src/'default.json').read_text())['Endpoint']
for key,value in dict(BackgroundPauseOnLowMemory=True,MemoryMinimumAvailableMiB=512,MemoryMinimumAvailablePercent=10,BackgroundBatchSize=4,SignatureMemoryDeferralMinutes=60).items():
    assert defaults[key]==value and key+' {get;set;}' in cs and 'Endpoint'+key in settings and key in js
    assert 'help-Endpoint'+key in settings
assert 'GlobalMemoryStatusEx' in budget and 'while(history.Count>120)' in budget
assert 'previousStart' in budget and 'ResourceClamdPid()!=pid' in budget
assert 'now-r.Next<c.SignatureMemoryDeferralMinutes*60L' in cs
assert cs.index('if(c.RealTime&&online){ScanWatcher')<cs.index('baselineThrottleReason=running?')<cs.index('if(online&&running&&pending.Count>0&&string.IsNullOrEmpty(baselineThrottleReason))')
assert 'countFull++<c.BackgroundBatchSize' in cs and 'resources=resourceMonitor.Snapshot(c)' in cs
for f in [src/'ClamUpdateWorker.cs',root/'setup/ClamSetup.cs']:
    assert 'BytecodeSecurity ConcurrentDatabaseReload"' in f.read_text() and 'Invalid database reload setting' in f.read_text()
print('PASS: resource defaults, settings help and binding, bounded history, scan scheduling and signature deferral wiring (static)')
# Exercise actual renderer with synthetic telemetry; missing readings and stale state must remain unknown.
section=re.search(r'<section id="endpoint-resources".*?</section>',html,re.S).group(0)
code=js[js.index('function renderEndpointResources('):js.index('function endpointActivity(')]
fixture='<html><head><meta name="viewport" content="width=device-width, initial-scale=1"><style>'+ (src/'app.css').read_text()+'</style></head><body data-page="endpoint"><main>'+section+'</main><script>const byId=id=>document.getElementById(id); const element=(tag,text)=>{const e=document.createElement(tag);if(text!=null)e.textContent=text;return e;};'+code+'</script></body></html>'
with sync_playwright() as pw:
    browser=pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH','/usr/bin/chromium'),args=['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']);page=browser.new_page(viewport={'width':1366,'height':768});page.set_content(fixture)
    sample={'sampleUtc':'2026-11-28T07:00:00Z','memoryStatus':'Low available memory','availableMiB':400,'totalMiB':8192,'effectiveFloorMiB':820,'lowMemory':True,'backgroundPauseEnabled':True,'clamStatus':'Registered ClamD service process','clamPid':123,'clamWorkingMiB':1300,'clamPrivateMiB':1500,'clamCpu':2.5,'history':[{'availableMiB':1000,'clamWorkingMiB':1200,'clamCpu':None},{'availableMiB':None,'clamWorkingMiB':1300,'clamCpu':2.5},{'availableMiB':400,'clamWorkingMiB':1300,'clamCpu':0}]}
    for width in (1366,768,390,320):
        page.set_viewport_size({'width':width,'height':768});page.evaluate('(s)=>renderEndpointResources(s,true)',sample)
        assert 'Low available memory' in page.locator('#endpoint-resource-status').inner_text();assert '2.5%' in page.locator('#endpoint-resource-cpu').inner_text();assert page.locator('#endpoint-resource-charts svg').count()==3
        assert page.locator('#endpoint-resource-charts svg').nth(0).locator('circle').count()==2
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth+1')
    page.evaluate('(s)=>renderEndpointResources(s,false)',sample);assert page.locator('#endpoint-resource-cpu').inner_text()=='—' and page.locator('#endpoint-resource-charts svg').count()==0
    browser.close()
print('PASS: actual resource renderer, null readings, stale state and four responsive widths (Chromium fixture)')
