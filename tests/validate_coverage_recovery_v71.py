"""Static source wiring and actual browser renderer; native self-checks execute on Windows."""
from pathlib import Path
import os,re
from playwright.sync_api import sync_playwright
root=Path(__file__).resolve().parents[1];src=root/'src'
cs=(src/'EndpointProtection.cs').read_text();budget=(src/'EndpointDiskBudget.cs').read_text();checks=(src/'SelfCheck.cs').read_text()
helper=cs.split('void ScheduleCoverageRecovery(',1)[1].split('void Observe(',1)[0]
assert 'if(running||complete||!online||lastScan<=0||traversalLimitReached)return;' in helper
assert "severity='coverage'" in helper and 'USN journal unavailable' in helper
assert 'Resolve(' not in helper and 'DELETE ' not in helper
assert cs.index('ScheduleCoverageRecovery(db,c);')<cs.index('if(force){nextScan=0;if(running)rescan=true;}')
assert 'return Math.Min(scheduled,last+Math.Min(interval,300));' in cs
assert 'if(running||complete||!online||blocked||pathFailures||last<=0)return scheduled;' in cs
assert 'long recovery=RecoveryFloor(total,floor);' in budget and 'RecoveryFloor(totalMiB.Value,effectiveFloor)' in budget
assert 'recovered path errors advance next reconciliation' in checks
assert 'if(!rescan&&!journalGapDuringScan)' in cs and 'complete=errors==0&&limited==0&&online&&!baselineResumed&&!rescan' in cs
print('PASS: bounded reconciliation schedule, no early warning retirement, memory hysteresis wiring, native self-check cases registered')
html=(src/'endpoint.html').read_text();js=(src/'app.js').read_text();css='\n'.join((src/f).read_text() for f in ('app.css','theme.css','navigation.css'))
html=re.sub(r'<script\b[^>]*>.*?</script>','',html,flags=re.S|re.I);html=re.sub(r'<link\b[^>]*>','',html,flags=re.I);html=html.replace('</head>','<style>'+css+'</style></head>').replace('{{admin-hidden}}','').replace('{{brand}}','LinkScope').replace('{{version}}','V71')
js=js[:js.rindex('LinkScopeBusy.run(')]
base=dict(status='scanning',engineOnline=True,signatureFreshness='Current',activeMalware=0,activeScanIssues=0,coverageIssueCount=0,canaryCount=3,mode='contain',violations=0,items=[],fullScanComplete=False,rootCoverage=[],scanRunning=True,baselineThrottleReason='Low available physical memory',scannedFiles=357,baselineDiscoveredPending=42,baselineFollowupRequired=True,resources=dict(sampleUtc='2026-11-28T14:35:37Z',availableMiB=400,effectiveFloorMiB=820,recoveryFloorMiB=1066))
with sync_playwright() as pw:
    browser=pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH','/usr/bin/chromium'),args=['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']);page=browser.new_page(viewport={'width':1366,'height':768});page.set_content(html)
    page.add_script_tag(content=js+'\nwindow.LinkScopePages={attach:()=>{}};csrf="test";maintenanceLast=Date.now();setupEndpointWorkspace();')
    page.evaluate('r=>window.base=r',base)
    page.evaluate('endpointOverview({result:base,ageSeconds:1,collectedUtc:"2026-11-28T14:35:40Z"},[])')
    assert page.locator('#ep-overview').get_attribute('data-state')=='review'
    detail=page.locator('#ep-attention').inner_text();assert '400 MiB' in detail and '1066 MiB' in detail and 'Another complete baseline' in detail and '42 discovered entries' in detail
    page.evaluate('endpointOverview({result:base,ageSeconds:1,collectedUtc:"2026-11-28T14:36:40Z"},[])');assert '400 MiB' not in page.locator('#ep-attention').inner_text()
    page.evaluate('endpointOverview({result:{...base,baselineThrottleReason:"",baselineFollowupRequired:false,activeScanIssues:2,items:[{change:"Scan incomplete",severity:"warning",path:"Protected paths",detail:"2 errors"}]},ageSeconds:1},[])');assert page.locator('#ep-overview').get_attribute('data-state')=='review'
    page.evaluate('endpointOverview({result:{...base,status:"partial",scanRunning:false,baselineThrottleReason:"",nextScanUtc:"2026-11-28T14:40:00Z"},ageSeconds:1},[])');assert 'Next reconciliation:' in page.locator('#ep-attention').inner_text()
    page.evaluate('endpointOverview({result:{...base,status:"ok",scanRunning:false,baselineThrottleReason:"",baselineFollowupRequired:false,fullScanComplete:true},ageSeconds:1},[])');assert page.locator('#ep-overview').get_attribute('data-state')=='ok'
    browser.close()
print('PASS: actual browser pause state, fresh RAM evidence, stale RAM rejection, follow-up, active warning and healthy state')
