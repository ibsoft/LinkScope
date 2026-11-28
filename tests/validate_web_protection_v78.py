"""Portable source contracts and Chromium view tests; no Windows or C# execution."""
from pathlib import Path
import json, os, re
from playwright.sync_api import sync_playwright
root=Path(__file__).resolve().parents[1]; src=root/'src'
e=(src/'EndpointProtection.cs').read_text(); u=(src/'UsnJournal.cs').read_text(); w=(src/'WebServerProtection.cs').read_text(); js=(src/'app.js').read_text(); settings=(src/'settings.html').read_text(); h=(src/'endpoint.html').read_text()
d=json.loads((src/'default.json').read_text())['Endpoint']; assert d['WebProtectionEnabled'] is False and d['WebProcessAuditEnabled'] is False and d['WebPaths']==[]
assert 'WebPaths=Normalize(WebPaths)' in e and 'Paths.Any(p=>EndpointProtection.Under(x,p))' in e
assert '!WebServerProtection.Selected(c,p)&&c.MetadataFastCache' in e
assert '!WebServerProtection.Selected(c,path)&&c.MetadataFastCache' in u
local=e.split('bool CheckFileCore(',1)[1].split('internal static string SizeLimitDetail',1)[0]
assert local.index('FileHash(file,budget)')<local.index('WebServerProtection.Inspect(file,budget,stop)')<local.index('candidate.Hash==hash')
helper=u.split('ScanBatch ReadScan(',1)[1].split('void ScanRun(',1)[0]
assert helper.index('VerifyScanPath(handle,path)')<helper.index('WebServerProtection.Inspect(file,budget,stopping)')<helper.index('generation==expectedGeneration&&hash==expectedHash')
assert helper.count('WebInspection=webInspection')==2
assert 'RecordWebInspection(db,p,result.Hash,result.WebInspection)' in e
assert 'WebServerProtection.Finding,"warning"' in e and 'WebServerProtection.ProcessFinding,"warning"' in e
assert 'file.Position=0;' in w and 'MaxScriptBytes=4*1024*1024' in w and 'Unverified: short read' in w
assert 'AuditQuerySystemPolicy' in w and 'ParentProcessName' in e and 'NewProcessName' in e
assert 'if(drained)SaveWebAuditCursor(db,newest.Value)' in e and 'if(!drained)nextWebAudit=now+1;' in e
assert 'cursor>newest.Value||cursor<oldest.Value-1' in e and 'if(ev.Id==1102)' in e
assert 'WebServerProtection.cs' in (root/'LinkScope.csproj').read_text()
for field in ('WebProtectionEnabled','WebProcessAuditEnabled','WebPaths'):
    assert 'id="Endpoint'+field+'"' in settings and "'"+field+"'" in js
assert 'data-ep-tab="web"' in h and 'data-endpoint-view="web"' in h
assert 'app-web-protection-v78.js' in (src/'Web.cs').read_text()
# Use the actual browser rendering and workspace selection functions.
h=re.sub(r'<script\b[^>]*>.*?</script>','',h,flags=re.S|re.I);h=re.sub(r'<link\b[^>]*>','',h,flags=re.I);h=h.replace('{{admin-hidden}}','').replace('{{brand}}','LinkScope').replace('{{version}}','V78');h=h.replace('</head>','<style>'+'\n'.join((src/f).read_text() for f in ('app.css','theme.css','navigation.css','toast.css'))+'</style></head>')
js=js[:js.rindex('LinkScopeBusy.run(')]
base=dict(status='ok',engineOnline=True,engineRecoveryPending=False,signatureFreshness='Current',activeMalware=0,activeHeuristic=0,activeScanIssues=0,coverageIssueCount=0,violations=0,items=[],fullScanComplete=True,scanRunning=False,protectedPaths=[r'C:\Web'],rootCoverage=[dict(path=r'C:\Web',state='Watching')],pendingAlertDelivery=0,canaryCount=0,canaries=[],mode='monitor')
web=dict(enabled=True,paths=[r'C:\Web'],processAuditEnabled=True,processAuditState='Available — reviewed through captured watermark',lastScriptCheckUtc='2026-11-28T15:00:00Z',suspiciousScripts=0,inspectionIssues=0,processFindings=0,auditIssues=0)
with sync_playwright() as pw:
    browser=pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH','/usr/bin/chromium'),args=['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']);page=browser.new_page(viewport={'width':1366,'height':768});page.set_content(h);page.add_script_tag(content=js+'\nsetupEndpointWorkspace();')
    page.evaluate('r=>window.base=r',base);page.evaluate('w=>window.web=w',web)
    page.evaluate('endpointOverview({result:{...base,webProtection:web},ageSeconds:1},[])');page.locator('[data-ep-tab=web]').click();assert page.locator('#ep-web-protection').is_visible();assert 'No active supplemental findings' in page.locator('#ep-web-state').inner_text();assert page.locator('#ep-web-kpis article').count()==4
    assert page.locator('#ep-overview').get_attribute('data-state')=='ok'
    page.evaluate('endpointOverview({result:{...base,webProtection:{...web,processAuditState:"Backlog — continuing review"}},ageSeconds:1},[])');assert page.locator('#ep-overview').get_attribute('data-state')=='verifying'
    page.evaluate('endpointOverview({result:{...base,violations:1,items:[{severity:"warning",change:"Suspicious web script"}],webProtection:{...web,suspiciousScripts:1}},ageSeconds:1},[])');assert page.locator('#ep-overview').get_attribute('data-state')=='review';assert 'Review active supplemental findings' in page.locator('#ep-web-state').inner_text()
    page.evaluate('endpointOverview({result:{...base,webProtection:web},ageSeconds:31},[])');assert 'unverified' in page.locator('#ep-web-state').inner_text();assert page.locator('#ep-web-kpis article').count()==0
    page.evaluate('endpointOverview({result:{...base,webProtection:{...web,enabled:false}},ageSeconds:1},[])');assert 'Not configured' in page.locator('#ep-web-state').inner_text()
    page.evaluate('endpointOverview({result:{...base,webProtection:web},ageSeconds:1},[])')
    for theme in ['light','dark']:
        page.evaluate('t=>document.documentElement.dataset.theme=t',theme)
        for width in [390,768,1366]:
            page.set_viewport_size({'width':width,'height':800});assert page.evaluate('document.documentElement.scrollWidth <= innerWidth+1'),(theme,width)
    page.locator('#ep-web-evidence').click();assert page.locator('#endpoint-alert-diagnostics').is_visible()
    browser.close()
print('PASS: opt-in policy, verified-reader integration, cache bypass, warning-only findings, audit cursor contracts, settings wiring, Chromium module status and responsive view. Native C# and Windows APIs not executed.')
