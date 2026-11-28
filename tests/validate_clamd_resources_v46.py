"""Portable regression checks; native Windows self-check is separately in SelfCheck.cs."""
from pathlib import Path
import re, os
from playwright.sync_api import sync_playwright
root=Path(__file__).resolve().parents[1];src=root/'src'
budget=(src/'EndpointDiskBudget.cs').read_text();program=(src/'Program.cs').read_text();response=(src/'EndpointResponse.cs').read_text();task=(src/'hardware-task.ps1').read_text();js=(src/'app.js').read_text();html=(src/'endpoint.html').read_text()
sample=budget.split('internal void Sample(EndpointSettings policy)',1)[1].split('internal object Snapshot',1)[0]
assert 'OpenProcess(QueryLimited,false,pid)' in sample and 'QueryLimited=0x1000' in budget
assert 'GetProcessById' not in sample and 'GetProcessMemoryInfo' in budget and 'UIntPtr' in budget and 'PrivateUsage' in budget
assert 'GetProcessTimes' in sample and 'QueryFullProcessImageName' in sample and 'ResourceClamdPid()!=pid' in sample and 'started==previousStart' in sample
assert 'if(memoryOk)' in sample and 'clamWorkingMiB=clamPrivateMiB=null;clamCpu=null' in sample
assert 'Marshal.GetLastWin32Error()' in budget and 'access denied; verify the installed ClamD query-access task' in budget
entry=program.split('static int RefreshInstalledClamPeerAccess()',1)[1].split('static int UpdateInstalledSignatures()',1)[0]
for x in ['id.IsSystem','maintenance.lock','if(!policy.Enabled)return 0','policy.Port!=3310','policy.Mode!="monitor"&&!Same(policy.TrustedEnginePath,standard)','RefreshClamPeerAccess(ServiceSid())']:assert x in entry
helper=response.split('internal static bool RefreshClamPeerAccess(',1)[1].split('internal static string CheckResponseEngine',1)[0]
assert 'StandardClamdResponsePid()!=pid' in helper and 'AceQualifier.AccessAllowed,(int)QueryLimited,serviceSid,false,null' in helper
assert "'D:P(A;;GA;;;SY)(A;;GA;;;BA)'" in task and '--clam-peer-access-installed' not in (src/'Web.cs').read_text()
assert 'NativeCounterSelfCheck()' in (src/'SelfCheck.cs').read_text()
assert re.search(r'app-endpoint-workspace-v[0-9]+\.js',html) and 'app-endpoint-workspace-v46.js' in (src/'Web.cs').read_text()
assert int((root/'source-build-version.txt').read_text().strip()[1:])>=46
print('PASS: limited-query handle, native counters, identity/restart guard, restricted task, diagnostics, self-check and version wiring (static)')
section=re.search(r'<section id="endpoint-resources".*?</section>',html,re.S).group(0)
code=js[js.index('function renderEndpointResources('):js.index('function endpointActivity(')]
fixture='<html><head><meta name="viewport" content="width=device-width, initial-scale=1"><style>'+ (src/'app.css').read_text()+'</style></head><body data-page="endpoint"><main>'+section+'</main><script>const byId=id=>document.getElementById(id); const element=(tag,text)=>{const e=document.createElement(tag);if(text!=null)e.textContent=text;return e;};'+code+'</script></body></html>'
with sync_playwright() as pw:
    browser=pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH','/usr/bin/chromium'),args=['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']);page=browser.new_page(viewport={'width':390,'height':768});page.set_content(fixture)
    s={'sampleUtc':'2026-11-28T07:20:09Z','memoryStatus':'Available memory measured','availableMiB':2657,'totalMiB':16075,'effectiveFloorMiB':1608,'lowMemory':False,'clamStatus':'Cannot open registered ClamD with query-only access (Win32 5): access denied; verify the installed ClamD query-access task','clamPid':None,'clamWorkingMiB':None,'clamPrivateMiB':None,'clamCpu':None,'history':[{'availableMiB':2657}]}
    page.evaluate('(s)=>renderEndpointResources(s,true)',s)
    assert 'Win32 5' in page.locator('#endpoint-resource-detail').inner_text() and page.locator('#endpoint-resource-cpu').inner_text()=='—'
    s.update(sampleUtc='2026-11-28T07:20:14Z',clamStatus='Registered ClamD service process (query-only) · CPU awaiting second sample',clamPid=123,clamWorkingMiB=895,clamPrivateMiB=1200,history=[{'availableMiB':2657,'clamWorkingMiB':895}])
    page.evaluate('(s)=>renderEndpointResources(s,true)',s);assert '895 MiB' in page.locator('#endpoint-resource-clam-memory').inner_text() and page.locator('#endpoint-resource-cpu').inner_text()=='Awaiting sample'
    s.update(sampleUtc='2026-11-28T07:20:19Z',clamStatus='Registered ClamD service process (query-only)',clamCpu=0,history=[{'availableMiB':2657,'clamWorkingMiB':895,'clamCpu':0}]);page.evaluate('(s)=>renderEndpointResources(s,true)',s)
    assert page.locator('#endpoint-resource-cpu').inner_text()=='0%' and page.locator('#endpoint-resource-charts svg').count()==3
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth+1')
    browser.close()
print('PASS: access-denied, first sample, actual zero CPU and chart recovery (Chromium synthetic telemetry)')
