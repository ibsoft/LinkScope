from pathlib import Path
import os,re,subprocess,zipfile
from playwright.sync_api import sync_playwright
root=Path(__file__).resolve().parents[1];src=root/'src'
cs=(src/'EndpointResponse.cs').read_text();web=(src/'Web.cs').read_text();script=(root/'Test-LinkScopeContainmentLab.ps1').read_text()
method=cs.split('internal static object ContainmentDiagnostics(',1)[1].split('internal static object LiveAuditProbe(',1)[0].split('  static void Confirmed(',1)[0]
assert 'TerminateProcess(' not in method and 'Quarantine(' not in method and 'Contain(' not in method and 'Issue(' not in method
assert 'OpenProcess(0x1000,false,a.Pid)' in method and 'FindWriter(marker)' in method and 'EndpointProtection.SafePath(marker)' in method
assert 'c.Paths.Any(x=>EndpointProtection.Under(marker,x))' in method and 'EndpointProtection.Excluded(c,marker)' in method
assert 'Confirmed("stream: OK")' in method and 'Confirmed("stream: Heuristics.Test FOUND")' in method and 'FOUND' not in method.replace('Heuristics.Test FOUND','')
route=web.split('else if(post&&r.Path=="/ui/endpoint-containment-tests")',1)[1].split('else if',1)[0];assert 'if(!session.IsAdmin)Deny()' in route and 'ContainmentDiagnostics(settings.Endpoint,input.marker)' in route
assert 'endpoint-containment-tests' not in web.split('static readonly HashSet<string> ViewerReads',1)[1].split('internal static bool ViewerAllowed',1)[0]
assert 'FileMode]::CreateNew' in script and 'FileMode.CreateNew' in script and 'ReparsePoint' in script and '$proc.Kill()' in script and 'Stop-Process' not in script and 'Remove-Item' not in script
assert 'if($TerminateChild)' in script and 'if($Eicar)' in script and 'lab-report.json' in script
assert len(re.search(r"GetBytes\('(X5O!.*?)'\)",script).group(1))==68
print('PASS: diagnostic isolation, route authorization, scope checks, negative verdict tests, local lab source constraints (static)')
html=(src/'endpoint.html').read_text();js=(src/'app.js').read_text();css='\n'.join((src/f).read_text() for f in ('app.css','theme.css','navigation.css'))
html=re.sub(r'<script\b[^>]*>.*?</script>','',html,flags=re.S|re.I);html=re.sub(r'<link\b[^>]*>','',html,flags=re.I);html=html.replace('</head>','<style>'+css+'</style></head>');html=html.replace('{{admin-hidden}}','').replace('{{brand}}','LinkScope').replace('{{version}}','V48')
js=js[:js.rindex('LinkScopeBusy.run(')]
with sync_playwright() as pw:
    browser=pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH','/usr/bin/chromium'),args=['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']);page=browser.new_page(viewport={'width':1366,'height':768});page.set_content(html)
    page.add_script_tag(content=js+'\nwindow.LinkScopePages={attach:()=>{}};csrf="test";setupEndpointWorkspace();')
    page.evaluate('''()=>{window.calls=[];request=async(path,data)=>{calls.push({path,data});return {utc:'2026-11-28T07:00:00Z',checks:[{name:'Entropy',state:'Pass',evidence:'Known vectors',durationMs:2},{name:'Live termination',state:'Not tested',evidence:'<img src=x onerror=alert(1)>'}]};};renderContainmentReadiness({ageSeconds:1,result:{status:'partial',mode:'contain',engineOnline:true,signatureFreshness:'Stale',responseEngineStatus:'Ready',responsePathsReadiness:[{path:'C:\\\\Test',status:'warning',detail:'Denied'}],canaries:[],recentIncidents:[{change:'Containment withheld',path:'test',detail:'Clean executable'}]}});}''')
    page.locator('[data-ep-tab=tests]').click();assert page.locator('#ep-test-center').is_visible();assert not page.locator('#ep-overview').is_visible();assert 'Denied' in page.locator('#ep-test-readiness').inner_text();page.locator('[data-test-step="6"]').click();assert 'Containment withheld' in page.locator('#ep-test-events').inner_text()
    page.locator('[data-test-step="2"]').click();page.locator('#ep-test-run').click();page.locator('#ep-test-results').get_by_text('Known vectors').wait_for();assert page.locator('#ep-test-results img').count()==0;assert 'Not tested' in page.locator('#ep-test-results').inner_text();assert page.evaluate('calls[0].path')=='/ui/endpoint-containment-tests' and page.evaluate('calls[0].data.marker')==''
    page.evaluate('renderContainmentReadiness({ageSeconds:30,result:{mode:"contain",engineOnline:true}})');assert 'No readiness verdict' in page.locator('#ep-test-readiness').inner_text()
    page.evaluate('()=>{request=async()=>{throw new Error("Access denied")};}');page.locator('#ep-test-run').click();page.locator('#ep-test-status').get_by_text('Diagnostics unavailable: Access denied').wait_for();assert not page.locator('#ep-test-run').is_disabled();assert page.locator('#ep-test-results article').count()==0
    for theme in ('light','dark'):
        page.evaluate('t=>document.documentElement.dataset.theme=t',theme)
        for width in (1440,768,390,320):
            page.set_viewport_size({'width':width,'height':800});assert page.evaluate('document.documentElement.scrollWidth <= innerWidth+1'),(theme,width)
    page.locator('[data-test-step="6"]').click();page.locator('#ep-test-evidence').click();assert page.locator('[data-ep-tab=evidence]').get_attribute('aria-pressed')=='true';browser.close()
print('PASS: real browser test center, fresh/stale readiness, diagnostics, evidence escaping, errors, 320–1440 px, dark/light and evidence navigation (mock API)')
