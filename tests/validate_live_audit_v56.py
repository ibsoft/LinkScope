"""Static source safeguards and real Chromium UI with mocked API; Windows integration is separate."""
from pathlib import Path
import re,os
from pygments import lex
from pygments.lexers.dotnet import CSharpLexer
from pygments.token import String,Comment
from playwright.sync_api import sync_playwright
root=Path(__file__).resolve().parents[1];src=root/'src'
cs=(src/'EndpointResponse.cs').read_text();web=(src/'Web.cs').read_text();js=(src/'app.js').read_text();html=(src/'endpoint.html').read_text()
probe=cs.split('internal static object LiveAuditProbe(',1)[1].split('  static void Confirmed(',1)[0]
for key in ('c.ResponsePaths.FirstOrDefault','c.Paths.Any','EndpointProtection.Excluded(c,root)','EndpointProtection.SafePath(root)','Program.ServiceMode','Guid.NewGuid().ToString("N")','CreateFile(path,0x10080U,2,IntPtr.Zero,1,0x04200000','VerifyHandle(handle,path)','stream.Flush(true)','catch(FileNotFoundException)','ev.Id!=4663','baselineRecord=baseline.RecordId.Value','ev.RecordId.Value<=baselineRecord','string filter="*"','writer!=pid','(mask&6)==0','eventUtc<start.AddSeconds(-1)','field("ProcessName"),image','field("ObjectName"),observedPath','maxMs=8000,maxRecords=512','passed=written&&clean&&matched'):
    assert key in probe,key
for forbidden in ('TerminateProcess(','Quarantine(','Contain(','File.Delete(','Directory.Delete(','SetAccessControl(','FileMode.Create,','Confirmed('):assert forbidden not in probe,forbidden
assert probe.index('VerifyHandle(handle,path)')<probe.index('stream.Write(marker')
assert 'CreateFile(path,0x40000080U,7,IntPtr.Zero,3,0x00200000' in probe
assert probe.index('VerifyHandle(writerHandle,path)')<probe.index('original.Volume!=reopened.Volume')<probe.index('stream.Write(marker')
assert 'original.IndexHigh!=reopened.IndexHigh' in probe and 'original.IndexLow!=reopened.IndexLow' in probe
assert 'eventCounts[ev.Id]=eventCount+1' in probe and 'parentMatches++' in probe
assert 'observed event IDs:' in probe and 'parent-directory candidates' in probe
route=web.split('else if(post&&(r.Path=="/ui/endpoint-audit-probe"||r.Path=="/ui/endpoint-external-probe"))',1)[1].split('else if',1)[0]
assert 'if(!session.IsAdmin)Deny()' in route and 'ResponsePaths.Contains(input.directory' in route and 'lastExternalAuditProbe:lastLiveAuditProbe)<30' in route and 'r.AuditAction=' in route
assert 'Access.Equal(session.Csrf,r.Header("X-CSRF-Token"))' in web
assert 'endpoint-audit-probe' not in web.split('static readonly HashSet<string> ViewerReads',1)[1].split('internal static bool ViewerAllowed',1)[0]
assert 'data-endpoint-view="tests"' in html and 'id="ep-audit-probe" {{admin-hidden}}' in html
assert int((root/'source-build-version.txt').read_text().strip().lstrip('V'))>=56
for path in ('EndpointResponse.cs','Web.cs'):
    stack=[]
    for tok,val in lex((src/path).read_text(),CSharpLexer()):
        if tok in String or tok in Comment:continue
        for ch in val:
            if ch in '([{':stack.append(ch)
            elif ch in ')]}':assert stack and stack.pop()=={')':'(',']':'[','}':'{'}[ch],(path,ch)
    assert not stack,path
print('PASS: static scope, CREATE_NEW, delete-on-close, no ACL or production response, exact event/PID/image/write mask/time, admin/CSRF/rate-limit and delimiters')
css='\n'.join((src/f).read_text() for f in ('app.css','theme.css','navigation.css'))
html=re.sub(r'<script\b[^>]*>.*?</script>','',html,flags=re.S|re.I);html=re.sub(r'<link\b[^>]*>','',html,flags=re.I);html=html.replace('</head>','<style>'+css+'</style></head>');html=html.replace('{{admin-hidden}}','').replace('{{brand}}','LinkScope').replace('{{version}}','V56')
js=js[:js.rindex('LinkScopeBusy.run(')]
with sync_playwright() as pw:
    browser=pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH','/usr/bin/chromium'),args=['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']);page=browser.new_page(viewport={'width':1366,'height':768});page.set_content(html)
    page.add_script_tag(content=js+'\nwindow.LinkScopePages={attach:()=>{}};csrf="test";setupEndpointWorkspace();')
    page.evaluate(r'''()=>{window.calls=[];request=async(path,data)=>{calls.push({path,data});return {utc:'2026-11-28T07:00:00Z',passed:true,marker:{path:'C:\\Test\\LinkScope-Audit-Probe-0123456789abcdef0123456789abcdef.txt',pid:1234,image:'C:\\Program Files\\LinkScope\\LinkScope.exe',startedUtc:'2026-11-28T06:59:59Z',baselineRecordId:'122'},proof:{path:'C:\\Test\\LinkScope-Audit-Probe-0123456789abcdef0123456789abcdef.txt',pid:1234,image:'C:\\Program Files\\LinkScope\\LinkScope.exe',eventUtc:'2026-11-28T06:59:59Z',eventId:4663,recordId:'123',accessMask:2},checks:[...['Selected audit scope','Disposable marker write','Marker cleanup'].map(name=>({name,state:'Pass',evidence:'Verified'})),{name:'Exact Event 4663 / service writer',state:'Pass',evidence:'Record 123; <img src=x onerror=alert(1)>',durationMs:2},{name:'Production containment',state:'Not tested',evidence:'Not tested'}]};};renderContainmentReadiness({ageSeconds:1,collectedUtc:'2026-11-28T07:00:00Z',result:{responseCheckedUtc:'2026-11-28T06:59:50Z',lastSignatureCheckUtc:'2026-11-28T06:59:50Z',status:'partial',mode:'protect',engineOnline:true,signatureFreshness:'Stale',responseEngineStatus:'Ready',testPaths:['C:\\Test'],responsePathsReadiness:[{path:'C:\\Test',status:'ok',detail:'Directory list and delete-child access granted.'},{path:'C:\\Denied',status:'warning',detail:'Denied'},{path:'C:\\file.exe',status:'ok',detail:'File read and delete access granted'}],canaries:[]}});}''')
    page.locator('[data-ep-tab=tests]').click();page.locator('[data-test-step="3"]').click();sel=page.locator('#ep-audit-directory');b=page.locator('#ep-audit-run')
    assert sel.locator('option').count()==2 and not b.is_disabled();sel.select_option(label=r'C:\Test');assert not b.is_disabled()
    b.click();page.get_by_role('button',name='Cancel',exact=True).click();assert page.evaluate('calls.length')==0;assert not b.is_disabled()
    b.click();page.get_by_role('button',name='Run live test',exact=True).click();page.locator('#ep-audit-status').get_by_text('Live audit verification passed',exact=False).wait_for();assert page.locator('#ep-audit-results img').count()==0
    assert page.evaluate('calls[0]')=={'path':'/ui/endpoint-audit-probe','data':{'directory':r'C:\Test'}}
    page.evaluate('()=>{request=async()=>({utc:"2026-11-28T07:00:00Z",passed:false,checks:[{name:"Disposable marker write",state:"Review",evidence:"Access denied"}]});}');b.click();page.get_by_role('button',name='Run live test',exact=True).click();page.locator('#ep-audit-status').get_by_text('requires review',exact=False).wait_for();assert 'Access denied' in page.locator('#ep-audit-results').inner_text()
    page.evaluate('()=>{request=async()=>{throw new Error("Unavailable")};}');b.click();page.get_by_role('button',name='Run live test',exact=True).click();page.locator('#ep-audit-status').get_by_text('Live audit result unavailable',exact=False).wait_for();assert not b.is_disabled()
    page.evaluate('renderContainmentReadiness({ageSeconds:30,result:{mode:"contain",engineOnline:true}})');assert b.is_disabled()
    for theme in ('light','dark'):
        page.evaluate('t=>document.documentElement.dataset.theme=t',theme)
        for width in (1440,768,390,320):
            page.set_viewport_size({'width':width,'height':800});assert page.evaluate('document.documentElement.scrollWidth <= innerWidth+1'),(theme,width)
    browser.close()
print('PASS: Chromium saved directory selection, confirm/cancel, exact request, pass/review/error/stale UI, safe text and dark/light 320–1440 px (mock API)')
