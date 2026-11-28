"""Portable SQL, route contracts and actual browser renderer. Native service not exercised."""
from pathlib import Path
import os,re,sqlite3
from playwright.sync_api import sync_playwright
root=Path(__file__).resolve().parents[1]; src=root/'src'
a=(src/'Alerts.cs').read_text(); web=(src/'Web.cs').read_text(); js=(src/'app.js').read_text()
method=a.split('internal object ReadEndpointAlert(',1)[1].split('internal static bool EndpointVerificationAllowed',1)[0]
sql=re.search(r'db.Exec\("(UPDATE alert_events[^"\n]+)"',method).group(1)
db=sqlite3.connect(':memory:');db.execute('CREATE TABLE alert_events(id TEXT PRIMARY KEY, category TEXT, is_read INTEGER,resolved INTEGER)');db.executemany('INSERT INTO alert_events VALUES(?,?,?,?)',[('a','endpoint_protection',0,0),('b','endpoint_protection',0,0),('r','ram',0,0),('h','endpoint_protection',0,1)])
for _ in range(2): db.execute(sql,('a',))
db.execute(sql,('r',)); assert db.execute('SELECT * FROM alert_events ORDER BY id').fetchall()==[('a','endpoint_protection',1,0),('b','endpoint_protection',0,0),('h','endpoint_protection',0,1),('r','ram',0,0)]
route=web.split('if(post&&(r.Path=="/ui/endpoint-alert-read"',1)[1].split('if(!post&&r.Path=="/ui/endpoint"',1)[0]
assert 'if(!session.IsAdmin)Deny()' in route and 'alerts.ValidateEndpointVerification(input.id)' in route and 'monitor.ScanEndpointNow()' in route and 'ResetEndpoint' not in route and '<30' in route
server=set(re.findall(r'"([^"]+)"',a.split('internal static bool EndpointVerificationAllowed',1)[1].split('}.Contains',1)[0].split('new[]{',1)[1])); client=set(re.findall(r"'([^']+)'",js.split('const endpointRetryTitles=new Set([',1)[1].split(']);',1)[0]));assert server==client and 'Malware signature detected' not in server
assert '!a.Resolved' in a and 'a.Severity=="warning"' in a
html=(src/'endpoint.html').read_text();html=re.sub(r'<script\b[^>]*>.*?</script>','',html,flags=re.S|re.I);html=re.sub(r'<link\b[^>]*>','',html,flags=re.I);html=html.replace('{{admin-hidden}}','').replace('{{brand}}','LinkScope').replace('{{version}}','V75');html=html.replace('</head>','<style>'+ '\n'.join((src/f).read_text() for f in ('app.css','theme.css','navigation.css','toast.css'))+'</style></head>')
js=js[:js.rindex('LinkScopeBusy.run(')]
with sync_playwright() as pw:
    browser=pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH','/usr/bin/chromium'),args=['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']);page=browser.new_page(viewport={'width':1366,'height':768});page.set_default_timeout(5000);page.set_content(html)
    page.add_script_tag(content=js+'\nwindow.LinkScopePages={attach:()=>{}};csrf="test";maintenanceLast=Date.now();setupEndpointWorkspace();')
    page.evaluate('''()=>{window.calls=[];window.items=[{id:'a',category:'endpoint_protection',severity:'warning',title:'USN journal coverage gap',message:'C: gap',resolved:false,read:false},{id:'b',category:'endpoint_protection',severity:'critical',title:'Malware signature detected',message:'sample',resolved:false,read:false}];window.sample={result:{status:'partial',engineOnline:true,signatureFreshness:'Current',scanRunning:false,activeMalware:1,items:[],protectedPaths:['C:\\\\Data']},ageSeconds:1,collectedUtc:'2026-11-28T07:00:00Z'};request=async(path,data)=>{if(data)calls.push([path,data]);if(path==='/ui/endpoint-alert-read'){items.find(x=>x.id===data.id).read=true;return {unread:1,activeUnread:1,through:2};}if(path==='/ui/endpoint-alert-retry')return {accepted:true};if(path==='/ui/endpoint-ack')return {unread:2,activeUnread:2,through:2};return {categories:{endpoint_protection:sample},generatedUtc:'2026-11-28T07:00:00Z',alerts:items};};}''')
    page.evaluate('renderHealth()');page.locator('[data-ep-tab=evidence]').click();page.locator('#endpoint-alert-diagnostics summary').click();rows=page.locator('#endpoint-alert-diagnostics tbody tr');usn=rows.filter(has_text='USN journal coverage gap');mal=rows.filter(has_text='Malware signature detected');assert usn.get_by_role('button',name='Retry verification').count()==1;assert mal.get_by_role('button',name='Retry verification').count()==0
    usn.get_by_role('button',name='Acknowledge').click();page.wait_for_function('items[0].read');usn.get_by_text('Acknowledged',exact=True).wait_for();assert mal.get_by_role('button',name='Acknowledge').count()==1;assert rows.count()==2;assert page.evaluate('calls[0]')==['/ui/endpoint-alert-read',{'id':'a'}]
    usn.get_by_role('button',name='Retry verification').click();page.get_by_role('dialog').get_by_role('button',name='Retry verification').click();page.wait_for_function('calls.length===2');assert page.evaluate('calls[1]')==['/ui/endpoint-alert-retry',{'id':'a'}];assert rows.count()==2
    page.locator('[data-ep-tab=overview]').click();assert page.locator('#ep-overview-title').inner_text()!='Protection healthy'
    page.evaluate('csrf="";epRenderKey="";renderHealth()');page.locator('[data-ep-tab=evidence]').click();assert page.locator('#endpoint-alert-diagnostics').get_by_role('button',name='Acknowledge').count()==0;assert page.locator('#endpoint-alert-diagnostics').get_by_role('button',name='Retry verification').count()==0
    browser.close()
print('PASS: individual acknowledgement SQL scope/idempotence, retry allowlist and route contracts, Chromium row actions, confirmed retry, threat retention and viewer read-only state.')
