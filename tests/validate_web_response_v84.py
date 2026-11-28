"""Portable source contracts and UI simulation; does NOT execute Windows quarantine."""
from pathlib import Path
import json, os, re
from playwright.sync_api import sync_playwright
src=Path(__file__).resolve().parents[1]/'src'
e=(src/'EndpointProtection.cs').read_text(); q=(src/'EndpointResponse.cs').read_text(); w=(src/'Web.cs').read_text(); a=(src/'Alerts.cs').read_text(); js=(src/'app.js').read_text()
assert json.loads((src/'default.json').read_text())['Endpoint']['WebManualQuarantineEnabled'] is False
assert 'if(!session.IsAdmin)Deny();var input=Decode<WebQuarantineInput>(r)' in w
assert 'alerts.WebQuarantineFinding(input.id,input.hash)' in w and 'currentSession.IsAdmin' in w
assert 'a.Message.EndsWith(" · SHA-256: "+hash' in a
manual=e.split('internal object QuarantineWebFinding(',1)[1].split('static bool EvidenceId',1)[0]
assert 'WHERE id=? AND hash=? AND active=1 AND change=?' in manual
assert manual.index('UserAudit.Write')<manual.index('EndpointResponse.QuarantineWebApproved')<manual.index('ConfirmAbsent(path)')<manual.index('Resolve(db,path,WebServerProtection.Finding)')
assert 'Monitor.TryEnter(scanResponseGate,150)' in manual and 'Monitor.TryEnter(vaultGate,150)' in manual
assert 'QuarantineWebApproved(' not in e.split('bool CheckFileCore(',1)[1].split('internal object QuarantineWebFinding(',1)[0]
assert 'return QuarantineCore(store,c,path,expected,stop,authorized,false' in q
core=q.split('static string QuarantineCore(',1)[1].split('internal static void DeleteSealedPayload',1)[0]
for x in ['VerifyHandle(handle,path)','if(hash!=expected)','WebServerProtection.Inspect(stream,null,stop)','else Confirmed(EndpointProtection.Command','ProtectedData.Protect','output.Flush(true)','if(!authorized()||stop.WaitOne(0))','SetFileInformationByHandle']:assert x in core,x
assert core.index('output.Flush(true)')<core.index('SetFileInformationByHandle')
html=(src/'endpoint.html').read_text();html=re.sub(r'<script\b[^>]*>.*?</script>','',html,flags=re.S|re.I);html=re.sub(r'<link\b[^>]*>','',html,flags=re.I);html=html.replace('{{admin-hidden}}','').replace('{{brand}}','LinkScope').replace('{{version}}','V84');html=html.replace('</head>','<style>'+'\n'.join((src/f).read_text() for f in ('app.css','theme.css','navigation.css','toast.css'))+'</style></head>')
js=js[:js.rindex('LinkScopeBusy.run(')]; toast=(src/'toast.js').read_text().split("    if(document.body.dataset.page==='login')return;",1)[0]+'})();'
with sync_playwright() as pw:
 browser=pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH','/usr/bin/chromium'),args=['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']);page=browser.new_page(viewport={'width':1366,'height':768});page.set_default_timeout(6000);page.set_content(html);page.add_script_tag(content=toast);page.add_script_tag(content=js+'\nwindow.LinkScopePages={attach:()=>{}};csrf="test";maintenanceLast=Date.now();setupEndpointWorkspace();')
 page.evaluate('''()=>{window.calls=[];window.reject=true;window.enabled=false;window.hash='a'.repeat(64);window.records=[{id:'script1',sequence:1,category:'endpoint_protection',severity:'warning',title:'Suspicious web script',message:'C:\\\\Web\\\\test.py · Review: synthetic marker · SHA-256: '+hash,resolved:false,read:false},{id:'process1',sequence:2,category:'endpoint_protection',severity:'warning',title:'Suspicious web server child process',message:'Test process',resolved:false,read:false}];window.fetch=async(path,options)=>{const response=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json'}});if(path==='/ui/endpoint-ack')return response({unread:2,activeUnread:2,through:2});if(path==='/ui/endpoint')return response({categories:{endpoint_protection:{result:{status:'ok',webProtection:{manualQuarantineEnabled:enabled}},ageSeconds:1}},generatedUtc:'2026-11-28T07:00:00Z',alerts:records.filter(a=>!a.resolved)});if(path==='/ui/endpoint-web-quarantine'){if(options.headers['X-CSRF-Token']!=='test')throw Error('Missing CSRF');calls.push(JSON.parse(options.body));if(reject)return response({error:'File changed since detection.'},409);records[0].resolved=true;return response({quarantined:true,detail:'Synthetic sealed evidence'});}return response({},404);};}''')
 page.evaluate('endpointLastSample={result:{webProtection:{manualQuarantineEnabled:false}}};renderEndpointAlertReview(records)');page.locator('[data-ep-tab=evidence]').click();page.locator('#endpoint-alert-diagnostics summary').click();rows=page.locator('#endpoint-alert-review-rows tbody tr');script=rows.filter(has_text='Suspicious web script');proc=rows.filter(has_text='Suspicious web server child process');assert script.get_by_role('button',name='Quarantine',exact=True).count()==0
 page.evaluate('enabled=true;endpointLastSample={result:{webProtection:{manualQuarantineEnabled:true}}};renderEndpointAlertReview(records)');assert script.get_by_role('button',name='Quarantine',exact=True).count()==1;assert proc.get_by_role('button',name='Quarantine',exact=True).count()==0
 script.get_by_role('button',name='Quarantine',exact=True).click();page.get_by_role('dialog').get_by_role('button',name='Cancel').click();assert page.evaluate('calls.length')==0
 script.get_by_role('button',name='Quarantine',exact=True).click();page.get_by_role('dialog').get_by_role('button',name='Quarantine',exact=True).click();page.wait_for_function("document.getElementById('endpoint-alert-action-status').textContent.includes('File changed since detection')");assert rows.count()==2
 page.evaluate('reject=false');script.get_by_role('button',name='Quarantine',exact=True).click();page.get_by_role('dialog').get_by_role('button',name='Quarantine',exact=True).click();page.wait_for_function("document.getElementById('endpoint-alert-action-status').textContent.includes('Suspicious script quarantined')");assert page.evaluate('calls')==[{'id':'script1','hash':'a'*64}]*2
 browser.close()
print('PASS: V84 source safety contracts and Chromium opt-in, confirmation/cancel, exact SHA-256, server rejection, success feedback and process action exclusion; simulated service only.')
