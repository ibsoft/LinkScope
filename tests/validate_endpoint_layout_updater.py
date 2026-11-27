"""Regression tests for rendered summary placement and updater wait wiring.
Node tests execute the actual renderHealth function with a minimal mock DOM;
Windows SCM, process shutdown and physical browser rendering are not exercised.
"""
from pathlib import Path
import re, subprocess
root=Path(__file__).resolve().parents[1]
html=(root/'src/endpoint.html').read_text()
app=(root/'src/app.js').read_text()
worker=(root/'src/ClamUpdateWorker.cs').read_text()
setup=(root/'setup/ClamSetup.cs').read_text()
css=(root/'src/theme.css').read_text()
assert 'id="metrics" class="endpoint-summary"' in html
assert html.index('id="metrics"')<html.index('id="endpoint-live"')<html.index('id="results"')
assert '/assets/app-signature-schedule-v17.js' in html
assert 'Asset("/assets/app-signature-schedule-v17.js","app.js","application/javascript")' in (root/'src/Web.cs').read_text()
render=app[app.index('async function renderHealth(){'):app.index('function filterHealthCategories(){')]
js=r'''
const assert=require('node:assert/strict');
class Node {
 constructor(tag,text=''){this.tagName=tag;this.textContent=text;this.children=[];this.dataset={};this.id='';this.className='';}
 append(...nodes){this.children.push(...nodes);}
 replaceChildren(...nodes){this.children=nodes;}
 querySelectorAll(){return [];}
}
const nodes=Object.fromEntries(['metrics','alerts','results','stamp','endpoint-live'].map(id=>[id,new Node('div')]));
const byId=id=>nodes[id];const element=(tag,t='')=>new Node(tag,t);
const document={activeElement:null};const page='endpoint';
let endpointAckEpoch=0,endpointAckBusy=false,endpointAck=null,maintenanceLast=Date.now();
function endpointAckControls(){}function endpointActivity(){}function refreshEndpointMaintenance(){}
function notice(){}function revealCategory(){}function label(x){return x;}
function healthKind(s){return s==='ok'?'ok':'unknown';}
function categoryAlertState(a,k,r,rows,kind){return {kind,status:'No active alerts',messages:[]};}
function decorateHealthSection(section,title){section.append(element('h2',title));}
function alertStateLabel(k){return k;}
function metric(name,v,foot,k,state){return element('card',name);}
function table(rows,k){return element('table',k);}
const live=nodes['endpoint-live'];const fixture={status:'ok',engineOnline:true,scannedFiles:16,queueDepth:0,watcherCount:1,changedFiles:0,entropyChanges:0,canaryCount:3,violations:0,mode:'monitor',cleanChecks:16,infectedChecks:0,heuristicChecks:0,excludedChecks:2,failedChecks:0,quarantinedChecks:0,scanActivity:[{path:'test.txt'}]};
async function request(path){return path==='/ui/endpoint-ack'?{unread:0}:{generatedUtc:'2026-11-27T10:00:00Z',categories:{endpoint_protection:{result:fixture}},alerts:[]};}
'''+render+r'''
(async()=>{
 await renderHealth();
 assert.equal(nodes.metrics.children.length,1);
 const summary=nodes.metrics.children[0];assert.equal(summary.id,'category-endpoint_protection');
 const groups=summary.children.filter(n=>n.className==='cards integrity-metrics');
 assert.deepEqual(groups.map(n=>n.children.length),[8,6]);
 assert.equal(nodes.results.children.length,1);
 const evidence=nodes.results.children[0];assert.equal(evidence.id,'endpoint-evidence');
 assert(evidence.children.some(n=>n.textContent==='Live file scan activity (latest 100)'));
 assert(!evidence.children.some(n=>n.className==='cards integrity-metrics'));
 await renderHealth();assert.equal(nodes['endpoint-live'],live);assert.equal(nodes.metrics.children.length,1);assert.equal(nodes.results.children.length,1);
 fixture.status='disabled';await renderHealth();assert.equal(nodes.metrics.children.length,0);assert.equal(nodes.results.children[0].id,'category-endpoint_protection');
 console.log('PASS: actual renderHealth places 8 summary and 6 scan statistic cards above stable activity controls; evidence below; repeat/disabled refresh');
})().catch(e=>{console.error(e);process.exitCode=1});
'''
subprocess.run(['node','-e',js],check=True)
assert '15px/1.3' in css and 'font-size:16px;min-height:44px' in css
assert 'nav.scrollWidth>nav.clientWidth' in (root/'src/theme.js').read_text()
# The worker uses a bounded wait with consecutive quiet observations, not process killing.
wait=worker.split('static void WaitForFreshClamIdle(',1)[1].split('internal static void WaitForFreshClamServiceOnly',1)[0]
for marker in ['Stopwatch.StartNew()','ServicePid("freshclam")','FreshClamPids().Where','++quiet>=2','Thread.Sleep(500)','TimeSpan.FromSeconds(seconds)','PIDs:','No updater process was terminated.']:
    assert marker in wait,marker
assert '.Kill(' not in wait
editor=setup.split('static int EditProviderSources',1)[1].split('static int UpdateClamSignatures',1)[0]
assert editor.index('WaitForFreshClamServiceOnly(log,120)')<editor.index('updater.Stop()')<editor.index('WaitForFreshClamExit(log,120)')<editor.index('File.Replace(temp,FreshConfig,backup)')
assert 'WaitForFreshClamExit(log,5);\n                        updater.Start()' in editor
assert 'restarting the previous FreshClam service' in editor
update=worker.split('internal static int Update(TextWriter log,bool enforceCooldown)',1)[1]
assert update.index('WaitForFreshClamServiceOnly(log,120)')<update.index('svc.Stop()')<update.index('WaitForFreshClamExit(log,120)')<update.index('DatabaseFingerprint()')
print('PASS: bounded updater waits, service PID exclusion, safe restart/rollback order and no-wrap menu font settings (source checks)')
