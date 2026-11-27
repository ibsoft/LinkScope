"""Execute live integrity activity and layout JS with a minimal test DOM.
The real Windows hashing and concurrency checks require running SelfCheck on Windows.
"""
from pathlib import Path
import subprocess
root=Path(__file__).resolve().parents[1];src=root/'src'
html=(src/'integrity.html').read_text();app=(src/'app.js').read_text();fim=(src/'FileIntegrity.cs').read_text();telemetry=(src/'Telemetry.cs').read_text()
assert html.index('id="metrics"')<html.index('id="integrity-live"')<html.index('id="results"')
assert 'volatile ActivityFrame activity' in fim and 'elapsed-progress.LastPublished<250' in fim
assert 'progress.BytesRead+=n;PublishActivity(c,progress)' in fim and 'progress.Files=files.Count' in fim
assert 'finally{PublishActivity(c,progress,true);}' in fim
assert 'activity=integrity.Activity(cfg.Integrity)' in telemetry
assert 'alerts.Sample("data_integrity",result,c)' in telemetry
assert 'FIM completed activity counters' in (src/'SelfCheck.cs').read_text()
code=app[app.index('let integrityLastSample='):app.index('function filterHealthCategories(){')]
js=r'''
const assert=require('node:assert/strict');
class Node{constructor(tag,text=''){this.tagName=tag;this.textContent=text;this.children=[];this.dataset={};this.className='';this.id='';this.disabled=false;}append(...nodes){this.children.push(...nodes);}replaceChildren(...nodes){this.children=nodes;}querySelectorAll(){return [];}querySelector(){return {replaceWith(){}};}}
const ids=['metrics','results','alerts','stamp','integrity-live','integrity-live-state','integrity-scan-now','integrity-hashed','integrity-excluded','integrity-errors','integrity-bytes','integrity-live-elapsed','integrity-live-time','integrity-live-file','integrity-live-updated'];
const nodes=Object.fromEntries(ids.map(id=>[id,new Node('div')]));
const byId=id=>nodes[id];const element=(tag,text='')=>new Node(tag,text);const page='integrity';const document={activeElement:null};let csrf='test';
function notice(){}function failure(e){throw e;}function revealCategory(){}function label(x){return x;}function healthKind(x){return x==='ok'?'ok':'unknown';}function categoryAlertState(a,k,r,rows,kind){return {kind,status:'test',messages:[]};}function decorateHealthSection(section,title){section.append(element('h2',title));}function alertStateLabel(k){return k;}function metric(name,v,foot,k,state){return element('card',name);}function table(rows,k){return element('table',k);}function healthBadge(){return element('span');}
const now='2026-11-27T10:00:00Z';const activity={state:'scanning',scanRunning:true,scanId:'scan-a',stage:'Hashing protected files',scanStartedUtc:now,updatedUtc:now,filesHashed:12,excludedEntries:2,reportedErrors:1,bytesRead:2048,elapsedMilliseconds:2300,currentPath:'C:\\test.txt'};
let sample={status:'collecting',activity},requests=[];async function request(path){requests.push(path);return path==='/ui/integrity-scan'?{accepted:true}:{generatedUtc:now,categories:{data_integrity:sample},alerts:[]};}
'''+code+r'''
(async()=>{
 const live=nodes['integrity-live'];await renderHealth();assert.equal(live.dataset.state,'scanning');assert.equal(nodes['integrity-hashed'].textContent,'12');assert.equal(nodes['integrity-bytes'].textContent,'2 KiB');assert(nodes['integrity-scan-now'].disabled);assert.equal(nodes.metrics.children[0].children.filter(n=>n.className==='cards integrity-metrics')[0].children.length,4);assert.equal(nodes.results.children[0].id,'integrity-evidence');
 // Keep prior verified results and active findings during the next scan.
 sample={result:{status:'ok',monitoredFiles:30,violations:1,items:[{path:'C:\\old.txt',severity:'critical'}]},activity:{...activity,filesHashed:18}};await renderHealth();assert.equal(nodes['integrity-hashed'].textContent,'18');assert.equal(nodes['integrity-live'],live);assert(nodes.results.children[0].children.some(n=>n.tagName==='table'));
 sample.activity={...activity,state:'completed',scanRunning:false,currentPath:'',scanFinishedUtc:now,nextScanUtc:'2026-11-27T10:05:00Z'};await renderHealth();assert.equal(live.dataset.state,'idle');assert(!nodes['integrity-scan-now'].disabled);assert.equal(nodes['integrity-live-file'].textContent,'');
 setupIntegrityControls();await nodes['integrity-scan-now'].onclick();assert.equal(live.dataset.state,'queued');assert.equal(requests.filter(p=>p==='/ui/integrity-scan').length,1);
 sample.activity={...activity,scanId:'scan-b'};await renderHealth();assert.equal(live.dataset.state,'scanning');
 sample.activity={...activity,state:'partial',scanRunning:false,scanId:'scan-b'};await renderHealth();assert.equal(live.dataset.state,'warning');
 csrf='';await renderHealth();assert(nodes['integrity-scan-now'].disabled);
 sample={status:'disabled',result:{status:'disabled',items:[]}};await renderHealth();assert.equal(live.dataset.state,'disabled');assert(nodes['integrity-scan-now'].disabled);
 console.log('PASS: actual integrity activity and renderer: initial collection, live counts, prior findings, fixed panel placement, completed, queued, partial, viewer, disabled.');
})().catch(e=>{console.error(e);process.exitCode=1});
'''
subprocess.run(['node','-e',js],check=True)
print('PASS: integrity activity API publication and completed-result separation (source checks).')
