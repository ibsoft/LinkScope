"""Exercise the actual endpoint renderer with mixed security/coverage alerts."""
from pathlib import Path
import subprocess
root=Path(__file__).resolve().parents[1]
app=(root/'src/app.js').read_text()
helpers=app[app.index('function healthKind('):app.index('const pct=')]
render=app[app.index('async function renderHealth(){'):app.index('function filterHealthCategories(){')]
js=r"""
const assert=require('node:assert/strict');
class Node {
 constructor(tag,text=''){this.tagName=tag.toUpperCase();this.textContent=text;this.children=[];this.dataset={};this.id='';this.className='';this.open=false;}
 append(...nodes){this.children.push(...nodes);}
 replaceChildren(...nodes){this.children=nodes;}
 querySelectorAll(s){return walk(this).filter(n=>s==='details[open]'&&n.tagName==='DETAILS'&&n.open);}
}
const walk=n=>[n,...(n.children||[]).flatMap(walk)];
const text=n=>walk(n).map(x=>x.textContent||'').join(' ');
const nodes=Object.fromEntries(['metrics','alerts','results','stamp'].map(id=>[id,new Node('div')]));
const byId=id=>nodes[id]||Object.values(nodes).flatMap(walk).find(n=>n.id===id);
const element=(tag,t='')=>new Node(tag,t);
const document={activeElement:null};const page='endpoint';
let endpointAckEpoch=0,endpointAckBusy=false,endpointAck=null,maintenanceLast=Date.now();
function endpointAckControls(){}function endpointActivity(){}function refreshEndpointMaintenance(){}function notice(){}function revealCategory(){}function label(x){return x;}
function table(rows,k){return element('table',JSON.stringify(rows));}
const fixture={status:'partial',engineOnline:true,scannedFiles:39,queueDepth:0,watcherCount:1,changedFiles:0,entropyChanges:0,canaryCount:3,violations:2,mode:'monitor',activeMalware:1,activeScanIssues:1,items:[]};
let input=[{category:'endpoint_protection',severity:'critical',title:'Malware signature detected',message:'Eicar-Test-Signature FOUND SHA-256: abc'},{category:'endpoint_protection',severity:'warning',title:'File scan error',message:'UnauthorizedAccessException: C:\\test'},{category:'endpoint_protection',severity:'warning',title:'Resolved error',message:'Do not display',resolved:true},{category:'ram',severity:'warning',title:'RAM alert',message:'Unrelated'}];
async function request(path){return path==='/ui/endpoint-ack'?{unread:0}:{generatedUtc:'2026-11-27T10:00:00Z',categories:{endpoint_protection:{result:fixture}},alerts:input};}
"""+helpers+render+r"""
(async()=>{
 await renderHealth();
 let summary=text(nodes.metrics);assert(summary.includes('Critical / Error'));assert(summary.includes('1 active malware finding'));assert(summary.includes('1 warning'));assert(!summary.includes('UnauthorizedAccessException'));assert(!summary.includes('SHA-256: abc'));
 let d=byId('endpoint-alert-diagnostics');assert(d);assert(!d.open);assert(text(d).includes('UnauthorizedAccessException'));assert(text(d).includes('Eicar-Test-Signature FOUND'));assert(!text(d).includes('Resolved error'));assert(!text(d).includes('RAM alert'));
 const link=walk(nodes.metrics).find(n=>n.href==='#endpoint-alert-diagnostics');assert(link);link.onclick();assert(d.open);
 await renderHealth();d=byId('endpoint-alert-diagnostics');assert(d.open);
 input=input.filter(a=>a.severity==='warning');fixture.activeMalware=0;await renderHealth();summary=text(nodes.metrics);assert(!summary.includes('Critical / Error'));assert(summary.includes('1 warning'));
 input=[];fixture.status='ok';fixture.activeScanIssues=0;await renderHealth();summary=text(nodes.metrics);assert(!summary.includes('View findings and diagnostics'));assert(text(byId('endpoint-alert-diagnostics')).includes('No active warning'));
 console.log('PASS: actual renderer preserves severity, moves raw messages, filters unrelated/resolved alerts, retains open state and clears summary when healthy');
})().catch(e=>{console.error(e);process.exitCode=1});
"""
subprocess.run(['node','-e',js],check=True)
