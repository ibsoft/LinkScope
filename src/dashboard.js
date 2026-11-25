
'use strict';
const $=id=>document.getElementById(id);
let period='day',selected='',data=null,sequence=0,timer;
function labelTime(t){
 const date=new Date(t*1000);
 if(period==='day')return date.toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit'});
 return date.toLocaleDateString(undefined,{month:'short',day:'numeric'});
}
function warning(text){$('warn').textContent=text;$('warn').hidden=!text;}
function row(cells){const tr=document.createElement('tr');for(const value of cells){const td=document.createElement('td');td.textContent=value;tr.append(td);}return tr;}
function render(d){
 const list=$('target'),ip=selected||d.targets[0].Address;
 list.replaceChildren(...d.targets.map(t=>new Option(t.Name+' · '+t.Address,t.Address)));list.value=ip;list.disabled=false;selected=ip;
 const t=d.targets.find(x=>x.Address===ip),last=d.latest;
 $('name').textContent=t.Name;$('details').textContent=ip+'   ·   Every '+d.interval+' s   ·   '+ranges[period]+(last?'   ·   Last probe '+local(last[0]):'');
 let state='Awaiting probe',kind='';
 if(last){if(d.now-last[0]>Math.max(3*d.interval,15)){state='Stale data';kind='bad';}
 else{state=last[1]==='Success'?'Reachable':last[1]==='TimedOut'?'Timed out':'Probe failed';kind=last[1]==='Success'?'ok':'bad';}}
 $('state').className='pill '+kind;$('state').textContent=state;
 const {ok,lost,to,err,sum,lo,hi,sent}=summarizeMetrics(d.points);
 
 $('rtt').textContent=fmt(ok?sum/ok:null,2);$('extreme').textContent=lo==null?'No successful replies':fmt(lo)+'–'+fmt(hi)+' ms range';
 $('loss').textContent=fmt(sent?100*lost/sent:null,3);$('lost').textContent=fmt(lost)+' of '+fmt(sent)+' probes';
 $('timeouts').textContent=fmt(d.points.length?to:null);$('replies').textContent=fmt(d.points.length?ok:null);$('errors').textContent=fmt(err)+' probe errors excluded from loss';
 $('nic').textContent=(d.nic||'Waiting for adapter counters')+' · Mbps';
 $('coverage').textContent=fmt(d.points.length)+' of '+fmt((d.end-d.start)/d.step)+' intervals observed · '+(d.step<3600?d.step/60+' min':d.step/3600+' h')+' per interval';
 $('zone').textContent='Display time · '+Intl.DateTimeFormat().resolvedOptions().timeZone;
 $('updated').textContent='Updated '+new Date(d.now*1000).toLocaleTimeString();
 renderFailures(d);
 warning(d.error?'Collector error · '+d.error:'');drawAll();
}
async function refresh(foreground=false){
 const done=foreground?LinkScopeBusy.begin('Loading network history…','network-history'):null;
 const token=++sequence;clearTimeout(timer);
 try{const q=new URLSearchParams({range:period});if(selected)q.set('target',selected);
 const res=await fetch('/api/history?'+q,{cache:'no-store'});if(res.status===401){location.assign('/login');return;}if(!res.ok)throw Error('HTTP '+res.status);
 const d=await res.json();if(token!==sequence)return;data=d;render(d);}
 catch(e){if(token!==sequence)return;$('updated').textContent='Update failed';$('state').textContent='Offline';$('state').className='pill bad';warning('Dashboard update failed ('+e.message+'). Retrying in 5 seconds.');}
 finally{done?.();}
 if(token===sequence)timer=setTimeout(refresh,5000);
}
function selectView(change){
 change();data=null;$('name').textContent='Loading history…';$('state').className='pill';$('state').textContent='Loading';$('details').textContent='';
 for(const id of ['rtt','extreme','loss','lost','timeouts','replies','errors','nic','coverage'])$(id).textContent='—';
 $('events').replaceChildren();$('failure-summary').replaceChildren();$('failure-count').textContent='Loading history…';drawAll();refresh(true);
}
$('target').onchange=()=>selectView(()=>selected=$('target').value);
for(const b of document.querySelectorAll('.tabs button'))b.onclick=()=>{if(b.dataset.range===period)return;selectView(()=>{period=b.dataset.range;for(const x of document.querySelectorAll('.tabs button'))x.setAttribute('aria-pressed',String(x===b));});};
const views=['latency','packet','traffic'];
function drawAll(){for(const id of views)draw(id);drawExpanded();}
function draw(id){
 const c=$(id),rect=c.getBoundingClientRect();
 drawChart(id,data,c,rect.width,rect.height,window.devicePixelRatio||1,labelTime,c.nextElementSibling);
}
const modal=$('network-modal'),expanded=$('network-modal-canvas');let expandedId=null,modalOpener=null;
function drawExpanded(){if(!modal.open||!expandedId)return;const rect=expanded.getBoundingClientRect();$('network-modal-range').textContent=ranges[period]+' · '+(expandedId==='traffic'?$('nic').textContent:selected);drawChart(expandedId,data,expanded,rect.width,rect.height,window.devicePixelRatio||1,labelTime,expanded.nextElementSibling);}
for(const id of views){const canvas=$(id),panel=canvas.closest('.panel'),heading=panel.querySelector('h2'),button=document.createElement('button');button.type='button';button.className='expand-chart';button.textContent='Expand ↗';button.setAttribute('aria-label','Expand '+heading.textContent);panel.querySelector('.panelhead').append(button);const open=()=>{if(modal.open)return;expandedId=id;modalOpener=document.activeElement;$('network-modal-title').textContent=heading.textContent;$('network-modal-legend').replaceChildren(...Array.from(panel.querySelector('.legend').children).map(x=>x.cloneNode(true)));modal.showModal();drawExpanded();$('network-modal-close').focus();};button.addEventListener('click',open);canvas.addEventListener('click',open);heading.addEventListener('click',open);heading.classList.add('clickable-chart');canvas.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();open();}});}
$('network-modal-close').onclick=()=>modal.close();modal.addEventListener('close',()=>{expandedId=null;modalOpener?.focus();});

function failureKind(status){const s=String(status).toLowerCase();if(s.startsWith('probe error:'))return 'error';if(s==='timedout')return 'timeout';if(s.includes('unreachable'))return 'unreachable';return 'other';}
const failureColors={timeout:'red',unreachable:'amber',error:'purple',other:'blue'};
const failureLabels={timeout:'Timeout',unreachable:'Unreachable',error:'Local probe error',other:'Other failure'};
function failureDescription(status){
 const raw=String(status),localError=/^probe error:/i.test(raw),code=raw.replace(/^probe error:\s*/i,'').trim().toLowerCase();
 const descriptions={
  timedout:'No ICMP reply arrived before the configured timeout. The host may be offline, congested or filtering ICMP.',
  destinationhostunreachable:'The destination host could not be reached. Check host availability, local routing and gateway connectivity.',
  destinationnetworkunreachable:'The destination network could not be reached. Check routes and gateways.',
  destinationprotocolunreachable:'The destination does not support the requested protocol.',
  destinationportunreachable:'The destination reported that the requested port is unreachable.',
  destinationunreachable:'The destination was reported unreachable. Check routing and network connectivity.',
  destinationprohibited:'Communication with the destination was administratively prohibited. Check network policy and firewall rules.',
  ttlexpired:'The packet exceeded its time-to-live in transit. Check routing paths for possible loops.',
  ttlreassemblytimeexceeded:'The destination could not reassemble packet fragments within the allowed time.',
  timeexceeded:'The packet exceeded its allowed lifetime or reassembly time.',
  packettoobig:'The packet exceeded the supported path MTU. Check MTU settings along the route.',
  badroute:'A routing error prevented the probe from completing.',
  badoption:'An invalid IP option was reported.',
  badheader:'An invalid IP header was reported.',
  baddestination:'The destination address was rejected. Check the configured target address.',
  parameterproblem:'A device reported a problem with an IP packet parameter.',
  sourcequench:'A device reported congestion using the obsolete ICMP source-quench message.',
  hardwareerror:'A local network hardware error was reported. Check the adapter and driver.',
  noresources:'Insufficient local system resources were reported.',
  generalfailure:'Windows reported a general probe failure. Check local adapter, IP configuration and network stack.',
  unknown:'Windows returned an unknown probe status.'
 };
 const detail=Object.prototype.hasOwnProperty.call(descriptions,code)?descriptions[code]:'';
 if(localError)return 'Local probe error (excluded from packet loss). '+(detail||'Windows reported: '+raw.replace(/^probe error:\s*/i,'')+'. Check the local network stack and application logs.');
 return detail||'The probe returned an unrecognized failure status. Review the raw result and application logs.';
}
function renderFailures(d){
 const all=d.searchEvents||d.events, select=$('failure-status'), prior=select.value;
 const statuses=[...new Set(all.map(e=>String(e[1])))].sort();if(prior&&!statuses.includes(prior))statuses.push(prior);
 select.replaceChildren(new Option('All results',''),...statuses.map(s=>new Option(s,s)));select.value=prior;
 const q=$('failure-query').value.trim().toLowerCase().split(/\s+/).filter(Boolean),kind=$('failure-kind').value;
 const from=$('failure-from').value,to=$('failure-to').value,lo=from?new Date(from).getTime()/1000:-Infinity,hi=to?new Date(to).getTime()/1000+59:Infinity;
 const valid=lo<=hi;const filtered=valid?all.filter(e=>{const s=String(e[1]),k=failureKind(s),hay=(local(e[0])+' '+new Date(e[0]*1000).toISOString()+' '+s+' '+failureLabels[k]+' '+failureDescription(s)).toLowerCase();return (!kind||k===kind)&&(!prior||s===prior)&&e[0]>=lo&&e[0]<=hi&&q.every(t=>hay.includes(t));}):[];
 if($('failure-sort').value==='oldest')filtered.reverse();
 const rows=filtered.map(e=>{const tr=row([local(e[0]),'',failureDescription(e[1])]);tr.cells[1].append(connBadge(e[1],failureColors[failureKind(e[1])]));return tr;});
 if(!rows.length)rows.push(row(['—',!valid?'Invalid time range: From must be before To.':all.length?'No failures match the filters.':d.points.length?'No failures recorded in this window.':'Waiting for observations.','']));
 $('events').replaceChildren(...rows);
 $('failure-summary').replaceChildren(connBadge('Total loaded · '+all.length,'neutral'),...Object.keys(failureLabels).map(k=>connBadge(failureLabels[k]+' · '+all.filter(e=>failureKind(e[1])===k).length,failureColors[k])));
 $('failure-count').textContent=filtered.length+' matching / '+all.length+' loaded'+(d.searchEventsMore?' · Limited to latest 2,000 failures; older matches may not be shown.':'')+' · Selected target and history range; maximum 48 hours.';
 LinkScopePages.attach($('failure-table'),'failures:'+d.target+':'+d.range,'Recent probe failures',!filtered.length);
}
for(const id of ['query','kind','status','from','to','sort'])$('failure-'+id).addEventListener('input',()=>{if(data)renderFailures(data);});
$('failure-clear').onclick=()=>{for(const id of ['query','kind','status','from','to'])$('failure-'+id).value='';$('failure-sort').value='newest';if(data)renderFailures(data);};
let connSnapshot=null,connTimer=null,connBusy=false,connError='';
const connFilters=['query','protocol','state','local','remote','lport','rport','family'];
function connValue(k){return $('conn-'+k).value.trim().toLowerCase();}
function endpointPort(s){return /:(\d+)$/.exec(s)?.[1]||'';}
function connBadge(value,kind){const el=document.createElement('span');el.className='conn-badge '+kind;el.textContent=value;return el;}
function stateKind(s){return ({Established:'green',Listen:'blue',Bound:'purple',TimeWait:'amber',CloseWait:'amber',SynSent:'amber',SynReceived:'amber',FinWait1:'amber',FinWait2:'amber',Closing:'amber',LastAck:'amber',Closed:'neutral',DeleteTcb:'neutral'})[s]||'neutral';}
function matchesConnection(x){const q=connValue('query'),l=x.local.toLowerCase(),r=x.remote.toLowerCase(),p=x.protocol.toLowerCase(),s=x.state.toLowerCase();return (!q||q.split(/\s+/).every(t=>[l,r,p,s].some(v=>v.includes(t))))&&(!connValue('protocol')||p===connValue('protocol'))&&(!connValue('state')||s===connValue('state'))&&l.includes(connValue('local'))&&r.includes(connValue('remote'))&&(!connValue('lport')||endpointPort(l)===connValue('lport'))&&(!connValue('rport')||endpointPort(r)===connValue('rport'))&&(!connValue('family')||(l.startsWith('[')?'6':'4')===connValue('family'));}
function renderConnections(){if(!connSnapshot)return;const all=connSnapshot.rows,filtered=all.filter(matchesConnection),body=$('connections-rows');const fragment=document.createDocumentFragment();for(const x of filtered){const tr=row(['',x.local,x.remote,'']);tr.cells[0].append(connBadge(x.protocol,x.protocol==='TCP'?'blue':'purple'));tr.cells[3].append(connBadge(x.state,stateKind(x.state)));fragment.append(tr);}if(!filtered.length)fragment.append(row(['No matching endpoints','','','']));body.replaceChildren(fragment);const summary=$('conn-summary');summary.replaceChildren(...[['TCP',all.filter(x=>x.protocol==='TCP').length,'blue'],['UDP',all.filter(x=>x.protocol==='UDP').length,'purple'],['Established',all.filter(x=>x.state==='Established').length,'green'],['Listening',all.filter(x=>x.state==='Listen').length,'blue']].map(([label,n,kind])=>connBadge(label+' · '+n,kind)));$('connections-status').textContent=(connError?connError+' Last successful snapshot: ':'')+filtered.length+' matching / '+all.length+' loaded / '+connSnapshot.total+' total · '+local(connSnapshot.now)+(all.length<connSnapshot.total?' · Snapshot capped; search covers loaded rows only.':'')+' · TCP direction is not inferred.';LinkScopePages.attach($('connections-table'),'native-connections','Network connections',!filtered.length);}
function connSchedule(){clearTimeout(connTimer);if($('conn-auto').checked&&!document.hidden&&!connBusy)connTimer=setTimeout(()=>loadConnections(false),Number($('conn-interval').value));}
function connLiveStatus(){const e=$('conn-live-status');e.textContent=$('conn-auto').checked?(document.hidden?'Tab hidden':connError?'Retrying':'Live polling'):'Paused';e.className='conn-badge '+($('conn-auto').checked&&!document.hidden?(connError?'amber':'green'):'neutral');}
async function loadConnections(manual){if(connBusy)return;clearTimeout(connTimer);connBusy=true;const b=$('connections-refresh'),status=$('connections-status');b.disabled=true;const done=manual?LinkScopeBusy.begin('Loading native network connections…','connections'):null;const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),15000);try{const res=await fetch('/ui/connections',{cache:'no-store',signal:controller.signal});if(res.status===401||res.status===403){$('conn-auto').checked=false;connSnapshot=null;$('connections-rows').replaceChildren();$('conn-summary').replaceChildren();LinkScopePages.attach($('connections-table'),'native-connections','Network connections',true);status.replaceChildren(document.createTextNode('Administrator sign-in required. '));const a=document.createElement('a');a.href='/login';a.textContent='Sign in';status.append(a);return;}if(!res.ok)throw Error('HTTP '+res.status);connSnapshot=await res.json();connError='';renderConnections();}catch(e){connError='Connection snapshot unavailable ('+e.message+').';if(connSnapshot)renderConnections();else status.textContent=connError;}finally{clearTimeout(timeout);connBusy=false;b.disabled=false;done?.();connLiveStatus();connSchedule();}}
$('connections-refresh').onclick=()=>loadConnections(true);
for(const k of connFilters)$('conn-'+k).addEventListener('input',renderConnections);
$('conn-clear').onclick=()=>{for(const k of connFilters)$('conn-'+k).value='';renderConnections();};
$('conn-auto').onchange=()=>{connLiveStatus();clearTimeout(connTimer);if($('conn-auto').checked&&!document.hidden)loadConnections(false);};
$('conn-interval').onchange=connSchedule;
document.addEventListener('visibilitychange',()=>{connLiveStatus();clearTimeout(connTimer);if(!document.hidden&&$('conn-auto').checked)loadConnections(false);});
window.addEventListener('resize',drawAll);refresh(true);
