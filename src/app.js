'use strict';
const byId=id=>document.getElementById(id);
const page=document.body.dataset.page;
const labels={endpoint_protection:"Endpoint Protection",data_integrity:'Data Integrity & Tamper Detection',ram:'RAM',cpu:'CPU',disk_usage:'Disk usage',smart:'Disk health and SSD life',events:'Event logs · last 24 hours',firewall:'Firewall profiles',antivirus:'Antivirus',security:'Security posture',event_details:'Event message text',ip_addresses:'IP addresses',dns:'DNS',bios:'BIOS',usb:'USB',os:'Operating system'};
const label=s=>labels[s]||s.replace(/_/g,' ').replace(/^./,c=>c.toUpperCase());
const element=(tag,text)=>{const e=document.createElement(tag);if(text!=null)e.textContent=text;return e;};
// Shared, asynchronous confirmation dialog. Never invoke browser-native prompts.
let activeConfirmation = false;
function confirmAction(title, message, action, destructive = false) {
    if (activeConfirmation) return Promise.resolve(false);
    const dialog = element('dialog');
    dialog.className = 'ls-confirm-dialog';
    dialog.setAttribute('aria-labelledby', 'ls-confirm-title');
    dialog.setAttribute('aria-describedby', 'ls-confirm-message');
    const heading = element('h2', title); heading.id = 'ls-confirm-title';
    const description = element('p', message); description.id = 'ls-confirm-message';
    const footer = element('div'); footer.className = 'ls-confirm-actions';
    const cancel = element('button', 'Cancel'); cancel.type = 'button'; cancel.className = 'secondary'; cancel.autofocus = true;
    const accept = element('button', action); accept.type = 'button';
    if (destructive) accept.className = 'ls-confirm-danger';
    footer.append(cancel, accept); dialog.append(heading, description, footer);
    const previous = document.activeElement;
    return new Promise(resolve => {
        let settled = false;
        function finish(approved) {
            if (settled) return;
            settled = true; activeConfirmation = false;
            if (dialog.open) dialog.close();
            dialog.remove();
            if (previous && previous.isConnected) previous.focus();
            resolve(approved);
        }
        cancel.addEventListener('click', () => finish(false));
        accept.addEventListener('click', () => finish(true));
        dialog.addEventListener('cancel', event => { event.preventDefault(); finish(false); });
        dialog.addEventListener('close', () => finish(false));
        activeConfirmation = true;
        document.body.append(dialog);
        try { dialog.showModal(); cancel.focus(); }
        catch (error) { finish(false); failure(error); }
    });
}
let csrf='';
async function request(url,data){
    const options={cache:'no-store',credentials:'same-origin',redirect:'error'};
    if(data!==undefined){
        options.method='POST';options.headers={'Content-Type':'application/json','X-CSRF-Token':csrf};options.body=JSON.stringify(data);
    }
    const response=await fetch(url,options);
    const result=await response.json();
    if(!response.ok){
        if(response.status===401&&page!=='login')location.assign(page==='settings'&&location.hash==='#siem'?'/login#siem':'/login');
        throw new Error(result.error||'Request failed');
    }
    return result;
}
const notice=(text,severity='success')=>{byId('notice').textContent=text;if(text&&window.LinkScopeToast)window.LinkScopeToast.message(severity,severity==='error'?'Action failed':'LinkScope',text);};
const failure=ex=>notice(ex.message||String(ex),'error');
function table(rows,key){
    const container=element('div');container.className='tablewrap';if(!rows.length){container.append(element('small','No records in this sample.'));return container;}
    const keys=[...new Set(rows.flatMap(row=>Object.keys(row)))];const t=element('table'),head=t.createTHead().insertRow(),body=t.createTBody();
    const endpointHeaders={utc:'Timestamp',firstUtc:'First detected',lastUtc:'Last detected',durationMs:'Duration (ms)',actualHash:'Actual SHA-256',expectedHash:'Expected SHA-256',result:'Result',path:'File / path',source:'Scan type',severity:'Severity',detail:'Details',status:'Status',hash:'SHA-256',change:'Detection'};
    keys.forEach(k=>head.append(element('th',page==='endpoint'?(endpointHeaders[k]||k):k)));
    for(const row of rows){const tr=body.insertRow();for(const k of keys){const v=row[k];const cell=tr.insertCell(),stamp=page==='endpoint'&&/^(utc|.*Utc)$/.test(k)&&typeof v==='string'&&Number.isFinite(Date.parse(v)),text=v==null?'—':stamp?new Date(v).toLocaleString():typeof v==='object'?JSON.stringify(v):String(v);if(stamp)cell.title=v;const kind=(page==='system'||page==='integrity'||page==='endpoint')?healthCellKind(key,k,v):null;if(kind)cell.append(healthBadge(text,kind));else cell.textContent=text;}}
    container.append(t);LinkScopePages.attach(t,key,label(key),false,page==='system'||page==='integrity'||page==='endpoint');return container;
}
function checkboxList(id,options,selected){
    byId(id).replaceChildren(...options.map(k=>{const lab=element('label');const box=element('input');box.type='checkbox';box.value=k;box.checked=selected.includes(k);lab.append(box,document.createTextNode(' '+label(k)));return lab;}));
}
const checked=id=>Array.from(byId(id).querySelectorAll('input:checked'),c=>c.value);
const numbers=['CpuAlertPercent','RamAlertPercent','DiskAlertPercent','ProbeAlertCount','NetworkCardHours','Port','IntervalSeconds','TimeoutMs','ResourceSeconds','InventoryMinutes','LowLifePercent','EventsPerChannel'];
const strings=['BrandLabel','BindAddress','HostName','InterfaceName','CertificateThumbprint'];
const flags=['RequireLogin','UseHttps','WriteDiskEvents'];
let config;
function certFields(){
    const enabled=byId('UseHttps').checked;
    byId('HostName').disabled=!enabled;byId('certMode').disabled=!enabled;
    byId('CertificateThumbprint').disabled=!enabled||byId('certMode').value!=='custom';
    byId('CertificateThumbprint').required=enabled&&byId('certMode').value==='custom';
}
function tokenRows(tokens){
    const list=byId('tokenList');list.replaceChildren();
    if(!tokens.length){list.append(element('p','No API tokens.'));return;}
    const t=element('table'),h=t.createTHead().insertRow(),body=t.createTBody();
    ['Client','Expires','Categories',''].forEach(x=>h.append(element('th',x)));
    tokens.forEach(k=>{const r=body.insertRow();[k.name,new Date(k.expires*1000).toLocaleDateString(),k.categories.map(label).join(', ')].forEach(x=>r.insertCell().textContent=x);
        const b=element('button','Revoke');b.className='secondary';b.onclick=async()=>{const done=LinkScopeBusy.begin('Revoking token…');try{await request('/ui/tokens/revoke',{id:k.id});await refreshTokens();notice('Token revoked.');}catch(ex){failure(ex);}finally{done();}};r.insertCell().append(b);});
    list.append(t);LinkScopePages.attach(t,'tokens','API tokens');
}
async function refreshTokens(){tokenRows((await request('/ui/settings')).tokens);}
const targetRules=new Map();
function targetLines(){
    return byId('targets').value.split(/\r?\n/).map(s=>s.trim()).filter(Boolean).map(s=>{
        const m=/^(\S+)(?:\s+(.*))?$/.exec(s);return {Address:m[1],Name:m[2]||m[1]};
    });
}
function renderRules(){
    const body=byId('probe-rules').tBodies[0];body.replaceChildren();
    for(const t of targetLines()){
        if(!targetRules.has(t.Address))targetRules.set(t.Address,{AlertsEnabled:true,FailureCount:null,HighRttMs:null,LossPercent:null,LossWindowProbes:20});
        const rules=targetRules.get(t.Address),row=body.insertRow();row.insertCell().textContent=t.Name===t.Address?t.Address:t.Name+' · '+t.Address;
        const enabled=element('input');enabled.type='checkbox';enabled.checked=rules.AlertsEnabled!==false;enabled.setAttribute('aria-label','Enable alerts for '+t.Address);
        enabled.onchange=()=>{rules.AlertsEnabled=enabled.checked;};row.insertCell().append(enabled);
        for(const [key,min,max,label] of [['FailureCount',0,100,'Consecutive failures'],['HighRttMs',1,30000,'RTT threshold'],['LossPercent',1,100,'Packet loss threshold'],['LossWindowProbes',2,1000,'Loss window']]){
            const field=element('input');field.type='number';field.min=min;field.max=max;field.step=1;field.value=rules[key]??(key==='LossWindowProbes'?20:'');
            field.required=key==='LossWindowProbes';field.placeholder=key==='FailureCount'?'Default':'Off';field.setAttribute('aria-label',label+' for '+t.Address);
            field.oninput=()=>{rules[key]=field.value===''?null:Number(field.value);};row.insertCell().append(field);
        }
    }
    LinkScopePages.attach(byId('probe-rules'),'rules','Network probe rules');
}
const deliveryStrings=['SmtpHost','Encryption','Authentication','Username','From','SenderName','To','Cc','Bcc','ReplyTo','SubjectPrefix','JsonDirectory'];
const deliveryNumbers=['SmtpPort','TimeoutSeconds','MaxJsonFiles'];
const deliveryFlags=['EmailEnabled','EmailRecovery','JsonEnabled'];
function deliveryInput(){
    const d={};
    deliveryStrings.forEach(k=>d[k]=byId(k).value.trim());
    deliveryNumbers.forEach(k=>d[k]=Number(byId(k).value));
    deliveryFlags.forEach(k=>d[k]=byId(k).checked);
    return {Delivery:d,NewSmtpPassword:byId('NewSmtpPassword').value,ClearSmtpPassword:byId('ClearSmtpPassword').checked};
}
let announceSmtpResult=false;
function showOutputStatus(st){
    if(st.logStatus)byId('log-delivery-status').textContent='Local log · '+st.logStatus.local+'   |   Syslog · '+st.logStatus.syslog;
    if(st.logStatus)showSiemStatus(st.logStatus.siem);
    if(announceSmtpResult&&(st.testState==='accepted'||st.testState==='failed')){
        announceSmtpResult=false;window.LinkScopeToast?.message(st.testState==='accepted'?'success':'error','SMTP test',st.testMessage);
    }
    byId('smtp-test-status').textContent=st.testState==='idle'?'':st.testMessage;
    byId('smtp-test').disabled=st.testState==='running';
    byId('smtp-delivery-status').textContent='Email delivery · '+st.email+' · '+st.queued+' queued';
    byId('file-delivery-status').textContent='JSON output · '+st.files;
}
let outputTimer,outputGeneration=0;
function pollOutput(delay){
    clearTimeout(outputTimer);const generation=++outputGeneration;
    outputTimer=setTimeout(async()=>{
        let next=15000;
        try{const st=await request('/ui/alert-delivery');
            if(generation!==outputGeneration)return;
            showOutputStatus(st);next=st.testState==='running'?1000:15000;
        }catch(e){if(generation===outputGeneration)byId('smtp-test-status').textContent='Could not refresh delivery status. Retrying…';}
        if(generation===outputGeneration)pollOutput(next);
    },delay);
}
async function testSmtp(){
    byId('smtp-test').disabled=true;byId('smtp-test-status').textContent='Starting test…';
    clearTimeout(outputTimer);++outputGeneration;
    try{await LinkScopeBusy.run('Starting SMTP test…',()=>request('/ui/smtp-test',deliveryInput()));announceSmtpResult=true;byId('smtp-test-status').textContent='Test in progress…';pollOutput(300);}
    catch(e){window.LinkScopeToast?.message('error','SMTP test',e.message);byId('smtp-test-status').textContent=e.message;byId('smtp-test').disabled=false;pollOutput(15000);}
}
function fillDelivery(model){
    const d=model.config.Delivery;
    [...deliveryStrings,...deliveryNumbers].forEach(k=>byId(k).value=d[k]??'');
    deliveryFlags.forEach(k=>byId(k).checked=d[k]);
    byId('NewSmtpPassword').value='';byId('ClearSmtpPassword').checked=false;
    byId('smtp-password-hint').textContent=model.smtpPasswordStored?'Password saved. Leave blank to keep it. Re-enter or clear it when changing the server or username.':'No SMTP password saved.';
    byId('JsonDirectory').placeholder=model.defaultJsonDirectory;
    showOutputStatus(model.outputStatus);pollOutput(model.outputStatus.testState==='running'?1000:15000);
}
let aiModel,aiDrafts={},aiSelected='';
function showAiProfile(id){
    aiSelected=id;const p=aiDrafts[id]||{};
    byId('AiModel').value=p.Model||'';byId('AiBase').value=p.BaseUrl||'';
    const remote=['compatible','azure','bedrock'].includes(id);
    byId('AiBaseField').hidden=!remote;byId('AiBase').disabled=!remote;
    byId('AiBase').placeholder=id==='azure'?'https://RESOURCE.openai.azure.com/openai/v1':id==='bedrock'?'https://bedrock-runtime.eu-central-1.amazonaws.com':'https://gateway.example.org/v1';
    byId('AiKey').value='';byId('AiClear').checked=false;
    byId('AiKeyHint').textContent=aiModel.aiKeyStored?.[id]?'Key saved. Leave blank to keep it.':'No key saved for this provider.';
}
function fillAi(model){
    aiModel=model;aiDrafts={...model.config.Ai.Profiles};
    byId('AiEnabled').checked=model.config.Ai.Enabled;byId('AiProvider').value=model.config.Ai.Provider;
    showAiProfile(model.config.Ai.Provider);
}
function stashAi(){aiDrafts[aiSelected]={Model:byId('AiModel').value.trim(),BaseUrl:byId('AiBase').disabled?'':byId('AiBase').value.trim()};}
function readAi(){
    stashAi();return {Ai:{Enabled:byId('AiEnabled').checked,Provider:aiSelected,Profiles:aiDrafts},NewAiKey:byId('AiKey').value,ClearAiKey:byId('AiClear').checked};
}
const logFields=['MinimumLevel','RetentionDays','SyslogEnabled','SyslogHost','SyslogTransport','SyslogPort','SyslogFacility','SyslogMinimumLevel'];
function fillLogs(model){
    const d=model.config.Logging;
    for(const k of logFields){if(k==='SyslogEnabled')byId(k).checked=d[k];else byId(k).value=d[k];}
    if(model.logStatus)byId('log-delivery-status').textContent='Local log · '+model.logStatus.local+'   |   Syslog · '+model.logStatus.syslog;
}
function readLogs(){
    const d={};
    for(const k of logFields)d[k]=k==='SyslogEnabled'?byId(k).checked:['RetentionDays','SyslogPort','SyslogFacility'].includes(k)?Number(byId(k).value):byId(k).value.trim();
    return d;
}
const receivers=['Seq','Wazuh','Elastic'];
let formDirty=false,waitingRestart=false;
function showSiemStatus(status){
    if(status)for(const name of receivers)byId(name+'Status').textContent=status[name]||'';
}
function fillSiem(model){
    for(const name of receivers){
        const cfg=model.config.Siem[name];
        byId(name+'Enabled').checked=cfg.Enabled;
        byId(name+'MinimumLevel').value=cfg.MinimumLevel;
        byId(name+'Test').disabled=!cfg.Enabled;
        if(name==='Wazuh'){
            for(const field of ['Host','Port','Transport'])byId(name+field).value=cfg[field];
        }else{
            byId(name+'BaseUrl').value=cfg.BaseUrl;byId(name+'Key').value='';byId(name+'Clear').checked=false;
            byId(name+'KeyHint').textContent=model[name.toLowerCase()+'KeyStored']?'Key saved. Leave blank to keep it.':'No ingestion key saved.';
            if(name==='Elastic')byId('ElasticIndex').value=cfg.Index;
        }
    }
    showSiemStatus(model.logStatus.siem);
}
function readSiem(){
    const edit={Siem:{}};
    for(const name of receivers){
        const cfg={Enabled:byId(name+'Enabled').checked,MinimumLevel:byId(name+'MinimumLevel').value};
        if(name==='Wazuh'){
            cfg.Host=byId('WazuhHost').value.trim();cfg.Port=Number(byId('WazuhPort').value);cfg.Transport=byId('WazuhTransport').value;
        }else{
            cfg.BaseUrl=byId(name+'BaseUrl').value.trim();edit['New'+name+'Key']=byId(name+'Key').value;
            edit['Clear'+name+'Key']=byId(name+'Clear').checked;
            if(name==='Elastic')cfg.Index=byId('ElasticIndex').value.trim();
        }
        edit.Siem[name]=cfg;
    }
    return edit;
}
async function testSiem(name){
    const feedback=byId(name+'TestResult'),button=byId(name+'Test');
    if(formDirty){feedback.textContent='Save settings before testing this receiver.';return;}
    button.disabled=true;
    try{
        const r=await LinkScopeBusy.run('Queuing test event…',()=>request('/ui/siem-test',{Receiver:name}));
        feedback.textContent='Test queued. Search the receiver for event ID '+r.eventId+'.';
    }catch(e){feedback.textContent=e.message;}
    finally{button.disabled=!config.Siem[name].Enabled;}
}
function showRestart(model){
    byId('probe-restart').hidden=!model.restartRequired;
    byId('restart-service').hidden=!model.canRestart;
    byId('restart-login').hidden=true;
    byId('restart-status').textContent=model.canRestart?'Saved changes take effect after a service restart.':'Restart the console process on the monitoring host to apply saved changes.';
}
async function restartService(){
    if(waitingRestart)return;
    const button=byId('restart-service'),status=byId('restart-status'),link=byId('restart-login');
    if(formDirty){status.textContent='Save your changes before restarting LinkScope.';return;}
    if(!(await confirmAction('Restart LinkScope?', 'Monitoring will pause briefly while saved settings are applied. Dashboard users will need to sign in again.', 'Restart service')))return;
    waitingRestart=true;button.disabled=true;
    const done=LinkScopeBusy.begin('Restarting LinkScope…');
    try{
        const before=await request('/ui/restart',{});
        const listenerChanging=before.activeOrigin!==before.nextOrigin;
        link.href=(listenerChanging?new URL(before.nextOrigin).origin:location.origin)+'/login#network';
        link.hidden=false;
        if(listenerChanging){status.textContent='Restart requested. Open the dashboard at '+before.nextOrigin+' and sign in when it is ready.';return;}
        status.textContent='Restart requested. Waiting for LinkScope to come back…';
        const deadline=Date.now()+120000;
        while(Date.now()<deadline){
            await new Promise(resolve=>setTimeout(resolve,1500));
            const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),2500);
            try{
                const response=await fetch('/ui/session',{cache:'no-store',credentials:'same-origin',signal:controller.signal});
                if(response.ok){const session=await response.json();if(session.instanceId&&session.instanceId!==before.instanceId){location.assign(link.href);return;}}
            }catch(e){/* The listener is briefly unavailable during the restart. */}
            finally{clearTimeout(timeout);}
        }
        status.textContent='Restart not confirmed. Check Get-Service LinkScope on the monitoring host, then reopen the dashboard.';
    }catch(e){status.textContent=e.message;}
    finally{done();waitingRestart=false;button.disabled=false;}
}
function exportCategoryState(){
    byId('telemetry-export-categories').querySelectorAll('input').forEach(x=>x.disabled=byId('TelemetryExportFull').checked);
}
function fillTelemetryExport(model){
    const e=model.config.TelemetryExport;
    byId('TelemetryExportEnabled').checked=e.Enabled;byId('TelemetryExportInterval').value=e.IntervalSeconds;
    byId('TelemetryExportDirectory').value=e.Directory;byId('TelemetryExportFull').checked=e.Full;
    checkboxList('telemetry-export-categories',model.telemetryExportCategories,e.Categories);exportCategoryState();
    const st=model.telemetryExportStatus;byId('telemetry-export-status').textContent=st.status+' · '+st.path+(st.lastSuccessUtc?' · Last successful: '+st.lastSuccessUtc:'');
}
function readTelemetryExport(){return {Enabled:byId('TelemetryExportEnabled').checked,IntervalSeconds:Number(byId('TelemetryExportInterval').value),Directory:byId('TelemetryExportDirectory').value.trim(),Full:byId('TelemetryExportFull').checked,Categories:checked('telemetry-export-categories')};}
function readDatabaseMaintenance(){return {Enabled:byId('DatabaseMaintenanceEnabled').checked,Age:Number(byId('DatabaseMaintenanceAge').value),Unit:byId('DatabaseMaintenanceUnit').value,KeepLatestMonth:byId('DatabaseMaintenanceKeepMonth').checked};}
function maintenanceFields(){const d=readDatabaseMaintenance();byId('DatabaseMaintenanceAge').max={days:3650,months:120,years:10}[d.Unit];byId('RetentionDays').disabled=d.Enabled;}
function showMaintenanceStatus(s){if(!s)return;byId('database-maintenance-status').textContent=s.status+(s.cutoffUtc?' · Delete before '+new Date(s.cutoffUtc).toLocaleString():'')+(s.lastSuccessUtc?' · Last successful: '+new Date(s.lastSuccessUtc).toLocaleString():'')+' · Last run rows removed: history '+s.historyDeleted+', alerts '+s.alertsDeleted+', logs '+s.logsDeleted;byId('DatabaseMaintenanceRun').disabled=!!s.busy||!config||!config.DatabaseMaintenance.Enabled;}
function fillDatabaseMaintenance(model){const d=model.config.DatabaseMaintenance;byId('DatabaseMaintenanceEnabled').checked=d.Enabled;byId('DatabaseMaintenanceAge').value=d.Age;byId('DatabaseMaintenanceUnit').value=d.Unit;byId('DatabaseMaintenanceKeepMonth').checked=d.KeepLatestMonth;maintenanceFields();showMaintenanceStatus(model.databaseMaintenanceStatus);}
async function refreshMaintenance(){try{showMaintenanceStatus(await request('/ui/database-maintenance'));}catch(ex){byId('database-maintenance-status').textContent=ex.message;}}
async function runMaintenance(){if(formDirty){notice('Save settings before running database cleanup.','error');return;}if(!(await confirmAction('Run database cleanup?', 'Records older than the saved retention period will be permanently deleted. Make sure you have a current backup.', 'Delete old records', true)))return;try{await request('/ui/database-maintenance',{});notice('Database cleanup queued.');await refreshMaintenance();}catch(ex){failure(ex);}}
const integrityLines=id=>byId(id).value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
function readIntegrity(){return {Enabled:byId('IntegrityEnabled').checked,IntervalSeconds:Number(byId('IntegrityInterval').value),Recursive:byId('IntegrityRecursive').checked,WriteEvents:byId('IntegrityWriteEvents').checked,Paths:integrityLines('IntegrityPaths'),ExcludedPaths:integrityLines('IntegrityExcludedPaths'),ExcludedPatterns:integrityLines('IntegrityExcludedPatterns')};}
const endpointFlags=['Enabled','WriteEvents','RealTime','ProcessCorrelation','SignatureScheduleEnabled'];
const endpointNumbers={IntervalSeconds:'EndpointInterval',ChangeThreshold:'EndpointThreshold',Port:'EndpointPort',MaxFileMiB:'EndpointMaxFileMiB',BehaviorWindowSeconds:'EndpointBehaviorWindowSeconds'};
const endpointArrays=['Paths','ExcludedPaths','ExcludedPatterns','CanaryPaths','ResponsePaths','ContainmentExecutables'];
function fillEndpoint(c){const e=c.Endpoint;for(const k of endpointFlags)byId('Endpoint'+k).checked=!!e[k];for(const [k,id] of Object.entries(endpointNumbers))byId(id).value=e[k];for(const k of endpointArrays)byId('Endpoint'+k).value=(e[k]||[]).join('\n');byId('EndpointMode').value=e.Mode;byId('EndpointTrustedEnginePath').value=e.TrustedEnginePath||'';byId('EndpointTrustedEngineSha256').value=e.TrustedEngineSha256||'';byId('EndpointSignatureScheduleFrequency').value=e.SignatureScheduleFrequency||'daily';byId('EndpointSignatureScheduleTime').value=e.SignatureScheduleTime||'03:00';byId('EndpointSignatureScheduleWeekday').value=String(e.SignatureScheduleWeekday??1);byId('EndpointSignatureScheduleMonthDay').value=e.SignatureScheduleMonthDay??1;signatureScheduleFields();}
function signatureScheduleFields(){const enabled=byId('EndpointSignatureScheduleEnabled').checked,f=byId('EndpointSignatureScheduleFrequency').value;byId('signature-schedule-fields').hidden=!enabled;byId('signature-weekday-field').hidden=f!=='weekly';byId('signature-monthday-field').hidden=f!=='monthly';for(const id of ['Frequency','Time','Weekday','MonthDay'])byId('EndpointSignatureSchedule'+id).disabled=!enabled||(id==='Weekday'&&f!=='weekly')||(id==='MonthDay'&&f!=='monthly');byId('signature-schedule-summary').textContent=enabled?'Saved schedules run while Endpoint Protection is enabled and LinkScope is installed as a Windows service. Next run appears under Endpoint Protection → Signature maintenance.':'No additional LinkScope-scheduled updates.';}
let endpointResponseSuggestions={paths:[],executables:[],engine:null};
// These controls prepare a draft only. The existing administrator-only Save settings
// confirmation and server-side response policy validation remain mandatory.
function responseUnder(path,root){const p=path.toLowerCase().replace(/\\+$/,'');const r=root.toLowerCase().replace(/\\+$/,'');return p===r||p.startsWith(r+'\\');}
function fillResponseOptions(id,values,empty){
    const select=byId(id),previous=select.value;
    select.replaceChildren(new Option(values.length?'Select application path…':empty,''),...values.map(x=>new Option(x,x)));
    select.value=values.includes(previous)?previous:values.length===1?values[0]:'';
    select.disabled=!values.length;
}
function updateResponseSuggestions(){
    const selectedPaths=integrityLines('EndpointResponsePaths'),protectedPaths=integrityLines('EndpointPaths');
    const allowed=endpointResponseSuggestions.paths.filter(p=>protectedPaths.some(r=>responseUnder(p,r)));
    const executable=endpointResponseSuggestions.executables.filter(p=>protectedPaths.some(r=>responseUnder(p,r))&&selectedPaths.some(r=>responseUnder(p,r)));
    fillResponseOptions('EndpointSuggestedResponse',allowed,'No eligible saved application paths');
    fillResponseOptions('EndpointSuggestedExecutable',executable,'Choose a response path first');
    byId('EndpointAddSuggestedResponse').disabled=!byId('EndpointSuggestedResponse').value;
    byId('EndpointAddSuggestedExecutable').disabled=!byId('EndpointSuggestedExecutable').value;
    byId('EndpointResponsePaths').placeholder=allowed.length?'Suggested: '+allowed[0]:'Save a non-system protected application path first';
    byId('EndpointContainmentExecutables').placeholder=executable.length?'Suggested: '+executable[0]:'Enter an exact eligible EXE path';
    byId('EndpointResponseSuggestionStatus').textContent=allowed.length?'Select a suggested path or executable to add to the draft policy. No permissions are granted until you save.':'No eligible saved application paths were found. Add and save a non-system protected directory first.';
}
function loadResponseSuggestions(model){
    const s=model.endpointResponseSuggestions||{};
    const engine=s.engine&&typeof s.engine.path==='string'&&/^[a-f0-9]{64}$/i.test(s.engine.sha256||'')?s.engine:null;
    endpointResponseSuggestions={paths:Array.isArray(s.paths)?s.paths:[],executables:Array.isArray(s.executables)?s.executables:[],engine};
    updateResponseSuggestions();updateEngineSuggestion();
}
function updateEngineSuggestion(){
    const e=endpointResponseSuggestions.engine,path=byId('EndpointTrustedEnginePath').value.trim(),pin=byId('EndpointTrustedEngineSha256').value.trim();
    const available=!!e&&!pin&&(!path||path.toLowerCase()===e.path.toLowerCase());
    byId('EndpointUseDetectedEngine').disabled=!available;
    byId('EndpointDetectedEngineStatus').textContent=available?'Detected '+e.path+' · SHA-256 calculated. Verify authenticity before accepting.':pin?'A SHA-256 pin is already set. It will not be replaced automatically.':'No eligible standard ClamD suggestion. Enter a verified executable path and hash manually.';
}
async function useDetectedEngine(){
    const e=endpointResponseSuggestions.engine;if(!e||byId('EndpointUseDetectedEngine').disabled)return;
    if(!(await confirmAction('Use detected ClamD executable?',e.path+'\nSHA-256: '+e.sha256+'\nAccept only if you have verified the authenticity of your installed ClamAV package. This fills the draft fields; it does not enable automatic response.','Use detected values')))return;
    const path=byId('EndpointTrustedEnginePath'),pin=byId('EndpointTrustedEngineSha256');
    if(pin.value.trim()||(path.value.trim()&&path.value.trim().toLowerCase()!==e.path.toLowerCase()))return;
    path.value=e.path;pin.value=e.sha256;pin.dispatchEvent(new Event('input',{bubbles:true}));updateEngineSuggestion();
}
function addResponseSuggestion(selectId,fieldId){
    const path=byId(selectId).value;if(!path)return;
    const field=byId(fieldId),lines=integrityLines(fieldId);
    if(!lines.some(x=>x.toLowerCase()===path.toLowerCase())){field.value=[...lines,path].join('\n');field.dispatchEvent(new Event('input',{bubbles:true}));}
    updateResponseSuggestions();
}
function readEndpoint(){const e={SignatureScheduleFrequency:byId('EndpointSignatureScheduleFrequency').value,SignatureScheduleTime:byId('EndpointSignatureScheduleTime').value,SignatureScheduleWeekday:Number(byId('EndpointSignatureScheduleWeekday').value),SignatureScheduleMonthDay:Number(byId('EndpointSignatureScheduleMonthDay').value),Mode:byId('EndpointMode').value,TrustedEnginePath:byId('EndpointTrustedEnginePath').value.trim(),TrustedEngineSha256:byId('EndpointTrustedEngineSha256').value.trim().toLowerCase()};for(const k of endpointFlags)e[k]=byId('Endpoint'+k).checked;for(const [k,id] of Object.entries(endpointNumbers))e[k]=Number(byId(id).value);for(const k of endpointArrays)e[k]=integrityLines('Endpoint'+k);return e;}
function fillIntegrity(c){const i=c.Integrity;byId('IntegrityEnabled').checked=i.Enabled;byId('IntegrityInterval').value=i.IntervalSeconds;byId('IntegrityRecursive').checked=i.Recursive;byId('IntegrityWriteEvents').checked=i.WriteEvents;for(const key of ['Paths','ExcludedPaths','ExcludedPatterns'])byId('Integrity'+key).value=(i[key]||[]).join('\n');byId('IntegrityReason').value='';}
async function loadSettings(){
    const model=await request('/ui/settings');config=model.config;fillIntegrity(config);fillEndpoint(config);loadResponseSuggestions(model);fillTelemetryExport(model);fillSiem(model);showRestart(model);formDirty=false;fillDelivery(model);fillLogs(model);fillAi(model);fillDatabaseMaintenance(model);
    byId('origin').textContent='Current listener · '+model.activeOrigin;
    byId('AllowedClientIPs').value=(config.AllowedClientIPs||[]).join('\n');byId('firewall-client-ip').textContent='Current client IP · '+model.clientIp;
    [...numbers,...strings].forEach(k=>byId(k).value=config[k]??'');flags.forEach(k=>byId(k).checked=k==='RequireLogin'||config[k]);byId('RequireLogin').disabled=true;
    byId('certMode').value=config.CertificateThumbprint?'custom':'auto';certFields();
    byId('targets').value=config.Targets.map(t=>t.Address+' '+t.Name).join('\n');
    targetRules.clear();config.Targets.forEach(t=>targetRules.set(t.Address,{...t}));renderRules();
    byId('core').textContent='Default categories · '+model.core.map(label).join(', ');
    checkboxList('channels',model.channels,config.EventChannels);checkboxList('extras',model.extras,config.ExtraCategories);
    checkboxList('scopes',[...model.core,...config.ExtraCategories],model.core);tokenRows(model.tokens);
}
function settingsPage(){
    const categories=[...document.querySelectorAll('details.settings-category')];
    byId('settings-expand-all').onclick=()=>{for(const d of categories)d.open=true;};
    byId('settings-collapse-all').onclick=()=>{for(const d of categories)d.open=false;};
    for(const form of [byId('configForm'),byId('tokenForm')])form.addEventListener('invalid',event=>{const d=event.target.closest('details.settings-category');if(d)d.open=true;},true);
    byId('configForm').addEventListener('input',()=>{formDirty=true;});
    for(const id of ['EndpointPaths','EndpointResponsePaths'])byId(id).addEventListener('input',updateResponseSuggestions);
    byId('EndpointSuggestedResponse').onchange=()=>{byId('EndpointAddSuggestedResponse').disabled=!byId('EndpointSuggestedResponse').value;};
    byId('EndpointSuggestedExecutable').onchange=()=>{byId('EndpointAddSuggestedExecutable').disabled=!byId('EndpointSuggestedExecutable').value;};
    byId('EndpointAddSuggestedResponse').onclick=()=>addResponseSuggestion('EndpointSuggestedResponse','EndpointResponsePaths');
    byId('EndpointAddSuggestedExecutable').onclick=()=>addResponseSuggestion('EndpointSuggestedExecutable','EndpointContainmentExecutables');
    for(const id of ['EndpointTrustedEnginePath','EndpointTrustedEngineSha256'])byId(id).addEventListener('input',updateEngineSuggestion);
    byId('EndpointUseDetectedEngine').onclick=()=>useDetectedEngine().catch(failure);
    byId('EndpointSignatureScheduleEnabled').onchange=byId('EndpointSignatureScheduleFrequency').onchange=signatureScheduleFields;

    byId('DatabaseMaintenanceUnit').onchange=byId('DatabaseMaintenanceEnabled').onchange=maintenanceFields;byId('DatabaseMaintenanceRun').onclick=runMaintenance;setInterval(refreshMaintenance,5000);
    byId('restart-service').onclick=restartService;byId('TelemetryExportFull').onchange=exportCategoryState;
    for(const name of receivers)byId(name+'Test').onclick=()=>testSiem(name);
    byId('AiProvider').onchange=()=>{stashAi();showAiProfile(byId('AiProvider').value);};
    byId('SyslogTransport').onchange=()=>{const port=byId('SyslogPort');if(['514','6514'].includes(port.value))port.value=byId('SyslogTransport').value==='tls'?6514:514;};
    byId('smtp-test').onclick=testSmtp;
    byId('tokenDays').value=90;byId('targets').oninput=renderRules;
    byId('certMode').onchange=byId('UseHttps').onchange=certFields;
    byId('configForm').onsubmit=async e=>{e.preventDefault();if(!config)return;
        let done=()=>{};
        try{const next={...config,...deliveryInput(),...readAi(),...readSiem(),Logging:readLogs(),TelemetryExport:readTelemetryExport(),DatabaseMaintenance:readDatabaseMaintenance()};numbers.forEach(k=>next[k]=Number(byId(k).value));strings.forEach(k=>next[k]=byId(k).value.trim());flags.forEach(k=>next[k]=byId(k).checked);
            next.Endpoint=readEndpoint();
            if(Object.keys(next.Endpoint).some(k=>JSON.stringify(next.Endpoint[k])!==JSON.stringify(config.Endpoint[k]))&&!(await confirmAction("Apply endpoint monitoring settings?",next.Endpoint.Mode==='monitor'?"Verify scan paths, exclusions and canary baselines before enabling monitoring.":"Automatic response can remove confirmed malicious files and, in Contain mode, stop explicitly eligible processes. Verify response paths, trusted signatures, backups and testing. Continue?","Apply settings",next.Endpoint.Mode!=='monitor')))return;
            next.Integrity=readIntegrity();
            if(Object.keys(next.Integrity).some(k=>JSON.stringify(next.Integrity[k])!==JSON.stringify(config.Integrity[k]))){
                next.IntegrityReason=byId('IntegrityReason').value.trim();
                if(next.IntegrityReason.length<5){byId('integrity-settings').open=true;byId('IntegrityReason').focus();throw Error('Enter a reason for the integrity policy change (at least five characters).');}
                if(!(await confirmAction('Apply integrity monitoring policy?', 'Verify that all protected files are trusted before the first scan. Changing exclusions can reduce monitoring coverage. Existing trusted hashes will not be replaced.', 'Apply policy')))return;
            }
            next.AllowedClientIPs=byId('AllowedClientIPs').value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
            if(JSON.stringify(next.AllowedClientIPs)!==JSON.stringify(config.AllowedClientIPs||[])&&!(await confirmAction('Apply IP firewall allowlist?', 'Remote clients outside the listed addresses and CIDR subnets will be denied immediately, including API clients. Localhost is always allowed.', 'Apply allowlist')))return;
            if(byId('certMode').value==='auto')next.CertificateThumbprint='';
            next.Targets=targetLines().map(t=>({...targetRules.get(t.Address),...t}));
            next.EventChannels=checked('channels');next.ExtraCategories=checked('extras');
            if(next.DatabaseMaintenance.Enabled&&JSON.stringify(next.DatabaseMaintenance)!==JSON.stringify(config.DatabaseMaintenance)&&!(await confirmAction('Apply retention policy?', 'Saving this retention policy starts permanent database cleanup. Continue only after making a backup.', 'Save and enable cleanup', true)))return;
            done=LinkScopeBusy.begin('Saving settings…');
            const res=await request('/ui/settings',next);await loadSettings();window.LinkScopeToast.brand(config.BrandLabel);
            notice(res.restartRequired?(byId('restart-service').hidden?'Settings saved. Restart the console process on the monitoring host.':'Settings saved. Use Restart LinkScope under Network probes to apply the changes.'):'Settings saved.');
        }catch(ex){failure(ex);}finally{done();}};
    byId('tokenForm').onsubmit=async e=>{e.preventDefault();const done=LinkScopeBusy.begin('Generating token…');
        try{const res=await request('/ui/tokens',{name:byId('tokenName').value,days:Number(byId('tokenDays').value),categories:checked('scopes')});
        byId('secret').value=res.token;byId('newToken').hidden=false;byId('secret').select();await refreshTokens();notice('Token generated.');
    }catch(ex){failure(ex);}finally{done();}};
    byId('hideSecret').onclick=()=>{byId('secret').value='';byId('newToken').hidden=true;};
    return loadSettings();
}
function healthKind(value){
    const v=String(value??'unknown').toLowerCase();
    if(['ok','normal','healthy','enabled','true','pass','passed','success','quarantined','deleted','clean','current','enrolled'].includes(v))return 'ok';
    if(['critical','error','fail','failed','replace','disabled','false','unhealthy','infected','missing'].includes(v))return 'fail';
    if(['warning','review','partial','stale','degraded','warming_up','scanning','evidence_saved','heuristic','limited','pending baseline'].includes(v))return 'review';
    return 'unknown';
}
function healthBadge(value,kind){const b=element('span',value);b.className='health-badge '+kind;return b;}
function healthCellKind(category,key,value){
    const k=key.toLowerCase();
    if(category.startsWith('endpoint')&&k==='result'&&String(value).toLowerCase()==='excluded')return 'info';
    if(['status','state','level','severity','health','recommendation','registrationstatus','result'].includes(k))return ['info','information'].includes(String(value).toLowerCase())?'info':healthKind(value);
    if((category==='firewall'&&k==='enabled')||(category==='defender'&&['amserviceenabled','antivirusenabled','realtimeprotectionenabled'].includes(k)))return healthKind(value);
    if(k==='predictfailure')return value==null?'unknown':String(value).toLowerCase()==='true'?'fail':String(value).toLowerCase()==='false'?'ok':'unknown';
    if(category==='firewall'&&['inbounddefault','outbounddefault'].includes(k))return 'info';
    return null;
}
function alertSeverityKind(alerts){
    return alerts.some(a=>['critical','error'].includes(String(a.severity||'').toLowerCase()))?'fail':alerts.some(a=>String(a.severity||'').toLowerCase()==='warning')?'review':null;
}
function alertStateLabel(kind){
    return kind==='fail'?'Critical / Error':kind==='review'?'Warning':kind==='ok'?'No active alerts':kind==='fail'?'Collection error':kind==='unknown'?'Data unavailable':'Data needs review';
}
function metricAlertState(active,category,volume,collectionKind){
    const matching=active.filter(a=>!a.resolved&&a.category===category&&(volume==null||a.title===volume+' usage is high'||(a.title==='Volume data unavailable'&&a.message===volume)||a.title===category+' coverage is unavailable'||a.title===category+' coverage is partial'));
    const severity=alertSeverityKind(matching);
    const kind=severity||(collectionKind==='ok'?'ok':collectionKind);
    return {kind,status:alertStateLabel(kind),messages:matching.filter(a=>['critical','error','warning'].includes(String(a.severity||'').toLowerCase())).map(a=>a.title+' · '+a.message)};
}
function categoryFallbackKind(category,result,rows,collectionKind){
    if(collectionKind==='fail'||collectionKind==='unknown')return collectionKind;
    const values=[];
    const push=v=>{if(v!=null&&v!=='')values.push(v);};
    if(!(category==='endpoint_protection'&&result?.status==='scanning'))push(result?.status);push(result?.health);push(result?.severity);push(result?.state);
    for(const row of rows||[]){
        if(category==='events'||category==='event_details'){push(row.status);for(const item of row.items||[]){push(item.level);push(item.severity);}}
        else if(category==='smart'){push(row.recommendation);push(row.health);push(row.status);push(row.predictFailure);}
        else if(category==='security'){push(row.status);push(row.state);push(row.level);push(row.severity);push(row.value);}
        else if(category==='antivirus'){
            push(row.registrationStatus);
            for(const [k,v] of Object.entries(row.defender||{}))if(['amServiceEnabled','antivirusEnabled','realTimeProtectionEnabled','status','health'].includes(k))push(v);
            for(const product of row.registeredProducts||[]){push(product.status);push(product.state);push(product.health);push(product.enabled);}
        }else if(category==='firewall'){push(row.status);push(row.enabled);push(row.state);}
        else{for(const [k,v] of Object.entries(row||{}))if(['status','state','health','severity','level','recommendation','enabled','registrationStatus','predictFailure'].includes(k))push(v);}
    }
    const kinds=values.map(healthKind);
    if(kinds.includes('fail'))return 'fail';
    if(kinds.includes('review'))return 'review';
    return collectionKind;
}
function categoryAlertState(active,category,result,rows,collectionKind){
    const matching=active.filter(a=>!a.resolved&&a.category===category);
    const severity=alertSeverityKind(matching);
    const fallback=categoryFallbackKind(category,result,rows,collectionKind);
    const kind=severity||fallback;
    return {kind,status:alertStateLabel(kind),messages:matching.filter(a=>['critical','error','warning'].includes(String(a.severity||'').toLowerCase())).map(a=>a.title+' · '+a.message)};
}
function metric(name,value,foot,collectionKind,alertState){
    const d=element('div');d.className='card health-metric-card '+alertState.kind;
    const heading=element('div');heading.className='health-metric-heading';heading.append(element('strong',name),healthBadge(alertState.status,alertState.kind));
    const n=element('strong',value);n.className='metric';d.append(heading,n,healthBadge(foot,collectionKind));
    for(const message of alertState.messages){const detail=element('small',message);detail.className='health-metric-alert-detail';d.append(detail);}
    return d;
}
function decorateHealthSection(section,title,state,kind,alertState,timeText){
    section.className='health-category-card '+alertState.kind;
    const summary=element(page==='integrity'||page==='endpoint'?'div':'summary');
    const heading=element('div');heading.className='health-category-heading';heading.append(element('strong',title),healthBadge(alertState.status,alertState.kind));
    summary.append(heading);
    section.append(summary,element('small',(state?state+'. ':'')+(timeText?'Collected'+timeText:'Waiting for Windows.')));
    if(alertState.messages.length){
        const list=element('div');
        for(const message of alertState.messages.slice(0,3)){
            const detail=element('small',message);detail.className='health-category-alert-detail';list.append(detail);
        }
        section.append(list);
    }
}
const pct=n=>n==null?'—':n+'%';
const gib=n=>n==null?'—':(n/1073741824).toLocaleString(undefined,{maximumFractionDigits:1})+' GiB';
const smartTabs=new Map();
const verdictClass=s=>({normal:'ok',review:'review',replace:'fail',unknown:'unknown',OK:'ok',REVIEW:'review',FAIL:'fail',UNKNOWN:'unknown'})[s]||'unknown';
const triple=n=>n==null?'—':String(n).padStart(3,'0');
function smartTable(attrs,diskId){
    const wrap=element('div');wrap.className='tablewrap';const t=element('table');t.className='smart-table';
    const head=t.createTHead().insertRow(),body=t.createTBody();['State','Num','Attribute Name','Value','Worst','Raw (hex)','Threshold'].forEach(x=>head.append(element('th',x)));
    for(const a of attrs){const row=body.insertRow();const badge=element('span',a.state);badge.className='health-badge '+verdictClass(a.state);row.insertCell().append(badge);
        [triple(a.id),a.name,triple(a.value),triple(a.worst),a.rawHex,triple(a.threshold)].forEach(v=>row.insertCell().textContent=v);}
    wrap.append(t);LinkScopePages.attach(t,'smart:'+diskId,'SMART attributes',false,true);return wrap;
}
function renderDrive(d){
    const card=element('article');card.className='drive';
    const headline=element('h3','●  State · '+(d.headline||'UNABLE TO DETERMINE'));headline.className='drive-state';headline.replaceChildren(healthBadge(d.headline||'UNABLE TO DETERMINE',verdictClass(d.recommendation)));card.append(headline);
    const meta=element('dl');meta.className='drive-meta';
    const capacity=d.capacityBytes!=null?(Number(d.capacityBytes)/1e9).toLocaleString(undefined,{maximumFractionDigits:2})+' GB ('+Number(d.capacityBytes).toLocaleString()+' bytes)':'—';
    for(const [k,v] of Object.entries({Model:d.model,Firmware:d.firmware,Serial:d.serial,Capacity:capacity,'Report by':d.reportBy,'Scan date':d.scanUtc?new Date(d.scanUtc).toLocaleString():'—',Vendor:d.vendor,Bus:d.bus,'Estimated life remaining':d.estimatedLifeRemainingPercent==null?'Unavailable':pct(d.estimatedLifeRemainingPercent)})){meta.append(element('dt',k),element('dd',v||'—'));}
    card.append(meta);const tabs=element('div');tabs.className='drive-tabs';tabs.setAttribute('role','group');tabs.setAttribute('aria-label','Disk details');
    const panel=element('div');const options=['S.M.A.R.T. Report','Findings / Advice','Diagnostics / NVMe'];
    function select(which){
        smartTabs.set(d.diskId,which);Array.from(tabs.children).forEach((b,i)=>b.setAttribute('aria-pressed',String(i===which)));panel.replaceChildren();
        if(which===0){panel.append(d.attributes?.length?smartTable(d.attributes,d.diskId):element('p','ATA attribute rows unavailable. See Diagnostics / NVMe for this drive.'));return;}
        if(which===1){panel.append(element('p',d.advice||'No advice available.'));const ul=element('ul');for(const f of d.findings||[])ul.append(element('li',f));panel.append(ul);return;}
        panel.append(element('p','SMART source · '+(d.smartSource||'unavailable')),element('p','Endurance source · '+(d.lifeSource||'unavailable')));
        if(d.nvme)panel.append(table([d.nvme],'nvme:'+d.diskId));for(const msg of d.diagnostics||[])panel.append(element('p',msg));
        const row=Object.fromEntries(['health','predictFailure','temperatureC','powerOnHours','readErrorsTotal','writeErrorsTotal','readErrorsUncorrected','writeErrorsUncorrected','thresholdPercent'].map(k=>[k,d[k]]));panel.append(table([row],'drive:'+d.diskId));
    }
    options.forEach((name,i)=>{const b=element('button',name);b.type='button';b.onclick=()=>{select(i);filterHealthCategories();};tabs.append(b);});
    card.append(tabs,panel);select(smartTabs.get(d.diskId)||0);return card;
}

let endpointAck=null,endpointAckEpoch=0,endpointAckBusy=false,endpointScanBusy=false,endpointScanRequested=null,endpointLastSample=null;
function endpointAckControls(){
    const b=byId('endpoint-ack-previous');if(!b)return;
    b.disabled=!csrf||endpointAckBusy||!endpointAck||!endpointAck.unread;
    b.textContent=endpointAckBusy?'Acknowledging…':'Acknowledge previous alerts'+(endpointAck?.unread?' ('+endpointAck.unread+')':'');
    byId('endpoint-ack-count').textContent=endpointAck?endpointAck.unread+' unread endpoint alerts · '+endpointAck.activeUnread+' active unread':'Acknowledgement status unavailable';
}
function endpointActivity(v,generatedUtc){
    endpointLastSample=v;const r=v?.result||v||{},panel=byId('endpoint-live');if(!panel)return;
    const age=Number(v?.ageSeconds??Infinity),fresh=!v?.stale&&age<=20,now=Date.parse(generatedUtc),recent=Number.isFinite(now)&&r.lastRealTimeScanUtc&&now-Date.parse(r.lastRealTimeScanUtc)<=8000&&now>=Date.parse(r.lastRealTimeScanUtc);
    if(endpointScanRequested&&((fresh&&(r.scanRunning||r.lastScanUtc!==endpointScanRequested.previous||r.scanStartedUtc!==endpointScanRequested.started))||Date.now()-endpointScanRequested.at>30000))endpointScanRequested=null;
    let state='waiting',message='Waiting for endpoint telemetry';
    if(r.status==='disabled'){state='disabled';message='Endpoint Protection disabled';}
    else if(!fresh){state='waiting';message=v?.collectedUtc?'Awaiting fresh scanner telemetry':'Waiting for endpoint telemetry';}
    else if(r.engineOnline!==true){state='warning';message='ClamAV unavailable · monitoring coverage incomplete';}
    else if(r.scanRunning){state='scanning';message='Full file scan in progress';}
    else if(endpointScanRequested){state='queued';message='Scan requested · waiting for scanner';}
    else if(Number(r.queueDepth)>0){state='queued';message='Processing real-time file events';}
    else if(recent){state='activity';message='Real-time file scan just completed';}
    else if(r.realTime&&r.watcherCount>0){state=r.status==='partial'?'warning':'watching';message=r.status==='partial'?'Watching files · coverage warning':'Real-time monitoring active · waiting for changes';}
    else if(r.realTime){state='warning';message='Real-time watcher unavailable';}
    else {state='idle';message='Scheduled monitoring · waiting for next scan';}
    panel.dataset.state=state;byId('endpoint-live-state').textContent=message;
    byId('endpoint-live-counts').textContent='Full scan: '+(r.scannedFiles??'—')+' files · Real-time checks: '+(r.realTimeChecked??'—')+' since policy start · Pending: '+(r.queueDepth??'—');
    byId('endpoint-live-file').textContent=r.lastFileScanUtc?'Last successful signature check: '+new Date(r.lastFileScanUtc).toLocaleString()+(r.lastScannedPath?' · '+r.lastScannedPath:''):'No successful file signature check reported yet.';
    if(byId('endpoint-signature-schedule')){const schedule=r.signatureSchedule,day=schedule?.frequency==='weekly'?' on '+(['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'][schedule.weekday]||'—'):schedule?.frequency==='monthly'?' on day '+schedule.monthDay:'';byId('endpoint-signature-schedule').textContent=r.status==='disabled'?'Scheduled refresh · Paused (Endpoint Protection disabled)':!fresh?'Scheduled refresh · Awaiting fresh status':schedule?.enabled?'Scheduled refresh · '+schedule.frequency+day+' at '+schedule.localTime+' (monitoring host) · '+schedule.status+' · Next: '+localEndpointDate(schedule.nextRunUtc)+' · Last request: '+localEndpointDate(schedule.lastScheduledRequestUtc):schedule?'Scheduled refresh · Disabled':'Scheduled refresh · Status not recorded';}
    if(byId('endpoint-signature-log'))byId('endpoint-signature-log').textContent='Latest database update reported by FreshClam log: '+localEndpointDate(r.lastReportedSignatureUpdateUtc)+(r.signatureUpdateLogRecognized?'':' · No recent matching log record');
    const b=byId('endpoint-scan-now');b.disabled=!csrf||endpointScanBusy||!!endpointScanRequested||r.status==='disabled'||!!r.scanRunning||!fresh;b.textContent=r.scanRunning&&fresh?'Scanning…':endpointScanRequested?'Scan queued…':'Scan now';
}
let signatureBusy=false,signatureRequested=null,signatureState=null,canaryBusy=false,maintenanceLast=0,maintenanceBusy=false;
function localEndpointDate(value){return value&&Number.isFinite(Date.parse(value))?new Date(value).toLocaleString():'Not recorded';}
async function refreshEndpointMaintenance(){
    if(maintenanceBusy)return;maintenanceBusy=true;
    try{
        const [m,c]=await Promise.all([request('/ui/endpoint-signatures'),request('/ui/endpoint-canaries')]);signatureState=m.state||{};
        let startupError='';
        if(signatureRequested&&(signatureState.attemptUtc!==signatureRequested.attempt||Date.now()-signatureRequested.at>60000)){
            if(signatureState.attemptUtc===signatureRequested.attempt)startupError='Task did not report startup. Check Windows Task Scheduler.';
            signatureRequested=null;
        }
        const elapsed=Date.now()-Date.parse(signatureState.attemptUtc||''),cooldown=Number.isFinite(elapsed)&&elapsed<3600000;
        const button=byId('endpoint-signatures');button.disabled=!csrf||!m.supported||signatureBusy||!!signatureRequested||signatureState.status==='Running'||signatureState.status==='Unavailable'||cooldown;button.textContent=signatureState.status==='Running'?'Updating signatures…':signatureRequested?'Update queued…':'Update signatures now';
        const state=byId('endpoint-signature-state');state.replaceChildren(healthBadge(signatureRequested?'Queued':signatureState.status||'Not recorded',({Running:'info',Updated:'ok',Checked:'ok',Failed:'fail',Warning:'review',Interrupted:'review',Unavailable:'unknown'})[signatureState.status]||'unknown'),document.createTextNode(' '+(startupError||signatureState.detail||'')+(cooldown&&signatureState.status!=='Running'?' · Next request after '+localEndpointDate(new Date(Date.parse(signatureState.attemptUtc)+3600000).toISOString()):'')+(!m.supported?' · Standard local service/port required.':'')));
        byId('endpoint-signature-check').textContent='Last successful FreshClam check (LinkScope initiated): '+localEndpointDate(signatureState.checkedUtc);
        byId('endpoint-signature-download').textContent='Last confirmed signature database content change (LinkScope initiated): '+localEndpointDate(signatureState.updatedUtc);
        const select=byId('endpoint-canary-dir'),prior=select.value,dirs=c.directories||[];if(JSON.stringify([...select.options].map(o=>o.value))!==JSON.stringify(['',...dirs])){select.replaceChildren(new Option(dirs.length?'Select a protected directory':'No eligible saved directory',''),...dirs.map(p=>new Option(p,p)));if(dirs.includes(prior))select.value=prior;}
        select.disabled=!dirs.length||canaryBusy;byId('endpoint-create-canaries').disabled=canaryBusy||!csrf||!select.value;
    }catch(e){byId('endpoint-signature-state').textContent='Maintenance status unavailable. '+e.message;byId('endpoint-signatures').disabled=true;byId('endpoint-create-canaries').disabled=true;}
    finally{maintenanceBusy=false;maintenanceLast=Date.now();}
}
// The vault is independent of the telemetry-rendered cards. Keep selection,
// filters and paging stable during live refreshes; never send browser-supplied paths.
let quarantineItems=[],quarantineReceipts=[],quarantineSelected=new Set(),quarantinePage=1;
let quarantineBusy=false,quarantineLoading=false,quarantineLast=0,quarantineSnapshotKey='',quarantineAvailable=false;
const quarantinePageSize=20,quarantineLimit=100;
function quarantineMatching(){
    const query=byId('quarantine-search').value.trim().toLowerCase();
    return quarantineItems.filter(r=>!query||[r.path,r.sha256,r.id,r.state,r.utc].some(x=>String(x??'').toLowerCase().includes(query)));
}
function quarantinePageRows(){const rows=quarantineMatching(),pages=Math.max(1,Math.ceil(rows.length/quarantinePageSize));quarantinePage=Math.max(1,Math.min(pages,quarantinePage));return {rows:rows.slice((quarantinePage-1)*quarantinePageSize,quarantinePage*quarantinePageSize),pages,matches:rows.length};}
function quarantineSelectionState(){
    const {rows}=quarantinePageRows(),eligible=rows.filter(r=>r.deletable===true);
    const pageSelect=byId('quarantine-select-page');pageSelect.checked=eligible.length>0&&eligible.every(r=>quarantineSelected.has(r.id));pageSelect.indeterminate=!pageSelect.checked&&eligible.some(r=>quarantineSelected.has(r.id));
    pageSelect.disabled=!csrf||quarantineBusy||!quarantineAvailable||!eligible.length;
    byId('quarantine-delete').disabled=!csrf||quarantineBusy||!quarantineAvailable||!quarantineSelected.size;
    byId('quarantine-selection').textContent=quarantineSelected.size+' selected'+(quarantineSelected.size===quarantineLimit?' (maximum per operation)':'');
    for(const box of byId('quarantine-rows').querySelectorAll('input[type=checkbox]')){box.checked=quarantineSelected.has(box.dataset.evidence);box.disabled=!csrf||quarantineBusy||!quarantineAvailable||box.dataset.eligible!=='true'||(!box.checked&&quarantineSelected.size>=quarantineLimit);}
}
function renderQuarantine(){
    const {rows,pages,matches}=quarantinePageRows(),body=byId('quarantine-rows');body.replaceChildren();
    for(const r of rows){
        const row=body.insertRow(),box=element('input');box.type='checkbox';box.dataset.evidence=r.id;box.dataset.eligible=String(r.deletable===true);box.setAttribute('aria-label','Select '+(r.path||r.id));
        box.onchange=()=>{if(box.checked&&quarantineSelected.size<quarantineLimit)quarantineSelected.add(r.id);else quarantineSelected.delete(r.id);quarantineSelectionState();};row.insertCell().append(box);
        row.insertCell().textContent=r.utc&&Number.isFinite(Date.parse(r.utc))?new Date(r.utc).toLocaleString():'—';
        row.insertCell().textContent=r.path||'Unavailable';
        const evidence=row.insertCell(),hash=element('code',r.sha256||'—');hash.className='quarantine-hash';evidence.append(hash,element('small',r.id||'—'));
        row.insertCell().textContent=Number.isFinite(r.sealedBytes)?(r.sealedBytes/1024).toLocaleString(undefined,{maximumFractionDigits:1})+' KiB':'—';
        const state=r.state==='quarantined'?'Quarantined':r.state==='purge_pending'?'Deletion pending':r.state==='evidence_saved'?'Incomplete evidence':'Review required';
        row.insertCell().append(healthBadge(state,r.state==='quarantined'?'ok':'review'));
    }
    if(!rows.length){const row=body.insertRow(),cell=row.insertCell();cell.colSpan=6;cell.textContent=quarantineItems.length?'No records match your search.':'No sealed malware evidence in quarantine.';}
    byId('quarantine-total').textContent=quarantineItems.length.toLocaleString()+' vault items · '+matches.toLocaleString()+' matching';
    byId('quarantine-page').textContent='Page '+quarantinePage+' of '+pages;
    byId('quarantine-previous').disabled=quarantinePage===1;byId('quarantine-next').disabled=quarantinePage===pages;
    quarantineSelectionState();
}
async function refreshQuarantine(force=false){
    if(quarantineLoading||quarantineBusy||(!force&&Date.now()-quarantineLast<5000))return;
    quarantineLoading=true;byId('quarantine-refresh').disabled=true;
    try{
        const data=await request('/ui/endpoint-quarantine');
        if(quarantineBusy)return;
        const items=Array.isArray(data.items)?data.items:[],receipts=Array.isArray(data.recentDeletions)?data.recentDeletions:[],key=JSON.stringify([items,receipts]);
        quarantineAvailable=true;
        if(quarantineSnapshotKey!==key){quarantineItems=items;quarantineReceipts=receipts;quarantineSnapshotKey=key;
            const eligible=new Set(items.filter(r=>r.deletable===true).map(r=>r.id));for(const id of quarantineSelected)if(!eligible.has(id))quarantineSelected.delete(id);
            renderQuarantine();const target=byId('quarantine-deletions');target.replaceChildren(receipts.length?table(receipts,'endpoint quarantine deletions'):element('p','No permanent deletions recorded.'));
        }else quarantineSelectionState();
        byId('quarantine-status').textContent='Updated '+new Date().toLocaleTimeString()+' · '+Number(data.deletedCount||0).toLocaleString()+' payloads permanently deleted'+(csrf?'':' · Read-only access');
    }catch(e){quarantineAvailable=false;byId('quarantine-status').textContent='Vault status unavailable: '+e.message;quarantineSelectionState();}
    finally{quarantineLoading=false;quarantineLast=Date.now();byId('quarantine-refresh').disabled=false;}
}
function setupQuarantineManager(){
    byId('quarantine-search').oninput=()=>{quarantinePage=1;renderQuarantine();};
    byId('quarantine-previous').onclick=()=>{quarantinePage--;renderQuarantine();};byId('quarantine-next').onclick=()=>{quarantinePage++;renderQuarantine();};
    byId('quarantine-refresh').onclick=()=>refreshQuarantine(true);
    byId('quarantine-select-page').onchange=()=>{const select=byId('quarantine-select-page').checked;for(const r of quarantinePageRows().rows.filter(r=>r.deletable===true)){if(select&&quarantineSelected.size<quarantineLimit)quarantineSelected.add(r.id);else if(!select)quarantineSelected.delete(r.id);}quarantineSelectionState();};
    byId('quarantine-delete').onclick=async()=>{
        if(!csrf||!quarantineAvailable||quarantineBusy||!quarantineSelected.size)return;
        const ids=[...quarantineSelected];quarantineBusy=true;quarantineSelectionState();
        try{if(!(await confirmAction('Permanently delete '+ids.length+' quarantined file'+(ids.length===1?'':'s')+'?', 'The selected sealed malware payloads will be removed irreversibly from the LinkScope vault. You cannot restore them through LinkScope. Detection records, original paths, hashes and audit history will remain. Backups and disk recovery are not affected.','Delete permanently',true)))return;
            const result=await request('/ui/endpoint-quarantine',{ids});
            for(const item of result.results||[])if(item.ok)quarantineSelected.delete(item.id);
            const details=(result.results||[]).filter(r=>!r.ok).map(r=>r.id+': '+r.detail).join(' · ');
            notice(result.deleted+' payloads deleted; '+result.failed+' not deleted.'+(details?' '+details:''),result.failed?'error':'success');
            byId('quarantine-status').textContent=result.deleted+' deleted; '+result.failed+' failed.';
            quarantineSnapshotKey='';
        }catch(e){failure(e);}finally{quarantineBusy=false;quarantineSelectionState();await refreshQuarantine(true);}
    };
    if(!csrf){byId('quarantine-delete').hidden=true;byId('quarantine-select-page').hidden=true;}
    refreshQuarantine(true);setInterval(refreshQuarantine,5000);
}
function setupEndpointControls(){
    byId('endpoint-signatures').onclick=async()=>{
        if(signatureBusy||signatureRequested)return;
        if(!(await confirmAction('Update ClamAV signatures now?','Run the installed, restricted FreshClam maintenance task. The scheduled updater will briefly stop and restart. The scanner continues running; only locally approved signature sources are used.','Update signatures')))return;
        signatureBusy=true;byId('endpoint-signatures').disabled=true;
        try{await request('/ui/endpoint-signatures',{});signatureRequested={at:Date.now(),attempt:signatureState?.attemptUtc};notice('Signature update requested. Follow progress in Signature maintenance.');}catch(e){failure(e);}finally{signatureBusy=false;await refreshEndpointMaintenance();}
    };
    byId('endpoint-canary-dir').onchange=()=>{byId('endpoint-create-canaries').disabled=canaryBusy||!csrf||!byId('endpoint-canary-dir').value;};
    byId('endpoint-create-canaries').onclick=async()=>{
        const directory=byId('endpoint-canary-dir').value;if(!directory||canaryBusy)return;
        if(!(await confirmAction('Create and enroll canary files?','Create three harmless Word, Excel and TXT documents under '+directory+'\\LinkScope Canary Documents. Existing files and previous baselines will never be replaced. The service must already have write permission.','Create canaries')))return;
        canaryBusy=true;byId('endpoint-create-canaries').disabled=true;
        try{const response=await request('/ui/endpoint-canaries',{directory});byId('endpoint-canary-status').textContent='Enrolled '+response.paths.length+' files. Monitoring will verify the original hashes.';notice('Canary files created and enrolled.');}
        catch(e){byId('endpoint-canary-status').textContent=e.message;failure(e);}finally{canaryBusy=false;await refreshEndpointMaintenance();}
    };
    byId('endpoint-scan-now').onclick=async()=>{
        if(endpointScanBusy||endpointScanRequested)return;
        endpointScanBusy=true;const r=endpointLastSample?.result||{};byId('endpoint-scan-now').disabled=true;
        try{await request('/ui/endpoint-scan',{});endpointScanRequested={at:Date.now(),previous:r.lastScanUtc,started:r.scanStartedUtc};notice('Endpoint scan queued.');byId('endpoint-live').dataset.state='queued';byId('endpoint-live-state').textContent='Scan requested · waiting for scanner';byId('endpoint-scan-now').textContent='Scan queued…';}catch(e){failure(e);}finally{endpointScanBusy=false;}
    };
    refreshEndpointMaintenance();
    byId('endpoint-ack-previous').onclick=async()=>{
        if(!endpointAck||!endpointAck.unread||endpointAckBusy)return;
        const cutoff=endpointAck.through,count=endpointAck.unread;endpointAckBusy=true;endpointAckEpoch++;endpointAckControls();
        try{if(!(await confirmAction('Acknowledge previous endpoint alerts?','Mark '+count+' existing unread Endpoint Protection alerts as read. New alerts arriving after this snapshot remain unread. Active threats and history are not cleared.','Acknowledge')))return;
            endpointAck=await request('/ui/endpoint-ack',{through:cutoff});window.LinkScopeToast?.categoryRead?.('endpoint_protection',cutoff);notice('Previous endpoint alerts acknowledged.');
        }catch(e){failure(e);}finally{endpointAckEpoch++;endpointAckBusy=false;endpointAckControls();}
    };
}
let integrityLastSample=null,integrityScanBusy=false,integrityScanRequested=null;
function integrityDate(value){return value&&Number.isFinite(Date.parse(value))?new Date(value).toLocaleString():'Not recorded';}
function integrityBytes(value){if(value==null||!Number.isFinite(Number(value)))return '—';let n=Number(value),unit=0;const units=['B','KiB','MiB','GiB','TiB'];while(n>=1024&&unit<units.length-1){n/=1024;unit++;}return n.toLocaleString(undefined,{maximumFractionDigits:unit?1:0})+' '+units[unit];}
function integrityActivity(v,generatedUtc){
    integrityLastSample=v;const a=v?.activity||{},r=v?.result||v||{},panel=byId('integrity-live');if(!panel)return;
    const disabled=r.status==='disabled'||a.state==='disabled',running=a.scanRunning===true;
    if(integrityScanRequested&&(disabled||running||(a.scanId&&a.scanId!==integrityScanRequested.previous)||Date.now()-integrityScanRequested.at>30000))integrityScanRequested=null;
    let state='waiting',message='Waiting for scanner telemetry';
    if(disabled){state='disabled';message='Data Integrity monitoring disabled';}
    else if(running){state='scanning';message=a.stage||'Integrity scan in progress';}
    else if(integrityScanRequested){state='queued';message='Scan requested · waiting for scanner';}
    else if(a.state==='failed'){state='warning';message='Integrity verification failed · review findings';}
    else if(a.state==='partial'){state='warning';message='Scan incomplete · review coverage errors';}
    else if(a.state==='cancelled'){state='warning';message='Scan cancelled';}
    else if(a.state==='completed'){state='idle';message='Last scan completed · waiting for next scheduled scan';}
    panel.dataset.state=state;byId('integrity-live-state').textContent=message;
    const number=x=>x==null?'—':Number(x).toLocaleString();
    for(const [id,key] of [['integrity-hashed','filesHashed'],['integrity-excluded','excludedEntries'],['integrity-errors','reportedErrors']])byId(id).textContent=number(disabled?null:a[key]);
    byId('integrity-bytes').textContent=integrityBytes(disabled?null:a.bytesRead);
    const elapsed=a.elapsedMilliseconds==null?null:Math.max(0,Number(a.elapsedMilliseconds)/1000);
    byId('integrity-live-elapsed').textContent=disabled||elapsed==null?'':'Elapsed: '+Math.floor(elapsed/60)+'m '+Math.floor(elapsed%60)+'s';
    byId('integrity-live-time').textContent=disabled?'Monitoring is disabled.':running?'Started: '+integrityDate(a.scanStartedUtc):'Last scan: '+integrityDate(a.scanFinishedUtc||v?.collectedUtc)+' · Next scheduled: '+integrityDate(a.nextScanUtc);
    byId('integrity-live-file').textContent=!disabled&&running&&a.currentPath?'Processing: '+a.currentPath:'';
    const lag=Date.parse(generatedUtc)-Date.parse(a.updatedUtc);
    byId('integrity-live-updated').textContent=disabled||!a.updatedUtc?'':'Last activity update: '+integrityDate(a.updatedUtc)+(running&&lag>30000?' · Waiting for next scanner update':'');
    const b=byId('integrity-scan-now');b.disabled=!csrf||disabled||!v||integrityScanBusy||!!integrityScanRequested||running;b.textContent=running?'Scanning…':integrityScanRequested?'Scan queued…':'Scan now';
}
function setupIntegrityControls(){
    byId('integrity-scan-now').onclick=async()=>{
        if(!csrf||integrityScanBusy||integrityScanRequested||integrityLastSample?.activity?.scanRunning)return;
        integrityScanBusy=true;byId('integrity-scan-now').disabled=true;
        const previous=integrityLastSample?.activity?.scanId;
        try{await request('/ui/integrity-scan',{});integrityScanRequested={at:Date.now(),previous};notice('Integrity scan queued.');}
        catch(e){failure(e);}finally{integrityScanBusy=false;integrityActivity(integrityLastSample,new Date().toISOString());}
    };
}
async function renderHealth(){
    // Shared security detail layout: keep all facts visible, without long concatenated lines.
    function summaryDetails(title,fields,paths,detail){
        const panel=element('div');panel.className='security-summary-details';
        const heading=element('h3',title);heading.className='security-summary-title';panel.append(heading);
        const list=element('dl');list.className='security-summary-grid';
        for(const [name,value,style] of fields){
            const group=element('div');group.className='security-summary-field';
            const label=element('dt',name),val=element('dd',value==null||value===''?'Not recorded':String(value));
            if(style==='hash')group.className+=' security-summary-hash';
            group.append(label,val);list.append(group);
        }
        panel.append(list);
        if(Array.isArray(paths)&&paths.length){
            const pathGroup=element('div');pathGroup.className='security-summary-paths';
            pathGroup.append(element('h4','Protected paths ('+paths.length+')'));
            const pathList=element('ul');for(const path of paths)pathList.append(element('li',String(path)));
            pathGroup.append(pathList);panel.append(pathGroup);
        }
        if(detail){const note=element('p',detail);note.className='security-summary-note';panel.append(note);}
        return panel;
    }
    const localDate=(value,fallback='Not recorded')=>value&&Number.isFinite(Date.parse(value))?new Date(value).toLocaleString():fallback;
    const data=await request(page==='endpoint'?'/ui/endpoint':page==='integrity'?'/ui/integrity':'/ui/system');
    if(page==='integrity')integrityActivity(data.categories?.data_integrity,data.generatedUtc);
    if(page==='endpoint'){
        const epoch=endpointAckEpoch,ack=await request('/ui/endpoint-ack').catch(()=>null);if(!endpointAckBusy&&epoch===endpointAckEpoch)endpointAck=ack;endpointAckControls();endpointActivity(data.categories?.endpoint_protection,data.generatedUtc);if(Date.now()-maintenanceLast>4000)refreshEndpointMaintenance();
    }
    const activeAlerts=Array.isArray(data.alerts)?data.alerts:[];const cats=data.categories,metrics=byId('metrics'),alerts=byId('alerts'),results=byId('results');
    const opened=new Set(Array.from(results.querySelectorAll('details[open]'),d=>d.dataset.category));
    const active=document.activeElement,focusKey=active?.dataset?.healthSearch,selection=focusKey?[active.selectionStart,active.selectionEnd]:null;
    const first=!results.children.length;notice('');byId('stamp').textContent='Snapshot · '+new Date(data.generatedUtc).toLocaleString();
    metrics.replaceChildren();alerts.replaceChildren();results.replaceChildren();
    for(const [key,v] of Object.entries(cats)){
        if(page==='endpoint'?key!=='endpoint_protection':page==='integrity'?key!=='data_integrity':['data_integrity','endpoint_protection'].includes(key))continue;
        const result=v.result||v,rows=result.items||[],state=(v.stale?'Stale · ':'')+'Collection: '+(result.status||'unknown');
        const kind=v.stale?'review':key==='endpoint_protection'&&result.status==='scanning'&&result.engineOnline===true?'ok':healthKind(result.status);
        const time=v.collectedUtc?' · '+new Date(v.collectedUtc).toLocaleTimeString():'';
        if(key==='cpu'||key==='ram'){const card=metric(label(key),pct(result.usedPercent),state+(key==='ram'&&result.totalBytes?' · '+gib(result.usedBytes)+' of '+gib(result.totalBytes):'')+time,kind,metricAlertState(activeAlerts,key,null,result.usedPercent==null&&kind==='ok'?'unknown':kind));card.id='category-'+key;metrics.append(card);continue;}
        if(key==='disk_usage')for(const disk of rows){const diskKind=v.stale?'review':healthKind(disk.status||result.status);metrics.append(metric('Volume '+disk.volume,pct(disk.usedPercent),gib(disk.freeBytes)+' free · '+state+time,diskKind,metricAlertState(activeAlerts,key,disk.volume,disk.usedPercent==null&&diskKind==='ok'?'unknown':diskKind)));}
        if(key==='smart')for(const disk of rows.filter(d=>d.recommendation==='replace'||d.recommendation==='review')){
            const msg=element('div',(disk.recommendation==='replace'?'Plan disk replacement':'Review disk health')+' · '+disk.model+' (disk '+disk.device+') · '+(disk.estimatedLifeRemainingPercent==null?'Life unavailable':pct(disk.estimatedLifeRemainingPercent)+' estimated life remaining')+' · '+state+time);msg.className='alert health-alert '+verdictClass(disk.recommendation);alerts.append(msg);
        }
        let section=element(page==='integrity'||page==='endpoint'?'section':'details');section.dataset.category=key;section.id='category-'+key;section.open=page==='integrity'||opened.has(key)||(first&&['smart','firewall','antivirus','security','data_integrity'].includes(key));
        const categoryState=categoryAlertState(activeAlerts,key,result,rows,kind);
        if(key==='endpoint_protection'&&result.status==='scanning'&&categoryState.kind==='ok')categoryState.status='Scanning';
        if(key==='endpoint_protection'&&result.status==='disabled'&&!categoryState.messages.length){categoryState.kind='unknown';categoryState.status='Disabled';}
        const infoState=(result.truncated?'Showing the first 256 records. ':'')+state;
        decorateHealthSection(section,label(key),infoState,kind,categoryState,time);
        if(key==='smart'&&rows.length){for(const disk of rows)section.append(renderDrive(disk));}
        else if(key==='events'||key==='event_details'){for(const group of rows){const heading=element('h3',group.channel+' ');heading.append(healthBadge(group.status,healthKind(group.status)));if(group.truncated)heading.append(' · capped');section.append(heading,table(group.items||[],key+' · '+group.channel));}}
        else if(key==='endpoint_protection'){
            if(result.status==='disabled')section.append(element('p','Enable Endpoint Protection in Settings.'));
            else {
                const stats=element('div');stats.className='cards integrity-metrics';
                const danger=rows.some(r=>r.severity==='critical'),warnings=rows.some(r=>r.severity==='warning');
                const cards=[['ClamAV engine',result.engineOnline===true?'Online':result.engineOnline===false?'Unavailable':'—',v.stale?'review':result.engineOnline===true?(rows.some(r=>r.path==='ClamAV'&&r.severity==='warning')?'review':'ok'):result.engineOnline===false?'review':'unknown',(result.engineVersion||'Waiting for scan')+' · DB '+(result.signatureDatabaseVersion||'Unknown')],['Files scanned',result.scannedFiles,kind,result.scanRunning?'Full scan running':'Last full scan'],['Real-time queue',result.queueDepth,rows.some(r=>r.change==='Real-time queue overflow')?'review':kind,'Watchers: '+(result.watcherCount??0)+' · Historical overflows: '+(result.overflowCount??0)],['File changes',result.changedFiles,rows.some(r=>r.change==='Possible ransomware activity')?'review':'ok','Behavior window'],['Entropy changes',result.entropyChanges,rows.some(r=>r.change==='Possible ransomware activity')?'review':kind,'Distinct files in behavior window'],['Canary files',result.canaryCount,rows.some(r=>r.change==='Canary integrity violation')?'fail':result.canaryCount===0?'unknown':kind,result.canaryCount===0?'Not configured':'Configured canaries'],['Active findings',result.violations,danger?'fail':warnings?'review':kind,'Persistent threat records'],['Mode',result.mode,result.mode==='monitor'?'ok':result.responseEngineStatus==='Ready'?'ok':'review',(result.mode==='monitor'?'Detection only':'Response: '+(result.responseEngineStatus||'Not checked'))+' · Process correlation: '+(result.processCorrelation||'Unavailable')]];
                for(const [name,val,k,foot] of cards)stats.append(metric(name,val==null?'—':String(val),foot,val==null?'unknown':k,{kind:val==null?'unknown':k,status:name==='Files scanned'&&result.scanRunning&&k==='ok'?'Scanning':alertStateLabel(val==null?'unknown':k),messages:[]}));section.append(stats);
                section.append(element('h3','Active threats and scan statistics'));
                const counts=element('div');counts.className='cards integrity-metrics';
                // Severity is driven by unresolved findings, not cumulative historical scan checks.
                const currentKind=v.stale?'review':kind;
                const currentCount=(name)=>result[name]==null?null:Number(result[name]);
                const malware=currentCount('activeMalware'),heuristic=currentCount('activeHeuristic'),scanIssues=currentCount('activeScanIssues'),vault=currentCount('quarantineCount');
                const counterCards=[
                    ['Clean signature checks',result.cleanChecks,currentKind,'Historical checks since policy start'],
                    ['Active confirmed malware',malware,malware>0?'fail':currentKind,'Historical infected checks: '+(result.infectedChecks??'—')],
                    ['Active heuristic findings',heuristic,heuristic>0?'review':currentKind,'Historical heuristic checks: '+(result.heuristicChecks??'—')],
                    ['Excluded checks',result.excludedChecks,'unknown','Excluded by policy'],
                    ['Active scan issues',scanIssues,scanIssues>0?'review':currentKind,'Historical failed / missing / limited checks: '+(result.failedChecks??'—')],
                    ['Quarantine vault',vault,vault==null?'unknown':vault>0?'review':currentKind,'Historical quarantined checks: '+(result.quarantinedChecks??'—')+' · Deleted payloads: '+(result.quarantineDeletedCount??'—')]
                ];
                for(const [name,val,k,foot] of counterCards){const state=val==null?'unknown':k;counts.append(metric(name,val==null?'—':String(val),foot,state,{kind:state,status:val==null?'Not available':name==='Excluded checks'?'Excluded by policy':name==='Quarantine vault'&&val>0?'Isolated evidence':alertStateLabel(state),messages:[]}));}section.append(counts);
                section.append(summaryDetails('Scan & protection details',[
                    ['Last full scan',localDate(result.lastScanUtc,'Not completed')],
                    ['Next scheduled scan',localDate(result.nextScanUtc,result.scanRunning?'In progress':'Not scheduled')],
                    ['Signature freshness',result.signatureFreshness||'Unknown'],
                    ['Engine-reported signature date',localDate(result.signatureDatabaseTimestamp,result.signatureDatabaseTimestamp||'Unknown')],
                    ['Last engine status check',localDate(result.lastSignatureCheckUtc,'Not verified')],
                    ['Automatic response',result.responseEngineStatus||'Not checked'],
                    ['Response verified',localDate(result.responseCheckedUtc,'Not verified')],
                    ['Queue overflows',result.overflowCount??0],
                    ['Size-limited files',result.sizeLimitedFiles??0],
                    ['Pending alert delivery',result.pendingAlertDelivery??0]
                ],result.protectedPaths,result.responseEngineDetail||'Waiting for response verification'));
                if(result.mode!=='monitor'&&(result.responsePathsReadiness||[]).length){section.append(element('h3','Authorized response path access (advisory)'),table(result.responsePathsReadiness,'endpoint response access'));}
                // Render both statistic groups before the fixed activity/maintenance panel.
                // That panel is never detached or recreated by the two-second telemetry poll.
                metrics.append(section);
                section=element('section');section.id='endpoint-evidence';
                section.append(element('h2','Scan activity & threat evidence'));
                section.append(element('h3','Registered canary files'),(result.canaries||[]).length?table(result.canaries,'endpoint canaries'):element('p','No canaries configured. Use Canary manager above, LinkScope Setup, or register existing decoys under Settings → Endpoint Protection. Do not edit or delete enrolled decoys.'));
                section.append(element('h3','Live file scan activity (latest 100)'),(result.scanActivity||[]).length?table(result.scanActivity,'endpoint scan activity'):element('p','No file scan results yet.'));
                section.append(element('h3','Active detections and response evidence'),rows.length?table(rows,key):element('p',result.status==='ok'?'No active findings.':'Scan pending or incomplete.'));
                section.append(element('h3','Recent threat and response history (latest 100)'),(result.recentIncidents||[]).length?table(result.recentIncidents,'endpoint incident history'):element('p','No recorded incidents.'));
                section.append(element('p','Use Quarantine manager above to review or permanently delete isolated payloads. Full detection history remains in the endpoint database.'));

            }
        }
        else if(key==='data_integrity'){
            if(result.status==='disabled'){section.className='health-category-card unknown';section.querySelector('.health-category-heading .health-badge').replaceWith(healthBadge('Disabled','unknown'));section.append(element('p','Enable integrity monitoring in Settings.'));metrics.append(section);section=element('section');section.id='integrity-evidence';section.append(element('p','Integrity monitoring is disabled.'));}
            else {
                const stats=element('div');stats.className='cards integrity-metrics';
                const observedKind=v.stale?'review':kind;
                const differenceKind=result.violations==null?'unknown':result.violations>0?(rows.some(r=>healthKind(r.severity)==='fail')?'fail':'review'):observedKind;
                const chainKind=result.chainValid===false?'fail':result.chainValid===true?(v.stale?'review':'ok'):'unknown';
                const values=[
                    ['Monitored files',result.monitoredFiles,observedKind,observedKind==='ok'?'Collected':alertStateLabel(observedKind),'Files hashed in latest scan'],
                    ['Excluded entries',result.excludedEntries,'unknown','Information','Excluded by monitoring policy'],
                    ['Detected differences',result.violations,differenceKind,alertStateLabel(differenceKind),'Differences and scan errors'],
                    ['Hash chain',result.chainValid===true?'Valid':result.chainValid===false?'Invalid':'—',chainKind,chainKind==='ok'?'Verified':alertStateLabel(chainKind),'Authenticated snapshot chain']
                ];
                for(const [name,val,k,status,foot] of values){const missing=val==null;stats.append(metric(name,missing?'—':typeof val==='number'?val.toLocaleString():String(val),foot,missing?'unknown':k,{kind:missing?'unknown':k,status:missing?'Data unavailable':status,messages:[]}));}section.append(stats);
                section.append(summaryDetails('Verification details',[
                    ['Last verified collection',localDate(v.collectedUtc)],
                    ['Collection status',v.stale?'Stale':(result.status||'Unknown')],
                    ['Chain sequence',result.sequence==null?'Not initialized':result.sequence],
                    ['Authenticated chain head (HMAC-SHA256)',result.chainHead||'Not initialized','hash']
                ],result.protectedPaths));
                metrics.append(section);
                section=element('section');section.id='integrity-evidence';section.append(element('h2','Integrity findings'));
                if(v.activity?.scanRunning)section.append(element('p',v.result?'A scan is in progress. Findings below are from the last completed verification.':'The initial scan is in progress. Results will appear after verification completes.'));
                section.append(rows.length?table(rows,key):element('p',result.status==='ok'?'No differences from trusted baseline.':'Integrity verification pending or incomplete.'));
            }
        }
        else if(key==='security'){if(result.scannedUtc)section.append(element('p','Security scan · '+new Date(result.scannedUtc).toLocaleString()));section.append(rows.length?table(rows,'security'):element('p',state));}
        else if(key==='antivirus'){const av=rows[0]||{};section.append(element('p','Windows Security Center · '+(result.windowsSecurityCenter||'unavailable')),element('h3','Microsoft Defender'),av.defender?table([av.defender],'defender'):element('p','Defender status unavailable.'),element('h3','Registered products · '+(av.registrationStatus||'unavailable')),table(av.registeredProducts||[],'antivirus products'));}
        else section.append(rows.length?table(rows,key):element('p',result.reason||((result.status==='ok')?'No records in this sample.':state)));
        results.append(section);
    }
    if(page==='system')filterHealthCategories();
    if(focusKey){const input=[...results.querySelectorAll('[data-health-search]')].find(e=>e.dataset.healthSearch===focusKey);if(input&&!input.closest('[hidden]')){input.focus({preventScroll:true});if(selection&&selection[0]!=null)input.setSelectionRange(...selection);}}
    if(first)revealCategory();
}
function filterHealthCategories(){
    const q=byId('health-category-search').value.trim().toLowerCase(),terms=q.split(/\s+/).filter(Boolean);
    const sections=[...byId('results').children];let count=0;
    for(const section of sections){const walker=document.createTreeWalker(section,NodeFilter.SHOW_TEXT);let node,parts=[];while((node=walker.nextNode())){if(!node.parentElement.closest('.health-table-search,.ls-pager'))parts.push(node.textContent);}
        const content=parts.join(' ').toLowerCase(),match=terms.every(t=>content.includes(t));section.hidden=!match;if(match)count++;}
    byId('health-category-count').textContent=count+' / '+sections.length+' categories';
}

function revealCategory(){
    if(page==='system'&&location.hash==='#category-data_integrity'){location.replace('/integrity#category-data_integrity');return;}
    const d=byId(location.hash.slice(1));
    if(d){if(d.tagName==='DETAILS')d.open=true;for(let p=d.parentElement;p;p=p.parentElement)if(p.tagName==='DETAILS')p.open=true;d.scrollIntoView({block:'start'});}
}
window.addEventListener('linkscope-reveal',revealCategory);window.addEventListener('hashchange',revealCategory);
async function start(){
    if(page==='login'){
        const form=byId('loginForm'), firstUse=byId('firstUse'), button=byId('signInButton');
        const spinner=byId('signInSpinner'), label=byId('signInLabel'), status=byId('notice');
        const mfa=byId('mfaChallenge'), fields=form.elements;
        const credentialFields=[fields.user,fields.password,fields.otp,fields.newPassword,fields.confirmPassword];
        function showMfa(required){
            mfa.hidden=!required;fields.otp.disabled=!required;fields.otp.required=required;
            if(!required)fields.otp.value='';
        }
        function resetChallenges(){
            showMfa(false);firstUse.hidden=true;firstUse.disabled=true;
            fields.newPassword.value='';fields.confirmPassword.value='';
        }
        resetChallenges();
        // A challenge applies to the credentials that the server just verified.
        // Editing either credential invalidates the current UI challenge.
        for(const field of [fields.user,fields.password])field.addEventListener('input',()=>{
            resetChallenges();if(!endBusy)status.textContent='';
        });
        const destinations={'#users':'/users','#account':'/account','#endpoint':'/endpoint','#integrity':'/integrity','#network':'/','#ai':'/ai','#logs':'/logs','#alerts':'/alerts','#report':'/system#report','#siem':'/settings#siem'};
        let endBusy=null,attempt=0;
        function setBusy(busy){
            button.disabled=busy;
            for(const field of credentialFields)field.readOnly=busy;
            spinner.hidden=!busy;
            form.setAttribute('aria-busy',String(busy));
            if(busy){
                label.textContent=!firstUse.disabled?'Saving password and signing in…':!mfa.hidden?'Verifying code…':'Signing in…';
                status.textContent=label.textContent;
                endBusy=LinkScopeBusy.begin(label.textContent);
            }else{
                label.textContent=!firstUse.disabled?'Save password and sign in':!mfa.hidden?'Verify & sign in':'Sign in';
                if(endBusy){endBusy();endBusy=null;}
            }
        }
        setBusy(false);
        try{const message=sessionStorage.getItem("ls-account-message");if(message){status.textContent=message;sessionStorage.removeItem("ls-account-message");}}catch{}
        window.addEventListener('pagehide',()=>{++attempt;});
        window.addEventListener('pageshow',event=>{
            if(event.persisted){resetChallenges();fields.password.value='';setBusy(false);status.textContent='';}
        });
        form.onsubmit=async e=>{
            e.preventDefault();
            if(endBusy)return;
            const input={user:fields.user.value,password:fields.password.value};
            if(!mfa.hidden&&!fields.otp.disabled)input.otp=fields.otp.value.trim();
            if(!firstUse.disabled){
                const next=fields.newPassword.value;
                if(next.length<12||next.length>128||!/[A-Z]/.test(next)||!/[a-z]/.test(next)||!/[0-9]/.test(next)||/[\x00-\x1f\x7f-\x9f]/.test(next)){
                    failure(new Error(byId('passwordRules').textContent));return;
                }
                if(next===input.password){failure(new Error('Choose a different password.'));return;}
                if(next!==fields.confirmPassword.value){failure(new Error('The two new passwords do not match.'));return;}
                input.newPassword=next;
            }
            const submitted=++attempt;
            let navigating=false;
            setBusy(true);
            try{
                const response=await request('/auth/login',input);
                if(submitted!==attempt)return;
                if(response.mfaRequired){
                    if(fields.user.value!==input.user||fields.password.value!==input.password){resetChallenges();status.textContent='Credentials changed. Sign in again.';return;}
                    showMfa(true);fields.otp.value='';
                    status.textContent="Enter the current six-digit authenticator code.";fields.otp.focus();return;
                }
                if(response.changeRequired){
                    firstUse.disabled=false;firstUse.hidden=false;
                    status.textContent='Choose your own password to finish signing in.';fields.newPassword.focus();return;
                }
                form.reset();resetChallenges();fields.password.value='';try{sessionStorage.removeItem('ls-notice-cursor');}catch{}
                location.assign(destinations[location.hash]||'/system');
                navigating=true;
            }catch(ex){if(submitted===attempt){fields.otp.value='';failure(ex);if(!mfa.hidden)fields.otp.focus();}}
            finally{if(submitted===attempt&&!navigating)setBusy(false);}
        };return;
    }
    const session=await request('/ui/session');csrf=session.admin?(session.csrf||''):'';
    if(page==='settings'){
        await settingsPage();
        if(location.hash)revealCategory();
        return;
    }
    if(page==='integrity'||page==='endpoint'){
        if(page==='endpoint'){setupEndpointControls();setupQuarantineManager();}else setupIntegrityControls();
        async function pollIntegrity(){try{await renderHealth();}catch(ex){if(page==='endpoint'){byId('endpoint-live').dataset.state='warning';byId('endpoint-live-state').textContent='Unable to refresh scanner telemetry';byId('endpoint-scan-now').disabled=true;endpointAck=null;endpointAckControls();}else{byId('integrity-live').dataset.state='warning';byId('integrity-live-state').textContent='Unable to refresh scanner telemetry';byId('integrity-scan-now').disabled=true;}failure(ex);}finally{setTimeout(pollIntegrity,2000);}}
        await pollIntegrity();return;
    }
    if(page==='system'){
        byId('health-category-search').oninput=filterHealthCategories;
        byId('health-category-clear').onclick=()=>{byId('health-category-search').value='';filterHealthCategories();byId('health-category-search').focus();};
        async function poll(){try{await renderHealth();}catch(ex){failure(ex);}finally{setTimeout(poll,15000);}}
        await poll();
    }
}
LinkScopeBusy.run(page==='settings'?'Loading settings…':'Loading page…',start).catch(failure);
