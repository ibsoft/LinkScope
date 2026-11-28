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
    const controller=(data===undefined&&['/ui/endpoint','/ui/endpoint-ack'].includes(url)||url==='/ui/endpoint-containment-tests'||url==='/ui/endpoint-audit-probe'||url==='/ui/endpoint-external-probe'||url==='/ui/endpoint-protection-lab'||['/ui/endpoint-alert-read','/ui/endpoint-alert-retry'].includes(url))?new AbortController():null;
    if(controller)options.signal=controller.signal;
    const timeout=controller?setTimeout(()=>controller.abort(),url==='/ui/endpoint-external-probe'?25000:url==='/ui/endpoint-audit-probe'||['/ui/endpoint-alert-read','/ui/endpoint-alert-retry'].includes(url)?20000:12000):null;
    if(data!==undefined){
        options.method='POST';options.headers={'Content-Type':'application/json','X-CSRF-Token':csrf};options.body=JSON.stringify(data);
    }
    let response,result;try{response=await fetch(url,options);try{result=await response.json();}catch(e){if(response.ok)throw e;result={error:'Request failed (HTTP '+response.status+').'};}}finally{if(timeout)clearTimeout(timeout);}
    if(!response.ok){
        if(response.status===401&&page!=='login')location.assign(page==='settings'&&location.hash==='#siem'?'/login#siem':'/login');
        throw new Error(result.error||'Request failed');
    }
    return result;
}
const notice=(text,severity='success')=>{byId('notice').textContent=text;if(text&&window.LinkScopeToast)window.LinkScopeToast.message(severity,severity==='error'?'Action failed':'LinkScope',text);};
const failure=ex=>notice(ex.message||String(ex),'error');
function table(rows,key,alertRecords){
    const container=element('div');container.className='tablewrap';if(!rows.length){container.append(element('small','No records in this sample.'));return container;}
    const keys=[...new Set(rows.flatMap(row=>Object.keys(row)))];const t=element('table'),head=t.createTHead().insertRow(),body=t.createTBody();
    const endpointHeaders={utc:'Timestamp',firstUtc:'First detected',lastUtc:'Last detected',durationMs:'Duration (ms)',actualHash:'Actual SHA-256',expectedHash:'Expected SHA-256',result:'Result',path:'File / path',source:'Scan type',severity:'Severity',detail:'Details',status:'Status',hash:'SHA-256',change:'Detection',review:'Review / actions'};
    keys.forEach(k=>head.append(element('th',page==='endpoint'?(endpointHeaders[k]||k):k)));
    for(const row of rows){const tr=body.insertRow();for(const k of keys){const v=row[k];const cell=tr.insertCell(),stamp=page==='endpoint'&&/^(utc|.*Utc)$/.test(k)&&typeof v==='string'&&Number.isFinite(Date.parse(v)),text=v==null?'—':stamp?new Date(v).toLocaleString():typeof v==='object'?JSON.stringify(v):String(v);if(stamp)cell.title=v;const kind=(page==='system'||page==='integrity'||page==='endpoint')?healthCellKind(key,k,v):null;if(kind)cell.append(healthBadge(text,kind));else cell.textContent=text;}if(alertRecords){const a=alertRecords[body.rows.length-1];if(a&&page==='endpoint'&&key==='endpoint active alert diagnostics'){endpointAlertActions(tr.cells[tr.cells.length-1],a,tr);}else if(a&&window.LinkScopeToast?.attachAlertRow){window.LinkScopeToast.attachAlertRow(tr,a,tr.cells[1]||tr.cells[0]);}}}
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
const endpointFlags=['WebManualQuarantineEnabled','WebProtectionEnabled','WebProcessAuditEnabled','Enabled','WriteEvents','RealTime','ProcessCorrelation','SignatureScheduleEnabled','MetadataFastCache','BackgroundPauseOnBusyDisk','BackgroundPauseOnBattery','BackgroundPauseOnLowMemory'];
const endpointNumbers={IntervalSeconds:'EndpointInterval',ChangeThreshold:'EndpointThreshold',Port:'EndpointPort',MaxFileMiB:'EndpointMaxFileMiB',BackgroundReadMiB:'EndpointBackgroundReadMiB',BehaviorWindowSeconds:'EndpointBehaviorWindowSeconds',ExtendedEntropyWindowSeconds:'EndpointExtendedEntropyWindowSeconds',ExtendedEntropyThreshold:'EndpointExtendedEntropyThreshold',EntropyMinimumSampleBytes:'EndpointEntropyMinimumSampleBytes',EntropyMinimumCurrent:'EndpointEntropyMinimumCurrent',EntropyMinimumIncrease:'EndpointEntropyMinimumIncrease',MemoryMinimumAvailableMiB:'EndpointMemoryMinimumAvailableMiB',MemoryMinimumAvailablePercent:'EndpointMemoryMinimumAvailablePercent',BackgroundBatchSize:'EndpointBackgroundBatchSize',SignatureMemoryDeferralMinutes:'EndpointSignatureMemoryDeferralMinutes'};
const endpointArrays=['WebPaths','Paths','ExcludedPaths','BackgroundExcludedPaths','ExcludedPatterns','CanaryPaths','ResponsePaths','TestPaths','ContainmentExecutables'];
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
    const testCandidates=selectedPaths.filter(p=>protectedPaths.some(r=>responseUnder(p,r))&&!selectedPaths.some(other=>other.toLowerCase()!==p.toLowerCase()&&responseUnder(other,p)));
    fillResponseOptions('EndpointSuggestedTest',testCandidates,'Choose a dedicated leaf response path first');
    byId('EndpointAddSuggestedTest').disabled=!byId('EndpointSuggestedTest').value;
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
    checkboxList('scopes',[...model.core,...config.ExtraCategories],model.core);tokenRows(model.tokens);refreshEndpointHistoryReset().catch(failure);
}
let endpointHistoryResetBusy=false,endpointHistoryResetSeen="",endpointHistoryResetPolling=false;
async function refreshEndpointHistoryReset(){
    if(!csrf||endpointHistoryResetPolling)return;
    endpointHistoryResetPolling=true;
    try{const r=await request('/ui/endpoint-history-reset');
    const busy=r.state==='Queued'||r.state==='Running';
    byId('EndpointHistoryReset').disabled=busy||endpointHistoryResetBusy||!config?.Endpoint?.Enabled;
    const status=byId('EndpointHistoryResetStatus');
    status.textContent=r.state==='Completed'?'History reset completed; a new baseline is scheduled.':r.state==='Failed'?'Reset failed or was interrupted. Check the service log; an incomplete central cleanup is retried by the worker.':busy?'Endpoint history reset '+r.state.toLowerCase()+'…':'';
    if(r.state==='Completed'&&r.id!==endpointHistoryResetSeen){endpointHistoryResetSeen=r.id;if(r.through)window.LinkScopeToast?.categoryRead?.('endpoint_protection',r.through);}
    return r;}finally{endpointHistoryResetPolling=false;}
}
async function resetEndpointHistory(){
    if(!csrf||endpointHistoryResetBusy)return;
    if(formDirty){notice('Save or discard settings changes first.','error');return;}
    endpointHistoryResetBusy=true;byId('EndpointHistoryReset').disabled=true;
    try{
        if(!(await confirmAction('Permanently reset Endpoint Protection history?', 'Delete endpoint scan activity, resolved findings and alert history, and schedule a new baseline. Active security findings, quarantine evidence, canary hashes, pending journal work and other modules are retained. This cannot be undone.','Delete endpoint history',true)))return;
        await request('/ui/endpoint-history-reset',{confirmation:'RESET ENDPOINT HISTORY'});
        notice('Endpoint history reset queued. Completion will appear in Settings.');
    }catch(e){failure(e);}finally{endpointHistoryResetBusy=false;refreshEndpointHistoryReset().catch(failure);}
}
// One accessible dialog for every settings help icon. It never submits the form.
function setupSettingsHelp(){
    const dialog=byId('setting-help-dialog');if(!dialog)return;
    const close=byId('setting-help-close');let opener=null;
    for(const trigger of document.querySelectorAll('[data-setting-help]'))trigger.addEventListener('click',()=>{
        const source=byId(trigger.dataset.settingHelp);if(!source||dialog.open)return;
        opener=trigger;byId('setting-help-title').textContent=trigger.dataset.helpTitle;
        byId('setting-help-content').textContent=source.textContent.trim();
        dialog.showModal();close.focus();
    });
    close.addEventListener('click',()=>dialog.close());
    dialog.addEventListener('close',()=>{if(opener&&opener.isConnected)opener.focus();opener=null;});
    dialog.addEventListener('click',event=>{if(event.target!==dialog)return;const r=dialog.getBoundingClientRect();if(event.clientX<r.left||event.clientX>r.right||event.clientY<r.top||event.clientY>r.bottom)dialog.close();});
}
function settingsPage(){
    setupSettingsHelp();
    byId('EndpointHistoryReset').onclick=resetEndpointHistory;
    setInterval(()=>refreshEndpointHistoryReset().catch(()=>{}),3000);

    const categories=[...document.querySelectorAll('details.settings-category')];
    ensureSettingsQuickLinks(categories);
    const hashTarget=location.hash?byId(location.hash.slice(1)):null;
    if(hashTarget&&hashTarget.matches('details.settings-category'))setTimeout(()=>{hashTarget.open=true;hashTarget.scrollIntoView({behavior:'smooth',block:'start'});},50);
    byId('settings-expand-all').onclick=()=>{for(const d of categories)d.open=true;};
    byId('settings-collapse-all').onclick=()=>{for(const d of categories)d.open=false;};
    for(const form of [byId('configForm'),byId('tokenForm')])form.addEventListener('invalid',event=>{const d=event.target.closest('details.settings-category');if(d)d.open=true;},true);
    byId('configForm').addEventListener('input',()=>{formDirty=true;});
    for(const id of ['EndpointPaths','EndpointResponsePaths'])byId(id).addEventListener('input',updateResponseSuggestions);
    byId('EndpointSuggestedResponse').onchange=()=>{byId('EndpointAddSuggestedResponse').disabled=!byId('EndpointSuggestedResponse').value;};
    byId('EndpointSuggestedExecutable').onchange=()=>{byId('EndpointAddSuggestedExecutable').disabled=!byId('EndpointSuggestedExecutable').value;};
    byId('EndpointAddSuggestedResponse').onclick=()=>addResponseSuggestion('EndpointSuggestedResponse','EndpointResponsePaths');
    byId('EndpointAddSuggestedExecutable').onclick=()=>addResponseSuggestion('EndpointSuggestedExecutable','EndpointContainmentExecutables');
    byId('EndpointSuggestedTest').onchange=()=>{byId('EndpointAddSuggestedTest').disabled=!byId('EndpointSuggestedTest').value;};
    byId('EndpointAddSuggestedTest').onclick=()=>addResponseSuggestion('EndpointSuggestedTest','EndpointTestPaths');
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
            // Preserve explicit canaries when an administrator narrows scan roots.
            // Never silently re-add a parent directory or an entire volume.
            const missingCanaryPaths=next.Endpoint.CanaryPaths.filter(p=>!next.Endpoint.Paths.some(root=>responseUnder(p,root)));
            if(missingCanaryPaths.length){
                if(!(await confirmAction('Keep enrolled canary files monitored?', 'Your new scan scope does not contain these canaries. Add only the exact files below (not their parent folders or drives)?\n'+missingCanaryPaths.join('\n'), 'Keep canaries')))return;
                next.Endpoint.Paths=[...new Set([...next.Endpoint.Paths,...missingCanaryPaths])];
            }

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
function makeMetricJump(card,targetId,explanation,openId){
    if(!card||!targetId)return card;
    card.classList.add('health-metric-card-action');card.tabIndex=0;card.setAttribute('role','button');card.title=explanation||'Open evidence';
    const go=()=>{
        if(openId){const d=byId(openId);if(d)d.open=true;}
        const target=byId(targetId);if(target){endpointJump(target);for(let p=target.parentElement;p;p=p.parentElement)if(p.tagName==='DETAILS')p.open=true;target.scrollIntoView({behavior:'smooth',block:'start'});target.classList.add('metric-jump-highlight');setTimeout(()=>target.classList.remove('metric-jump-highlight'),1800);if(typeof target.focus==='function'&&target.tabIndex>=0)target.focus({preventScroll:true});}
    };
    card.addEventListener('click',go);
    card.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();go();}});
    return card;
}
function ensureSettingsQuickLinks(categories){
    const toolbar=document.querySelector('body[data-page=settings] .settings-category-toolbar');
    if(!toolbar||byId('settings-quick-links'))return;
    const strip=element('div');strip.id='settings-quick-links';strip.className='settings-quick-links';strip.setAttribute('role','group');strip.setAttribute('aria-label','Jump to settings category');
    for(const d of categories){
        const summary=d.querySelector('summary');const title=d.querySelector('.settings-category-title')?.textContent?.trim()||d.id||'Category';
        const sourceIcon=d.querySelector('.settings-category-icon');const button=document.createElement('button');button.type='button';button.className='secondary settings-quick-link';button.title=title;button.setAttribute('aria-label',title);
        if(sourceIcon)button.append(sourceIcon.cloneNode(true));
        const name=element('span',title);name.className='settings-quick-name';button.append(name);
        button.setAttribute('aria-controls',d.id);button.setAttribute('aria-expanded',String(d.open));
        d.addEventListener('toggle',()=>button.setAttribute('aria-expanded',String(d.open)));
        button.addEventListener('click',()=>{d.open=true;d.scrollIntoView({behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth',block:'start'});history.replaceState(null,'','#'+d.id);});
        strip.append(button);
    }
    toolbar.after(strip);
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

let epView='overview',epRenderKey='',epAckPending=false;
function applyEndpointView(){
    if(page!=='endpoint')return;
    document.querySelectorAll('[data-endpoint-view]').forEach(n=>{n.hidden=!n.dataset.endpointView.split(' ').includes(epView);});
    document.querySelectorAll('[data-ep-tab]').forEach(n=>n.setAttribute('aria-pressed',String(n.dataset.epTab===epView)));
}
function selectEndpointView(view,writeHash=true){
    if(!['overview','scan','behavior','web','maintenance','resources','evidence','quarantine','tests'].includes(view))return;
    epView=view;applyEndpointView();if(writeHash)history.replaceState(null,'','#view-'+view);
}
function endpointJump(target){
    if(!target||page!=='endpoint')return;
    const owner=target.closest('[data-endpoint-view]');if(owner){const views=owner.dataset.endpointView.split(' ');if(!views.includes(epView))selectEndpointView(views[0],false);}
}
function setupEndpointWorkspace(){
    const nav=byId('endpoint-views');if(!nav)return;setupContainmentTests();const webEvidence=byId('ep-web-evidence');if(webEvidence)webEvidence.onclick=()=>{selectEndpointView('evidence');const d=byId('endpoint-alert-diagnostics');if(d)d.open=true;};
    const review=byId('endpoint-alert-diagnostics');if(review){
        review.addEventListener('pointerdown',e=>{if(e.target.closest('button,input,select,summary'))endpointReviewPointer=true;});
        const release=()=>{if(endpointReviewPointer){endpointReviewPointer=false;setTimeout(()=>renderEndpointAlertReview(),0);}};
        window.addEventListener('pointerup',release);window.addEventListener('pointercancel',release);window.addEventListener('blur',release);
    }
    nav.addEventListener('click',e=>{const b=e.target.closest('[data-ep-tab]');if(b)selectEndpointView(b.dataset.epTab);});
    for(const id of ['ep-overview','ep-web-protection'])byId(id)?.addEventListener('click',e=>{const b=e.target.closest('[data-ep-go]');if(b)selectEndpointView(b.dataset.epGo);});
    byId('ep-status-reasons').addEventListener('click',()=>{const panel=byId('ep-attention');panel.focus();panel.scrollIntoView({block:'nearest'});});
    if(location.hash.startsWith('#view-'))selectEndpointView(location.hash.slice(6),false);else if(location.hash==='#endpoint-alert-diagnostics'){selectEndpointView('evidence',false);byId('endpoint-alert-diagnostics').open=true;}else applyEndpointView();
}
function epTestCards(target,rows){
    const node=byId(target);if(!node)return;const key=JSON.stringify(rows);if(node.dataset.key===key)return;node.dataset.key=key;
    node.replaceChildren(...rows.map(row=>{const card=element('article');card.className='ep-test-card';const top=element('div');top.className='ep-test-card-top';top.append(element('strong',row.name),healthBadge(row.state,row.state==='Pass'?'ok':row.state==='Fail'?'fail':row.state==='Review'?'review':'unknown'));card.append(top,element('p',row.evidence));if(Number.isFinite(row.durationMs))card.append(element('small',row.durationMs+' ms'));if(row.sourceUtc)card.append(element('small','Source UTC: '+row.sourceUtc));return card;}));
}
// V58: session-local workflow progress. Navigation is never a test verdict.
const epStepLabels=['Prepare','Run diagnostics','Verify live audit','Identify a writer','Test live protection','Review evidence'];
let epTestStep=1,epDiagnosticBusy=false,epSuiteBusy=false,epSuiteReport=null,epReadinessRows=[],epReadinessObservedAt=0,epReadinessAge=Infinity,epReadinessUtc=null;
let epSyncDiagnostics=()=>{};
const epStepResults=['Awaiting telemetry','Not run','Not run','Not run','Not run','Review results'];
function epStepResult(step,value){
    epStepResults[step-1]=value;const label=byId('ep-step-state-'+step);if(label&&label.textContent!==value)label.textContent=value;
    const review=byId('ep-test-review');if(!review)return;const key=JSON.stringify(epStepResults);if(review.dataset.key===key)return;review.dataset.key=key;
    review.replaceChildren(...epStepLabels.slice(0,5).map((name,i)=>{const row=element('div');row.className='ep-review-row';row.append(element('strong',name),element('span',epStepResults[i]));return row;}));
}
function epSelectStep(step,focus=true){
    if(!Number.isInteger(step)||step<1||step>epStepLabels.length)return;epTestStep=step;
    document.querySelectorAll('[data-test-panel]').forEach(p=>{p.hidden=Number(p.dataset.testPanel)!==step;});
    document.querySelectorAll('[data-test-step]').forEach(b=>{if(Number(b.dataset.testStep)===step)b.setAttribute('aria-current','step');else b.removeAttribute('aria-current');});
    byId('ep-step-counter').textContent='Step '+step+' of '+epStepLabels.length;byId('ep-step-back').disabled=step===1;const next=byId('ep-step-next');next.hidden=step===epStepLabels.length;next.textContent=step<epStepLabels.length?'Next: '+epStepLabels[step]:'Complete';
    if(focus){const heading=byId('ep-stage-'+step);if(heading)heading.focus();}
}
let epAuditBusy=false;
let epExternalBusy=false,epProtectionBusy=false;
function epAuditControls(paths,testPaths){
    const select=byId('ep-audit-directory'),button=byId('ep-audit-run');if(!select||!button)return;
    if(paths!==undefined){const configured=new Set((Array.isArray(testPaths)?testPaths:[]).filter(x=>typeof x==='string').map(x=>x.toLowerCase()));const available=Array.from(new Set(paths.filter(x=>configured.has(String(x.path).toLowerCase())&&!paths.some(other=>other.path.toLowerCase()!==x.path.toLowerCase()&&responseUnder(other.path,x.path))&&x.status==='ok'&&String(x.detail||'').startsWith('Directory list and delete-child access granted')).map(x=>x.path))),key=JSON.stringify(available);
        if(select.dataset.key!==key){const previous=select.value;select.dataset.key=key;select.replaceChildren(new Option(available.length?'Choose a saved test directory':'No verified saved test directories',''),...available.map(path=>new Option(path,path)));if(available.includes(previous))select.value=previous;else if(available.length===1)select.value=available[0];}
    }
    select.disabled=epProtectionBusy||epExternalBusy||epAuditBusy||epSuiteBusy||epDiagnosticBusy||select.options.length<=1;button.disabled=epAuditBusy||epSuiteBusy||select.disabled||!select.value;
    const suite=byId('ep-suite-directory'),run=byId('ep-suite-run');if(suite&&run){const key=select.dataset.key||'[]';if(suite.dataset.key!==key){const previous=suite.value;suite.dataset.key=key;suite.replaceChildren(...Array.from(select.options,x=>new Option(x.text,x.value)));suite.value=previous&&Array.from(suite.options).some(x=>x.value===previous)?previous:select.value;}suite.disabled=epProtectionBusy||epExternalBusy||epSuiteBusy||epAuditBusy||epDiagnosticBusy||suite.options.length<=1;run.disabled=suite.disabled||!suite.value;}

    const external=byId('ep-external-directory'),externalRun=byId('ep-external-run');if(external&&externalRun){const key=select.dataset.key||'[]';if(external.dataset.key!==key){const previous=external.value;external.dataset.key=key;external.replaceChildren(...Array.from(select.options,x=>new Option(x.text,x.value)));external.value=previous&&Array.from(external.options).some(x=>x.value===previous)?previous:select.value;}external.disabled=epProtectionBusy||epExternalBusy||epSuiteBusy||epAuditBusy||epDiagnosticBusy||external.options.length<=1;externalRun.disabled=external.disabled||!external.value;const command=byId('ep-manual-lab-command');if(command)command.textContent=external.value?'& "$env:ProgramFiles\\LinkScope\\lab\\Test-LinkScopeContainmentLab.ps1" -LabRoot '+"'"+external.value.replace(/'/g,"''")+"'":'Select a saved Test Center directory above to generate the command.';}
    const lab=byId('ep-protection-directory'),labRun=byId('ep-protection-run'),include=byId('ep-suite-protection');if(lab&&labRun){const available=Array.from(select.options).map(x=>x.value).filter(Boolean);const leaf=available.filter(x=>!available.some(y=>y.toLowerCase().startsWith(x.replace(/\\+$/,'').toLowerCase()+'\\')&&y.toLowerCase()!==x.toLowerCase()));const key=JSON.stringify(leaf);if(lab.dataset.key!==key){const previous=lab.value;lab.dataset.key=key;lab.replaceChildren(new Option('Choose dedicated test directory',''),...leaf.map(x=>new Option(x,x)));if(leaf.includes(previous))lab.value=previous;else if(leaf.length===1)lab.value=leaf[0];}lab.disabled=epProtectionBusy||epSuiteBusy||epAuditBusy||epDiagnosticBusy||epExternalBusy||!leaf.length;labRun.disabled=lab.disabled||!lab.value;const full=byId('ep-suite-full');if(full)full.disabled=!suite||suite.disabled||!leaf.includes(suite.value);if(include){include.disabled=epSuiteBusy||epProtectionBusy;if(include.checked&&suite&&suite.value&&!leaf.includes(suite.value)){run.disabled=true;if(!epSuiteBusy)byId('ep-suite-status').textContent='Select a dedicated leaf response directory for the isolated protection lab (not its parent).';}}}

}
// Only server-returned, nonempty evidence is displayed as a test result.
// A missing/malformed result is inconclusive, never an implicit pass.
const epAuditRequired=['Selected audit scope','Disposable marker write','Marker cleanup','Exact Event 4663 / service writer'];
const epDiagnosticRequired=['Containment policy','Entropy detector (in memory)','Behavior aggregation (in memory)','Canary hash (in memory)','Response refusal gate (in memory)','Security log readability','File system audit evidence'];
function epVerifiedRows(result,required){
    if(!result||!Array.isArray(result.checks)||!Number.isFinite(Date.parse(result.utc)))throw new Error('Missing valid server result or execution timestamp');
    const rows=result.checks.map((row,i)=>{
        if(!row||typeof row.name!=='string'||!row.name.trim()||typeof row.evidence!=='string'||!row.evidence.trim()||!['Pass','Review','Fail','Not tested'].includes(row.state))return {name:'Invalid result row '+(i+1),state:'Review',evidence:'Malformed or missing server evidence; no verdict.',sourceUtc:result.utc};
        return {...row,sourceUtc:result.utc};
    });
    for(const name of required){const hits=rows.filter(x=>x.name===name);if(hits.length!==1){for(const x of hits){x.state='Review';x.evidence='Duplicate result; cannot establish a unique verdict. '+x.evidence;}if(!hits.length)rows.push({name,state:'Not tested',evidence:'Required check was not returned by the service.',sourceUtc:result.utc});}}
    return rows;
}
function epReadinessSnapshot(phase='suite start'){
    const age=epReadinessAge+(performance.now()-epReadinessObservedAt)/1000;
    if(!epReadinessRows.length||!epReadinessUtc||!Number.isFinite(age)||age<0||age>20)return [{name:'Current telemetry',state:'Not tested',evidence:'No fresh readiness snapshot at '+phase+'. No readiness verdict.'}];
    return epReadinessRows.map(x=>({...x,sourceUtc:epReadinessUtc,evidence:x.evidence+' [Telemetry snapshot; age '+Math.round(age)+' s at '+phase+'.]'}));
}
// A final snapshot must be collected after the live probe, not just fetched after it.
async function epRefreshFinalReadiness(afterUtc){
    const cutoff=Date.parse(afterUtc);
    if(!Number.isFinite(cutoff))return [{name:'Current telemetry',state:'Review',evidence:'No valid post-probe cutoff; final telemetry cannot be verified.'}];
    const deadline=performance.now()+8000;let reason='No post-test telemetry sample returned';
    do{
        try{
            const data=await request('/ui/endpoint');const sample=data?.categories?.endpoint_protection;
            if(sample&&!sample.stale&&Number.isFinite(sample.ageSeconds)&&sample.ageSeconds>=0&&sample.ageSeconds<=20&&Date.parse(sample.collectedUtc)>=cutoff){
                renderContainmentReadiness(sample);return epReadinessSnapshot('suite end');
            }
            reason='Latest sample predates the final diagnostic or is stale/unavailable';
        }catch(ex){reason='Telemetry refresh failed: '+ex.message;break;}
        if(performance.now()>=deadline)break;
        await new Promise(resolve=>setTimeout(resolve,750));
    }while(performance.now()<deadline);
    return [{name:'Current telemetry',state:'Review',evidence:reason+'. Initial telemetry is retained separately; no final readiness verdict.'}];
}
function epAuditProofMatches(result,directory){
    const m=result?.marker,p=result?.proof;
    if(!m||!p||typeof directory!=='string'||typeof m.path!=='string'||typeof m.image!=='string'||!m.image.trim()||typeof p.path!=='string'||typeof p.image!=='string')return false;
    const root=directory.replace(/\\+$/,'').toLowerCase()+'\\',path=m.path.toLowerCase();
    const event=Date.parse(p.eventUtc),start=Date.parse(m.startedUtc),finish=Date.parse(result.utc);
    // Compare decimal record IDs without Number precision loss.
    const baseline=m.baselineRecordId,record=p.recordId;
    if(typeof baseline!=='string'||typeof record!=='string'||!/^[1-9][0-9]{0,18}$/.test(baseline)||!/^[1-9][0-9]{0,18}$/.test(record)||!(record.length>baseline.length||(record.length===baseline.length&&record>baseline)))return false;
    return path.startsWith(root)&&/^linkscope-audit-probe-[0-9a-f]{32}\.txt$/.test(path.slice(root.length))&&p.path.toLowerCase()===path&&p.image.toLowerCase()===m.image.toLowerCase()&&Number.isSafeInteger(m.pid)&&m.pid>4&&p.pid===m.pid&&p.eventId===4663&&typeof p.recordId==='string'&&/^[1-9][0-9]*$/.test(p.recordId)&&Number.isSafeInteger(p.accessMask)&&p.accessMask>0&&(p.accessMask&6)!==0&&Number.isFinite(event)&&Number.isFinite(start)&&Number.isFinite(finish)&&event>=start-1000&&event<=finish+2000;
}
async function epRunAudit(directory){
    epAuditBusy=true;epAuditControls();const status=byId('ep-audit-status');
    try{epStepResult(3,'Running');status.textContent='Writing marker and waiting for Windows audit evidence…';epTestCards('ep-audit-results',[]);
        const result=await request('/ui/endpoint-audit-probe',{directory});const rows=epVerifiedRows(result,epAuditRequired);
        for(const row of rows.filter(x=>x.name==='Exact Event 4663 / service writer'&&x.state==='Pass')){
            if(!epAuditProofMatches(result,directory)){row.state='Review';row.evidence='Missing or inconsistent structured event proof. No writer verification. Server reported: '+row.evidence;}
        }
        const reportedPass=epAuditRequired.every(name=>rows.some(row=>row.name===name&&row.state==='Pass'));
        const passed=result.passed===true&&reportedPass&&!rows.some(row=>row.state==='Fail'||row.state==='Review');
        if(result.passed===true&&!passed||result.passed!==true&&reportedPass)rows.push({name:'Audit result consistency',state:'Review',evidence:'Service summary and individual checks do not establish a consistent pass.',sourceUtc:result.utc});
        epTestCards('ep-audit-results',rows);
        epStepResult(3,passed?'Passed · self-writer only':'Review evidence');status.textContent=(passed?'Live audit verification passed':'Live audit verification requires review')+' · '+localEndpointDate(result.utc)+' · no production containment executed.';return rows;
    }catch(ex){epStepResult(3,'Result unavailable');status.textContent='Live audit result unavailable: '+ex.message+'. If the request timed out, the server may have completed the probe; wait before retrying.';return [{name:'Live audit request',state:'Review',evidence:status.textContent}];}finally{epAuditBusy=false;epAuditControls();}
}
const epExternalRequired=['Selected audit scope','Disposable marker write','Marker cleanup','Exact Event 4663 / external writer','External writer exit'];
function epExternalProofMatches(result,directory){
    const m=result?.marker,p=result?.proof,created=Date.parse(m?.processCreatedUtc);
    return epAuditProofMatches(result,directory)&&m.external===true&&Number.isSafeInteger(m.servicePid)&&m.servicePid>4&&m.pid!==m.servicePid&&/^[a-z]:\\[^\r\n]+\\WindowsPowerShell\\v1\.0\\powershell\.exe$/i.test(m.image)&&Number.isFinite(created)&&created>=Date.parse(m.startedUtc)-1000&&created<=Date.parse(p.eventUtc);
}
async function epRunExternal(directory){
    epExternalBusy=true;epAuditControls();const status=byId('ep-writer-status'),marker=byId('ep-external-marker');marker.value='';
    try{epStepResult(4,'Running');status.textContent='Starting installed PowerShell lab and collecting real audit evidence…';epTestCards('ep-writer-results',[]);
        const result=await request('/ui/endpoint-external-probe',{directory});const rows=epVerifiedRows(result,epExternalRequired);
        if(typeof result.marker?.path==='string'&&result.marker.path.length<=1024)marker.value=result.marker.path;
        for(const row of rows.filter(x=>x.name==='Exact Event 4663 / external writer'&&x.state==='Pass'))if(!epExternalProofMatches(result,directory)){row.state='Review';row.evidence='Missing or inconsistent independent writer proof. '+row.evidence;}
        const reportedPass=epExternalRequired.every(name=>rows.some(row=>row.name===name&&row.state==='Pass'));
        const passed=result.passed===true&&reportedPass&&!rows.some(row=>row.state==='Fail'||row.state==='Review');
        if(result.passed===true&&!passed||result.passed!==true&&reportedPass)rows.push({name:'External writer result consistency',state:'Review',evidence:'Service summary and individual checks do not establish a consistent pass.',sourceUtc:result.utc});
        epTestCards('ep-writer-results',rows);epStepResult(4,passed?'Passed · independent PowerShell writer':'Review evidence');status.textContent=(passed?'External writer verification passed':'External writer verification requires review')+' · '+localEndpointDate(result.utc)+' · no production response executed.';
        return rows.filter(x=>x.name!=='Production containment');
    }catch(ex){epStepResult(4,'Result unavailable');status.textContent='External writer result unavailable: '+ex.message;return [{name:'External writer request',state:'Review',evidence:status.textContent}];}finally{epExternalBusy=false;epAuditControls();}
}
const epProtectionRequired=['Lab scope and engine','Disposable canary comparison','Canary cleanup','Live enrolled-canary watcher detection','Controlled production incident attribution','Live containment target refusal','Owned child termination mechanics','Enrolled canary cleanup','EICAR sample creation','EICAR signature detection','EICAR sealed quarantine','EICAR original cleanup'];
function epProtectionProof(result,directory){
    const p=result?.proof,run=result?.runId;const id=x=>typeof x==='string'&&/^[1-9][0-9]{0,18}$/.test(x),root=directory.replace(/\\+$/,'')+'\\';
    const start=Date.parse(result?.startedUtc),finish=Date.parse(result?.utc),receiptUtc=Date.parse(p?.receiptUtc);
    const validRun=typeof run==='string'&&/^[a-f0-9]{32}$/.test(run)&&result.directory===directory&&Number.isFinite(start)&&Number.isFinite(finish)&&finish>=start;
    const later=(a,b)=>a.length>b.length||(a.length===b.length&&a>b);
    const c=validRun&&p?.canaryPath===root+'LinkScope-Lab-Canary-'+run+'.txt'&&p.expected==='91f9caa3348b49940b33bdd45fd185d529fafac274015516123ecaa112f68283'&&p.actual==='c71185d7e1e13483b70632d74ae30177e79378ee817cb620cb3d9ed802b31d7b'&&id(p.canaryIncident);
    const sample=validRun&&p?.sampleCreated===true&&p.eicarPath===root+'LinkScope-Lab-EICAR-'+run+'.com'&&p.eicarHash==='275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
    const e=sample&&typeof p.incidentWatermark==='string'&&/^(0|[1-9][0-9]{0,18})$/.test(p.incidentWatermark)&&id(p.malwareIncident)&&later(p.malwareIncident,p.incidentWatermark)&&typeof p.verdict==='string'&&/^stream: .*eicar.* FOUND$/i.test(p.verdict)&&!/Heuristics\./i.test(p.verdict);
    return {scope:validRun&&p?.scopeVerified===true,sample,canary:c,canaryClean:c&&p.canaryClean===true,detection:e,quarantine:e&&id(p.quarantineIncident)&&later(p.quarantineIncident,p.malwareIncident)&&/^[a-f0-9]{32}$/.test(p.receipt||'')&&Number.isFinite(receiptUtc)&&receiptUtc>=start&&receiptUtc<=finish+2000&&p.quarantineVerified===true&&p.eicarClean===true,cleanup:sample&&p.eicarClean===true};
}
// Evidence must identify the newly enrolled file and the actual production detector incident.
function epEnrolledProof(result,directory){
    const p=result?.proof?.enrolled,run=result?.runId;const decimal=x=>typeof x==='string'&&/^(0|[1-9][0-9]{0,18})$/.test(x),later=(a,b)=>decimal(a)&&decimal(b)&&(a.length>b.length||(a.length===b.length&&a>b));
    const start=Date.parse(result?.startedUtc),finish=Date.parse(result?.utc),modified=Date.parse(p?.modifiedUtc),event=Date.parse(p?.eventUtc);
    const scope=typeof run==='string'&&/^[a-f0-9]{32}$/.test(run)&&result.directory===directory&&p?.path===directory.replace(/\\+$/,'')+'\\LinkScope-Lab-Enrolled-'+run+'.txt'&&p.expected==='91f9caa3348b49940b33bdd45fd185d529fafac274015516123ecaa112f68283'&&p.changed==='c71185d7e1e13483b70632d74ae30177e79378ee817cb620cb3d9ed802b31d7b'&&p.registered===true;
    const incident=scope&&p.detected===true&&later(p.seq,p.incidentBaseline)&&Number.isFinite(start)&&Number.isFinite(finish)&&Number.isFinite(modified)&&modified>=start&&modified<=finish;
    const mask=typeof p?.mask==='string'&&/^0x[0-9a-f]{1,8}$/i.test(p.mask)?parseInt(p.mask,16):0;
    const attribution=incident&&p.attributed===true&&later(p.record,p.securityBaseline)&&Number.isSafeInteger(p.pid)&&p.pid>4&&p.pid===p.expectedPid&&typeof p.image==='string'&&p.image.length>0&&typeof p.expectedImage==='string'&&p.image.toLowerCase()===p.expectedImage.toLowerCase()&&Number.isFinite(event)&&event>=modified&&event<=finish+2000&&(mask&6)!==0;
    return {watcher:incident&&p.source==='watcher',attribution,refusal:attribution&&p.refusal===true,cleanup:scope&&p.clean===true&&p.baselineRemoved===true};
}
// Only the fixed child launched during this run is eligible for a mechanics Pass.
function epOwnedTerminationProof(result,directory){
    const p=result?.proof?.termination,start=Date.parse(result?.startedUtc),finish=Date.parse(result?.utc),created=Date.parse(p?.createdUtc),requested=Date.parse(p?.requestedUtc),observed=Date.parse(p?.observedUtc);
    return typeof result?.runId==='string'&&/^[a-f0-9]{32}$/.test(result.runId)&&result.directory===directory&&result.proof?.scopeVerified===true&&[start,finish,created,requested,observed].every(Number.isFinite)&&created>=start-1000&&created<=requested&&requested<=observed&&observed<=finish&&observed-requested<=3000&&Number.isSafeInteger(p?.pid)&&p.pid>4&&Number.isSafeInteger(p.servicePid)&&p.servicePid>4&&p.pid!==p.servicePid&&p.handlePid===p.pid&&typeof p.image==='string'&&typeof p.expectedImage==='string'&&p.image.toLowerCase()===p.expectedImage.toLowerCase()&&/^[a-z]:\\.+\\system32\\windowspowershell\\v1\.0\\powershell\.exe$/i.test(p.image)&&p.identityVerified===true&&p.ready===true&&p.requested===true&&p.exitVerified===true&&p.childExited===true&&p.expectedExitCode===0x4C530068&&p.observedExitCode===0x4C530068;
}
async function epRunProtection(directory){
    epProtectionBusy=true;epAuditControls();const status=byId('ep-protection-status');epStepResult(5,'Running');status.textContent='Starting isolated protection lab; awaiting real scanner evidence…';epTestCards('ep-protection-results',[]);
    try{let job=await request('/ui/endpoint-protection-lab',{action:'start',directory,confirmed:true});const jobId=job?.jobId;if(typeof jobId!=='string'||!/^[a-f0-9]{32}$/.test(jobId))throw new Error('Invalid lab job identifier');const deadline=performance.now()+75000;
        while(!job.done&&performance.now()<deadline){await new Promise(resolve=>setTimeout(resolve,750));job=await request('/ui/endpoint-protection-lab',{action:'status',jobId});if(job?.jobId!==jobId)throw new Error('Lab job identity changed');}
        if(!job.done||!job.result)throw new Error('Lab job still running or result unavailable; inspect the vault before retrying');const result=job.result,rows=epVerifiedRows(result,epProtectionRequired),proof=epProtectionProof(result,directory),enrolled=epEnrolledProof(result,directory);
        const checks={'Lab scope and engine':proof.scope,'EICAR sample creation':proof.sample,'Disposable canary comparison':proof.canary,'Canary cleanup':proof.canaryClean,'Live enrolled-canary watcher detection':enrolled.watcher,'Controlled production incident attribution':enrolled.attribution,'Live containment target refusal':enrolled.refusal,'Owned child termination mechanics':epOwnedTerminationProof(result,directory),'Enrolled canary cleanup':enrolled.cleanup,'EICAR signature detection':proof.detection,'EICAR sealed quarantine':proof.quarantine,'EICAR original cleanup':proof.cleanup};
        for(const row of rows)if(row.state==='Pass'&&(!Object.prototype.hasOwnProperty.call(checks,row.name)||!checks[row.name])){row.state='Review';row.evidence='Missing or inconsistent lab proof. '+row.evidence;}
        const pass=epProtectionRequired.every(n=>rows.some(x=>x.name===n&&x.state==='Pass'))&&!rows.some(x=>x.state==='Review'||x.state==='Fail');epStepResult(5,pass?'Passed · isolated watcher, attribution, quarantine and owned child exit':'Review lab evidence');status.textContent=(pass?'Isolated lab checks passed':'Lab checks require review')+' · '+localEndpointDate(result.utc)+' · no production containment certification.';epTestCards('ep-protection-results',rows);return rows;
    }catch(ex){epStepResult(5,'Result unavailable');status.textContent='Protection lab unavailable: '+ex.message;return [{name:'Protection lab request',state:'Review',evidence:status.textContent}];}finally{epProtectionBusy=false;epAuditControls();epSyncDiagnostics();}
}
function setupLiveAuditProbe(){
    const select=byId('ep-audit-directory'),button=byId('ep-audit-run');if(!select||!button)return;
    const lab=byId('ep-protection-directory'),labButton=byId('ep-protection-run');lab.onchange=()=>epAuditControls();labButton.onclick=async()=>{if(labButton.disabled)return;const directory=lab.value;epProtectionBusy=true;epAuditControls();epSyncDiagnostics();try{if(await confirmAction('Run isolated protection lab?', 'Confirm this is a disposable test directory in an isolated environment: '+directory+'. Creates and temporarily enrolls a disposable canary, writes an EICAR test file, may generate real alerts and retains a sealed quarantine receipt. Launches and terminates only a fixed harmless child owned by this test; no production process is selected.', 'Run protection lab'))await epRunProtection(directory);}finally{epProtectionBusy=false;epAuditControls();epSyncDiagnostics();}};
    select.onchange=()=>epAuditControls();const ext=byId('ep-external-directory'),extButton=byId('ep-external-run');ext.onchange=()=>epAuditControls();extButton.onclick=async()=>{if(extButton.disabled||epProtectionBusy||epExternalBusy||epAuditBusy||epSuiteBusy||epDiagnosticBusy)return;const directory=ext.value;epExternalBusy=true;epAuditControls();epSyncDiagnostics();try{if(await confirmAction('Run automatic writer test?', 'Run the installed fixed PowerShell script under the existing service identity and create/remove one harmless marker in '+directory+'. No policy changes or containment.', 'Run writer test'))await epRunExternal(directory);}finally{epExternalBusy=false;epAuditControls();epSyncDiagnostics();}};button.onclick=async()=>{
        if(button.disabled||epProtectionBusy||epExternalBusy||epAuditBusy||epSuiteBusy||epDiagnosticBusy)return;const directory=select.value;epAuditBusy=true;epAuditControls();epSyncDiagnostics();
        try{if(!await confirmAction('Run live audit test?', 'Create and automatically remove a uniquely named harmless marker in '+directory+'. The test uses existing service permissions only.', 'Run live test'))return;
            await epRunAudit(directory);
        }finally{epAuditBusy=false;epAuditControls();epSyncDiagnostics();}
    };
}
function epProductionCoverage(report){
    const check=(name,key)=>{const matches=report.rows.filter(row=>row.name===key);return matches.length===1?{name,state:matches[0].state,evidence:matches[0].evidence,sourceUtc:matches[0].sourceUtc}: {name,state:matches.length?'Review':'Not tested',evidence:matches.length?'Duplicate capability results; cannot establish a verdict.':'No verified result for this capability in this run.'};};
    return [check('Incident attribution through the normal detector (controlled writer)','Isolated protection / Controlled production incident attribution'),check('Enrolled-canary watcher detection','Isolated protection / Live enrolled-canary watcher detection'),check('Actual EICAR quarantine','Isolated protection / EICAR sealed quarantine'),check('Owned child termination mechanics (controlled)','Isolated protection / Owned child termination mechanics'),check('Production malicious-process termination','Production process containment')];
}
function epRenderSuiteReport(report){
    epSuiteReport=report;byId('ep-suite-report').hidden=false;
    const counts={Pass:0,Review:0,Fail:0,'Not tested':0};for(const row of report.rows)counts[Object.prototype.hasOwnProperty.call(counts,row.state)?row.state:'Review']++;
    const summary=counts.Pass+' passed checks · '+counts.Review+' inconclusive / review · '+counts.Fail+' failed · '+counts['Not tested']+' not tested';
    const overall=counts.Fail?'Failed checks present':counts.Review||counts['Not tested']?'Incomplete validation — not certified':'Reported checks passed — not certified';
    report.summary=overall+' · '+summary;
    byId('ep-suite-summary').textContent=overall+' · '+summary+' · '+report.directory+' · '+localEndpointDate(report.finishedUtc);
    report.productionCoverage=epProductionCoverage(report);epTestCards('ep-suite-production',report.productionCoverage);epTestCards('ep-suite-results',report.rows);
    epTestCards('ep-suite-baseline-results',report.baseline||[]);
    byId('ep-suite-status').textContent='Validation finished. '+overall+'. '+summary+'. See Step 06 for the full report.';
}
function epExportSuite(){
    if(!epSuiteReport)return;const r=epSuiteReport;const text=['LinkScope — Automated validation report','Started UTC: '+r.startedUtc,'Finished UTC: '+r.finishedUtc,'Directory: '+r.directory,'Verdict: '+r.summary,'Scope: initial observations, benign self-writer and independent PowerShell writer probes, optional temporary enrolled-canary watcher, EICAR and owned child termination lab, final diagnostics and fresh readiness telemetry. Controlled normal-detector incidents are not unplanned malicious incidents. No production termination certification.','Pass applies only to the named check; Review means inconclusive or needs attention.','','PRODUCTION READINESS ASSESSMENT — NOT CERTIFIED (summary, not additional checks)',...(r.productionCoverage||epProductionCoverage(r)).map(x=>x.state+' | '+x.name+'\r\n'+x.evidence+(x.sourceUtc?'\r\nSource UTC: '+x.sourceUtc:'')),'','DETAILED VALIDATION RESULTS',...r.rows.map(x=>x.state+' | '+x.name+(Number.isFinite(x.durationMs)?' ('+x.durationMs+' ms)':'')+'\r\n'+x.evidence+(x.sourceUtc?'\r\nSource UTC: '+x.sourceUtc:'')),'','INITIAL OBSERVATIONS (not counted in final verdict; retained for comparison)',...(r.baseline||[]).map(x=>x.state+' | '+x.name+'\r\n'+x.evidence+(x.sourceUtc?'\r\nSource UTC: '+x.sourceUtc:'')),'','Manual exercises must be independently verified.'].join('\r\n\r\n');
    const url=URL.createObjectURL(new Blob([text],{type:'text/plain;charset=utf-8'}));const a=element('a');a.href=url;a.download='LinkScope-validation-'+r.finishedUtc.replace(/[:.]/g,'-')+'.txt';document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function renderContainmentReadiness(v){
    if(!byId('ep-test-readiness'))return;const r=v?.result||{},fresh=!!v&&!v.stale&&Number.isFinite(v.ageSeconds)&&v.ageSeconds>=0&&v.ageSeconds<=20&&Number.isFinite(Date.parse(v.collectedUtc))&&r.status!=='disabled'&&r.engineOnline!=null;
    epReadinessObservedAt=performance.now();epReadinessAge=fresh?Number(v.ageSeconds):Infinity;epReadinessUtc=fresh?v.collectedUtc:null;
    if(!fresh){epReadinessRows=[{name:'Current telemetry',state:'Not tested',evidence:'Disabled, stale or unavailable. No readiness verdict.'}];epStepResult(1,'Telemetry unavailable');epAuditControls([]);epTestCards('ep-test-readiness',[{name:'Current telemetry',state:'Not tested',evidence:'Disabled, stale or unavailable. No readiness verdict.'}]);epTestCards('ep-test-events',[{name:'Current evidence',state:'Not tested',evidence:'Await fresh telemetry.'}]);return;}
    const recentCheck=value=>{const elapsed=(Date.parse(v.collectedUtc)-Date.parse(value))/1000;return Number.isFinite(elapsed)&&elapsed>=0&&elapsed<=90;};
    const responseFresh=recentCheck(r.responseCheckedUtc),signatureFresh=recentCheck(r.lastSignatureCheckUtc);
    const checks=[{name:'Protection mode',state:r.mode==='contain'?'Pass':'Review',evidence:'Saved mode: '+(r.mode||'Unknown')+' (configuration only; not a containment test).'},{name:'Engine and signature freshness',state:r.engineOnline===true&&signatureFresh&&r.signatureFreshness==='Current'&&typeof r.signatureComparison==='string'&&r.signatureComparison.startsWith('Current advertised daily version ')&&r.engineRecoveryPending===false?'Pass':'Review',evidence:(r.engineOnline?'Online':'Unavailable')+'; signatures '+(r.signatureFreshness||'Unknown')+(r.signatureComparison?' · '+r.signatureComparison:'')+' · Last checked UTC: '+(r.lastSignatureCheckUtc||'Unknown')+(signatureFresh?'':' (not recently verified)')},{name:'Response engine',state:responseFresh&&r.responseEngineStatus==='Ready'&&typeof r.responseEngineDetail==='string'&&r.responseEngineDetail.trim()?'Pass':'Review',evidence:(r.responseEngineStatus||'Unknown')+' — '+(r.responseEngineDetail||'No detail')+' · Last checked UTC: '+(r.responseCheckedUtc||'Unknown')+(responseFresh?'':' (not recently verified)')},{name:'Awaiting production incident evidence',state:typeof r.processCorrelation==='string'&&/^Awaiting matching audit evidence/i.test(r.processCorrelation)?'Not tested':'Review',evidence:(r.processCorrelation||'Unknown')+'; independent lab evidence is reported separately in Step 04. No production attribution verdict.'},{name:'Canary enrollment',state:(r.canaries||[]).length&&(r.canaries||[]).every(x=>x.status==='Enrolled')?'Pass':'Review',evidence:(r.canaries||[]).length+' registered; enrollment is not a detection test'}];
    const paths=r.responsePathsReadiness||[];epAuditControls(responseFresh?paths:[],r.testPaths);checks.push({name:'Authorized response path access',state:responseFresh&&paths.length&&paths.every(x=>x.status==='ok')?'Pass':'Review',evidence:paths.length?paths.map(x=>x.path+' — '+x.detail).join(' | '):'No directory access results recorded'});if(!responseFresh)checks[checks.length-1].evidence+=' · Permission telemetry not recently verified.';epReadinessRows=checks;epTestCards('ep-test-readiness',checks);const reviewCount=checks.filter(x=>x.state!=='Pass').length;epStepResult(1,reviewCount?reviewCount+' item'+(reviewCount===1?'':'s')+' to review':'Checks reported ready');
    const events=(r.recentIncidents||[]).filter(x=>/containment|canary integrity violation|malware signature detected|ransomware/i.test(x.change||'')).slice(0,8).map(x=>({name:x.change,state:'Recorded',evidence:[localEndpointDate(x.utc),x.path,x.detail].filter(Boolean).join(' · ')}));epTestCards('ep-test-events',events.length?events:[{name:'No matching recent incident',state:'Not tested',evidence:'No relevant record in the returned history.'}]);
}
function setupContainmentTests(){
    const b=byId('ep-test-run'),writer=byId('ep-writer-run');if(!b||!writer)return;setupLiveAuditProbe();
    byId('ep-test-evidence').onclick=()=>selectEndpointView('evidence');
    const center=byId('ep-test-center');center.querySelectorAll('[data-test-step]').forEach(node=>node.onclick=()=>epSelectStep(Number(node.dataset.testStep)));
    center.querySelectorAll('[data-test-view]').forEach(node=>node.onclick=()=>selectEndpointView(node.dataset.testView));
    byId('ep-step-back').onclick=()=>epSelectStep(epTestStep-1);byId('ep-step-next').onclick=()=>epSelectStep(epTestStep+1);epSelectStep(1,false);epStepResult(1,epStepResults[0]);
    const marker=byId('ep-test-marker');const sync=()=>{b.disabled=epProtectionBusy||epExternalBusy||epDiagnosticBusy||epSuiteBusy||epAuditBusy;writer.disabled=b.disabled||!marker.value.trim();epAuditControls();};epSyncDiagnostics=sync;marker.addEventListener('input',sync);sync();
    async function run(external){
        if(epProtectionBusy||epExternalBusy||epDiagnosticBusy||epAuditBusy)return [];const value=external?marker.value.trim():'';if(external&&!value)return [];epDiagnosticBusy=true;sync();
        const step=external?4:2,target=external?'ep-writer-results':'ep-test-results',status=byId(external?'ep-writer-status':'ep-test-status');epStepResult(step,'Running');status.textContent=external?'Verifying external writer…':'Running read-only checks…';epTestCards(target,[]);
        try{const result=await request('/ui/endpoint-containment-tests',{marker:value});const allRows=epVerifiedRows(result,external?['Lab writer correlation','Lab process identity']:epDiagnosticRequired);
            if(!external&&!allRows.some(x=>x.name==='Response path access'||x.name==='Response directory permissions'))allRows.push({name:'Response path access',state:'Not tested',evidence:'Service returned no response-path access check.',sourceUtc:result.utc});
            // Keep each step's evidence separate. Missing results are never a pass.
            const rows=allRows.filter(row=>external?/^Lab (writer|process)/.test(row.name):!/^Lab (writer|process)|^Live quarantine and termination/.test(row.name));
            epTestCards(target,rows);if(external){const passed=['Lab writer correlation','Lab process identity'].every(name=>rows.some(row=>row.name===name&&row.state==='Pass'));epStepResult(step,passed?'Passed · query-only identity':'Review / incomplete');}else{const needs=rows.filter(row=>row.state!=='Pass').length;epStepResult(step,!rows.length?'No checks returned':needs?needs+' check'+(needs===1?'':'s')+' to review':'Reported checks passed');}
            status.textContent=(external?'Writer diagnostics completed':'Diagnostics completed')+' · '+localEndpointDate(result.utc)+' · no production response executed.';return rows.length?rows:[{name:'Service diagnostics',state:'Review',evidence:'No checks returned.'}];
        }catch(ex){epStepResult(step,'Result unavailable');status.textContent='Diagnostics unavailable: '+ex.message;return [{name:'Service diagnostic request',state:'Review',evidence:status.textContent}];}finally{epDiagnosticBusy=false;sync();}
    }
    b.onclick=()=>{if(!epSuiteBusy)run(false);};writer.onclick=()=>{if(!epSuiteBusy)run(true);};
    const suite=byId('ep-suite-run'),directory=byId('ep-suite-directory'),progress=byId('ep-suite-progress'),status=byId('ep-suite-status');
    const full=byId('ep-suite-full');if(full)full.onclick=()=>{if(full.disabled)return;byId('ep-suite-protection').checked=true;epAuditControls();suite.click();};
    directory.onchange=()=>epAuditControls();byId('ep-suite-protection').onchange=()=>epAuditControls();byId('ep-suite-export').onclick=epExportSuite;
    suite.onclick=async()=>{
        if(suite.disabled||epProtectionBusy||epExternalBusy||epSuiteBusy||epAuditBusy||epDiagnosticBusy)return;const selected=directory.value,includeProtection=byId('ep-suite-protection').checked;let report=null;epSuiteBusy=true;sync();
        try{if(!await confirmAction('Run all automated tests?', 'Run read-only checks and create/remove two harmless markers in '+selected+'. The installed PowerShell script runs automatically. '+(includeProtection?'Also run temporary canary enrollment, watcher and incident-attribution verification the isolated EICAR exercise and a fixed owned-child termination test; confirm this is a disposable test directory in an isolated environment. Real alerts and sealed quarantine may result. ':'Canary and quarantine remain manual. ')+'Actual malicious-process containment remains unverified.', 'Run automated tests'))return;
            report={directory:selected,startedUtc:new Date().toISOString(),rows:[],baseline:[]};epSuiteReport=null;byId('ep-suite-report').hidden=true;progress.value=0;
            status.textContent='1 of 6 · Capturing initial readiness…';report.baseline.push(...epReadinessSnapshot().map(x=>({...x,name:'Initial readiness / '+x.name})));progress.value=1;
            status.textContent='2 of 6 · Running initial service diagnostics…';epSelectStep(2,false);report.baseline.push(...(await run(false)).map(x=>({...x,name:'Initial diagnostics / '+x.name})));progress.value=2;
            status.textContent='3 of 6 · Verifying live audit delivery…';epSelectStep(3,false);
            if(Array.from(directory.options).some(x=>x.value===selected)){byId('ep-audit-directory').value=selected;report.rows.push(...(await epRunAudit(selected)).filter(x=>x.name!=='Production containment').map(x=>({...x,name:'Live audit / '+x.name})));}else{epStepResult(3,'Not tested · scope changed');report.rows.push({name:'Live audit',state:'Not tested',evidence:'Selected directory is no longer available in current readiness. No marker written.'});}
            progress.value=3;
            status.textContent='4 of 6 · Verifying independent PowerShell writer…';epSelectStep(4,false);
            if(Array.from(directory.options).some(x=>x.value===selected)){byId('ep-external-directory').value=selected;report.rows.push(...(await epRunExternal(selected)).map(x=>({...x,name:'External writer / '+x.name})));}else{epStepResult(4,'Not tested · scope changed');report.rows.push({name:'External writer attribution',state:'Not tested',evidence:'Selected directory is no longer available. No marker written.'});}
            if(includeProtection){epSelectStep(5,false);status.textContent='4 of 6 · Running isolated protection lab…';const lab=byId('ep-protection-directory');if(Array.from(lab.options).some(x=>x.value===selected)){lab.value=selected;report.rows.push(...(await epRunProtection(selected)).map(x=>({...x,name:'Isolated protection / '+x.name})));}else report.rows.push({name:'Isolated protection lab',state:'Not tested',evidence:'Select a dedicated leaf response directory. No lab file written.'});for(const name of epProtectionRequired)if(!report.rows.some(x=>x.name==='Isolated protection / '+name))report.rows.push({name:'Isolated protection / '+name,state:'Not tested',evidence:'No independent result returned for this exercise.'});}
            progress.value=4;
            status.textContent='5 of 6 · Rechecking service diagnostics after the probes…';
            const finalRows=await run(false);
            // Reject a replayed pre-probe result. The service clock is used for both observations.
            const precedingTimes=[...report.baseline,...report.rows].map(x=>Date.parse(x.sourceUtc)).filter(Number.isFinite);
            const finalTimes=[...new Set(finalRows.map(x=>x.sourceUtc).filter(Boolean))];
            const cutoff=finalTimes.length===1&&Number.isFinite(Date.parse(finalTimes[0]))&&(!precedingTimes.length||Date.parse(finalTimes[0])>=Math.max(...precedingTimes))?finalTimes[0]:null;
            if(!cutoff){for(const row of finalRows){if(row.state==='Pass'){row.state='Review';row.evidence='Final diagnostic timestamp could not be validated. No final pass. '+row.evidence;}}}
            report.rows.push(...finalRows.map(x=>({...x,name:'Final diagnostics / '+x.name})));progress.value=5;
            // No client timestamp substitute: only the server's diagnostic completion is a valid cutoff.
            status.textContent='6 of 6 · Waiting for fresh readiness telemetry…';
            report.rows.push(...(await epRefreshFinalReadiness(cutoff)).map(x=>({...x,name:'Final readiness / '+x.name})));progress.value=6;
            for(const [name,evidence] of [...(!includeProtection?[['Live enrolled-canary watcher detection','Choose Full security validation to run the temporary enrolled-canary exercise.'],['Controlled production incident attribution','Full security validation is required for a normal-detector incident with matching audit evidence.'],['Live malware quarantine','Opt in to the isolated protection lab or use Step 05 B.'],['Isolated protection / Owned child termination mechanics','Choose Full security validation to run the fixed owned child termination exercise.']]:[]),['Production process containment','Not executed by this suite. A benign writer cannot satisfy the confirmed-malicious-executable gate. No production termination verdict.']])report.rows.push({name,state:'Not tested',evidence});
            report.finishedUtc=new Date().toISOString();epRenderSuiteReport(report);epSelectStep(6);
        }catch(ex){if(report){report.rows.push({name:'Suite completion',state:'Review',evidence:'Validation interrupted: '+ex.message+'. Remaining checks are unverified.'});report.finishedUtc=new Date().toISOString();epRenderSuiteReport(report);epSelectStep(6);}else status.textContent='Validation interrupted: '+ex.message;}finally{epSuiteBusy=false;sync();}
    };
}
function renderWebProtection(v){
    const panel=byId('ep-web-protection');if(!panel)return;
    const r=v?.result||{},w=r.webProtection,age=v?.ageSeconds;
    const fresh=!v?.stale&&typeof age==='number'&&Number.isFinite(age)&&age>=0&&age<=20;
    const disabled=v?.status==='disabled'||r.status==='disabled';
    const known=fresh&&!disabled&&w&&typeof w.enabled==='boolean';
    const state=byId('ep-web-state'),cards=byId('ep-web-kpis'),paths=byId('ep-web-paths'),monitor=byId('ep-web-monitor');
    const set=(title,detail,kind,mode,summary)=>{panel.dataset.state=kind;byId('ep-web-title').textContent=title;state.textContent=detail;byId('ep-web-mode').textContent=mode;byId('ep-web-summary').textContent=summary;};
    const replace=(node,key,build)=>{const k=JSON.stringify(key);if(node.dataset.key!==k){node.dataset.key=k;node.replaceChildren(...build());}};
    if(!known){set(disabled?'Endpoint Protection disabled':'Awaiting fresh telemetry',disabled?'Supplemental inspection inactive.':'Web protection status unverified; waiting for fresh service data.','unknown','Supplemental · '+(disabled?'Inactive':'Unverified'),'Current counters unavailable');replace(cards,[],()=>[]);replace(paths,[],()=>[]);replace(monitor,[],()=>[]);byId('ep-web-last').textContent='';if(byId('ep-web-history'))byId('ep-web-history').textContent='';return;}
    const isCount=n=>typeof n==='number'&&Number.isFinite(n)&&n>=0;
    const counts=[w.suspiciousScripts,w.inspectionIssues,w.processFindings,w.auditIssues];
    const countsKnown=counts.every(isCount),pending=counts.some(n=>isCount(n)&&n>0);
    const webPaths=Array.isArray(w.paths)?w.paths.filter(p=>typeof p==='string'&&p.trim()):[];
    const auditKnown=typeof w.processAuditEnabled==='boolean';
    const auditAvailable=w.processAuditEnabled===true&&String(w.processAuditState||'').startsWith('Available —');
    const auditPending=w.processAuditEnabled===true&&!auditAvailable;
    const auditUnavailable=auditPending&&/unavailable|disabled|gap|error/i.test(String(w.processAuditState||''));
    const sharedIssues=r.engineOnline===false||r.status==='partial'||r.status==='unavailable'||Number(r.coverageIssueCount)>0||Number(r.activeScanIssues)>0||!!r.baselineThrottleReason;
    const sharedVerified=r.status==='ok'&&r.engineOnline===true&&r.fullScanComplete===true&&r.scanRunning===false&&r.baselineFollowupRequired!==true&&!r.engineRecoveryPending&&r.coverageIssueCount===0&&r.activeScanIssues===0;
    const normalizePath=p=>String(p||'').replace(/\//g,'\\').replace(/\\+$/,'').toLowerCase();
    const roots=Array.isArray(r.rootCoverage)?r.rootCoverage:[];
    const pathCovered=path=>roots.some(root=>{const base=normalizePath(root.path),target=normalizePath(path);return base&&(target===base||target.startsWith(base+'\\'))&&['Watching','Scheduled only'].includes(root.state);});
    const pathVerified=w.enabled&&webPaths.length>0&&webPaths.every(pathCovered)&&sharedVerified;
    const scriptVerified=pathVerified&&!!w.lastScriptCheckUtc&&Number.isFinite(Date.parse(w.lastScriptCheckUtc));
    const clean=w.enabled&&countsKnown&&!pending&&scriptVerified&&auditKnown&&!auditPending;
    const title=pending?'Supplemental findings need attention':!w.enabled?'Web protection not configured':sharedIssues||auditUnavailable?'Verification needs attention':clean?'No active supplemental findings':!countsKnown||!auditKnown?'Status unverified':'Web protection verification in progress';
    const detail=pending?'Review active supplemental findings below. Acknowledgement does not resolve them.':!w.enabled?'Not configured. Existing Endpoint Protection remains independent.':sharedIssues?'Shared scanner reports a coverage or availability issue. Review Scanning and Evidence.':auditUnavailable?'Process audit is unavailable; review the audit state.':auditPending?'Process audit review pending; see audit state below.':clean?'No active supplemental findings reported. This is not a comprehensive web-shell verdict.':!countsKnown||!auditKnown?'Some supplemental telemetry is unverified.':!webPaths.length?'No web paths configured. Review protection settings.':'Protected-scope verification in progress or no supplemental script check recorded yet.';
    const kind=pending||w.enabled&&(sharedIssues||auditUnavailable)?'review':!w.enabled||!countsKnown||!auditKnown?'unknown':clean?'ok':'verifying';
    set(title,detail,kind,'Supplemental · '+(w.enabled?'Enabled':'Disabled'),webPaths.length+' configured web '+(webPaths.length===1?'directory':'directories')+' · Process audit '+(w.processAuditEnabled===true?'enabled':w.processAuditEnabled===false?'disabled':'unverified')+' · '+(countsKnown?counts.reduce((a,b)=>a+b,0)+' active supplemental findings':'Finding counts unverified'));
    const rows=[['Suspicious scripts',w.suspiciousScripts,w.enabled,scriptVerified,'Script pattern findings'],['Inspection issues',w.inspectionIssues,w.enabled,pathVerified,'Supplemental inspection coverage'],['Process findings',w.processFindings,w.enabled&&w.processAuditEnabled===true,auditAvailable,'Unexpected web-server child processes'],['Audit issues',w.auditIssues,w.enabled&&w.processAuditEnabled===true,auditAvailable,'Process audit coverage']];
    replace(cards,rows,()=>rows.map(([name,value,enabled,verified,caption])=>{const box=element('article');box.className='ep-kpi';const countKnown=isCount(value),active=countKnown&&value>0;box.dataset.state=active?'review':!enabled||!countKnown?'unknown':verified?'ok':'verifying';const label=element('span',active?'Needs attention':!enabled?'Not enabled':!countKnown?'Unverified':verified?'None reported':'Verifying');label.className='ep-component-state';box.append(element('span',name),element('strong',countKnown?String(value):'—'),label,element('small',caption));return box;}));
    replace(paths,webPaths,()=>webPaths.length?webPaths.map(p=>{const row=element('div');row.className='ep-web-path-row';row.append(element('strong',p));return row;}):[element('p','No web paths configured.')]);
    byId('ep-web-last').textContent='Last supplemental script check: '+(w.lastScriptCheckUtc?localEndpointDate(w.lastScriptCheckUtc):'Not recorded');
    const history=byId('ep-web-history');if(history)history.textContent=typeof w.historicalAuditLimitation==='string'&&w.historicalAuditLimitation?('Historical limitation (not an active coverage failure): '+w.historicalAuditLimitation):'';
    const checks=[['Shared scanner',r.engineOnline===true?'Online':r.engineOnline===false?'Offline':'Unverified',r.engineOnline===true?'ok':r.engineOnline===false?'review':'unknown'],['Protected-scope baseline',sharedIssues?'Review coverage':sharedVerified?'Complete':'Verification pending',sharedIssues?'review':sharedVerified?'ok':'unknown'],['Manual web quarantine',w.manualQuarantineEnabled===true?'Administrator approval required':w.manualQuarantineEnabled===false?'Disabled':'Unverified','unknown'],['Process audit',w.processAuditEnabled===true?(w.processAuditState||'Unverified'):w.processAuditEnabled===false?'Disabled':'Unverified',auditUnavailable?'review':auditAvailable?'ok':'unknown']];
    replace(monitor,checks,()=>checks.map(([name,value,kind])=>{const row=element('div');row.className='ep-web-monitor-row';row.append(element('strong',name),healthBadge(value,kind));return row;}));
}
function endpointOverview(v,activeAlerts){
    renderWebProtection(v);
    if(!byId('ep-overview'))return;
    const r=v?.result||{},fresh=!v?.stale&&Number(v?.ageSeconds??Infinity)<=20&&!(r.status==='unavailable'&&r.engineOnline==null),disabled=r.status==='disabled'||v?.status==='disabled';
    const findings=Array.isArray(r.items)?r.items:[],alertsKnown=Array.isArray(activeAlerts),alerts=(alertsKnown?activeAlerts:[]).filter(x=>!x.resolved),behavior=row=>String(row.change||row.title||'').startsWith('Possible ransomware activity'),severity=x=>String(x.severity||'').toLowerCase(),isCount=n=>typeof n==='number'&&Number.isFinite(n)&&n>=0;
    const critical=Number(r.activeMalware)>0||findings.some(x=>['critical','error'].includes(severity(x)))||alerts.some(x=>['critical','error'].includes(severity(x))),warning=findings.some(x=>severity(x)==='warning')||alerts.some(x=>severity(x)==='warning');
    const roots=Array.isArray(r.rootCoverage)?r.rootCoverage:[],paths=Array.isArray(r.protectedPaths)?r.protectedPaths:[],rootIssues=roots.some(x=>['Uncovered','Initializing','Excluded','Journal only'].includes(x.state));
    const scopeKnown=paths.length>0&&paths.every(path=>roots.some(x=>x.path===path&&['Watching','Scheduled only','Uncovered','Initializing','Excluded','Journal only'].includes(x.state)));
    const countsKnown=[r.activeMalware,r.activeScanIssues,r.coverageIssueCount,r.violations,r.pendingAlertDelivery].every(isCount),findingsKnown=Array.isArray(r.items)&&alertsKnown&&!r.truncated&&r.pendingAlertDelivery===0;
    const uncertain=(!fresh||disabled),needsReview=r.engineOnline!==true||r.signatureFreshness!=='Current'||rootIssues||Number(r.activeScanIssues||0)>0||Number(r.coverageIssueCount||0)>0||r.status==='partial'||r.status==='unavailable'||(r.scanRunning&&!!r.baselineThrottleReason)||warning||r.truncated||Number(r.violations||0)>0||Number(r.pendingAlertDelivery||0)>0||Number(r.activeHeuristic||0)>0;
    const webAuditPending=r.webProtection?.enabled&&r.webProtection?.processAuditEnabled&&!String(r.webProtection?.processAuditState||'').startsWith('Available —');
    const verified=!webAuditPending&&scopeKnown&&countsKnown&&findingsKnown&&r.status==='ok'&&r.fullScanComplete===true&&r.scanRunning!==true&&r.baselineFollowupRequired!==true&&!r.engineRecoveryPending;
    const verifying=!uncertain&&!critical&&!needsReview&&!verified;
    let title=disabled?'Protection disabled':!fresh?'Status awaiting fresh data':critical?'Critical finding — investigate':needsReview?'Protection needs attention':verifying?'Protection verification in progress':'Protection healthy';
    let kind=uncertain?'unknown':critical?'fail':needsReview?'review':verifying?'verifying':'ok';const hero=byId('ep-overview');hero.dataset.state=kind;byId('ep-overview-title').textContent=title;
    byId('ep-overview-message').textContent=disabled?'Choose protected application directories in Settings, then enable Endpoint Protection.':!fresh?'Displayed counters may be old; no current protection verdict is implied.':critical?'Review current detections and response evidence.':needsReview?'One or more checks need attention. Healthy components are shown separately below.':verifying?'No active problem in the available evidence. Complete protected-scope verification is not yet established.':'Configured protection checks verified; no active warnings reported. Not a guarantee against every threat.';
    byId('ep-mode').textContent='Mode · '+(fresh&&!disabled&&r.mode?r.mode:'—');
    const safe=n=>uncertain||!isCount(n)?'—':String(n),rapid=[...findings,...alerts].filter(behavior),canaries=r.canaries||[],canaryKnown=isCount(r.canaryCount)&&Array.isArray(r.canaries)&&r.canaries.length===r.canaryCount;
    const coverageState=rootIssues||Number(r.coverageIssueCount)>0||Number(r.activeScanIssues)>0?'review':!countsKnown||!scopeKnown?'unknown':verified?'ok':'verifying';
    const stats=[['Antivirus engine',r.engineOnline===true?'Online':r.engineOnline===false?'Offline':'Unverified','maintenance',r.engineOnline===true&&!r.engineRecoveryPending?'ok':r.engineOnline===false?'review':'unknown','Engine connectivity; not a clean-file verdict'],['Signatures',r.signatureFreshness||'Unverified','maintenance',r.signatureFreshness==='Current'&&r.engineOnline===true?'ok':r.signatureFreshness&&r.signatureFreshness!=='Unknown'?'review':'unknown','Loaded signature freshness'],['Confirmed malware',safe(r.activeMalware),'evidence',Number(r.activeMalware)>0?'fail':isCount(r.activeMalware)&&findingsKnown?'ok':'unknown','Recorded active signature findings; not a clean-system verdict'],['Ransomware signals',uncertain?'—':rapid.length?'Detected':findingsKnown?'None reported':'Unverified','behavior',rapid.some(x=>severity(x)==='critical')?'fail':rapid.length?'review':findingsKnown?'ok':'unknown','Recorded behavioral findings'],['Scan coverage',uncertain?'—':safe(r.coverageIssueCount)+' / '+safe(r.activeScanIssues),'scan',coverageState,'Outstanding paths / active scanner findings'],['Canary files',safe(r.canaryCount),'behavior',canaries.some(x=>x.status==='critical')?'fail':!canaryKnown||!canaries.length?'unknown':canaries.some(x=>x.status!=='Enrolled')?'review':'ok',r.canaryCount===0?'Not configured; no canary protection':'Integrity decoys']];
    const labels={ok:'Healthy',fail:'Critical',review:'Needs attention',unknown:'Unverified',verifying:'Verifying'};
    const key=JSON.stringify([stats,uncertain]);const cards=byId('ep-kpis');if(cards.dataset.key!==key){cards.dataset.key=key;cards.replaceChildren(...stats.map(([name,value,view,state,caption])=>{const b=element('button');b.type='button';b.className='ep-kpi';b.dataset.epGo=view;b.dataset.state=uncertain?'unknown':state;const label=element('span',uncertain?'Unverified':name==='Canary files'&&r.canaryCount===0?'Not configured':labels[state]);label.className='ep-component-state';b.append(element('span',name),element('strong',uncertain?'—':value),label,element('small',caption+' ›'));return b;}));}
    const summary=byId('ep-alert-summary');if(summary){const issues=alerts.filter(x=>['warning','error','critical'].includes(severity(x))),unread=issues.filter(x=>x.read===false).length,read=issues.filter(x=>x.read===true).length;summary.textContent=uncertain||!alertsKnown?'Current alert counts unverified':issues.length+' active warning / critical alerts · '+unread+' unread · '+read+' acknowledged'+(issues.length-unread-read?' · '+(issues.length-unread-read)+' review status unknown':'')+'. Acknowledgement does not resolve a finding.';}
    const a=byId('ep-attention'),messages=[];
    if(fresh&&!disabled){
        if(!scopeKnown)messages.push('Configured protected-folder coverage has not been fully reported.');
        if(!countsKnown||!findingsKnown)messages.push('Complete finding or alert delivery evidence is not yet available.');
        if(Number(r.pendingAlertDelivery)>0)messages.push(r.pendingAlertDelivery+' durable alert transitions awaiting delivery.');
        if(verifying)messages.push('Baseline or protected-scope verification is not complete. See Scanning for progress.');
        if(r.engineOnline!==true)messages.push('Antivirus engine unavailable or unverified. Check the ClamD service and Maintenance readiness.');
        if(r.signatureFreshness!=='Current')messages.push('Signature freshness: '+(r.signatureFreshness||'Unknown')+' · '+(r.signatureComparison||'Check Maintenance.'));
        for(const root of (r.rootCoverage||[]).filter(x=>['Uncovered','Initializing','Excluded','Journal only'].includes(x.state)))messages.push('Monitoring: '+root.path+' · '+root.state+(root.detail?' · '+root.detail:'')+' · Review protected folder coverage.');
        if(Number(r.coverageIssueCount||0)>0)messages.push(r.coverageIssueCount+' outstanding file/path checks. See Evidence → Scan coverage details; inspect access, locks, exclusions and scan limits.');
        if(Number(r.activeScanIssues||0)>0)messages.push(r.activeScanIssues+' active scanner findings (separate from outstanding paths). See Evidence and Scanning.');
        if(r.scanRunning&&r.baselineThrottleReason){
            messages.push('Baseline reconciliation paused · '+r.baselineThrottleReason+' · '+(r.scannedFiles??'—')+' files checked; '+(r.baselineDiscoveredPending??'—')+' discovered entries pending. Existing scan/journal warnings remain until successful reconciliation.');
            const ram=r.resources,age=Date.parse(v.collectedUtc)-Date.parse(ram?.sampleUtc);
            if(r.baselineThrottleReason==='Low available physical memory'){
                if(Number.isFinite(age)&&age>=-1000&&age<=30000&&ram?.availableMiB!=null&&ram?.effectiveFloorMiB!=null&&ram?.recoveryFloorMiB!=null)messages.push('Available physical RAM: '+ram.availableMiB+' MiB · pause threshold: '+ram.effectiveFloorMiB+' MiB · automatic resume threshold: '+ram.recoveryFloorMiB+' MiB (two consecutive healthy samples). Free memory or review the host capacity in Resources.');
                else messages.push('See Resources for fresh available-memory readings and configured pause/resume thresholds.');
            }
        }
        if(r.scanRunning&&r.baselineFollowupRequired)messages.push('Another complete baseline is required because coverage changed during this scan or it resumed after interruption. Recovery is not yet verified.');
        if(!r.scanRunning&&r.fullScanComplete===false&&r.nextScanUtc&&Number.isFinite(Date.parse(r.nextScanUtc)))messages.push('Next reconciliation: '+new Date(r.nextScanUtc).toLocaleString()+'. Recovery is automatic after successful verification. Acknowledging alerts only marks them as read. Do not repeatedly reset or restart the scanner.');
        for(const issue of (r.coverageDetails||[]))messages.push((issue.issue||'Coverage check')+' · '+issue.path+' · '+(issue.detail||'Review scan coverage details.'));
        const liveFindings=findings.filter(x=>['critical','warning','error'].includes(String(x.severity||'').toLowerCase()));
        for(const item of liveFindings)messages.push((item.change||'Active finding')+' · '+(item.path||'Unknown path')+' · '+(item.detail||'No detail reported.'));
        for(const alert of alerts.filter(x=>!x.resolved&&['critical','warning','error'].includes(String(x.severity||'').toLowerCase()))){
            // Avoid hiding a distinct alert just because another finding has the same title.
            if(!liveFindings.some(x=>x.change===alert.title&&(alert.message===x.detail||alert.message===x.path+' · '+x.detail)))messages.push('Active alert: '+(alert.title||'Untitled')+' · '+(alert.message||'No detail reported.'));
        }
        if(r.status==='partial'){
            if(!r.scanRunning&&r.fullScanComplete===false)messages.push('Baseline reconciliation is incomplete. See Scanning; resolve errors and allow a fresh baseline to finish.');
            if(Number(r.queueDepth||0)>0)messages.push(r.queueDepth+' queued file events remain to be processed.');
            if(!messages.length)messages.push('Scanner reports partial coverage. Review Scanning and Evidence; exact reason was not supplied by the service.');
        }
        if(r.truncated)messages.push('Active findings are capped by the service; additional evidence exists.');
        if(Number(r.violations||0)>liveFindings.length)messages.push(r.violations+' total active warning/critical findings; not all are present in this snapshot.');
    }
    const reasons=[...new Set(messages)];byId('ep-status-reasons').hidden=uncertain||!(critical||needsReview||verifying);
    const messageKey=JSON.stringify([reasons,kind]);if(a.dataset.key!==messageKey){a.dataset.key=messageKey;a.replaceChildren(...(reasons.length?reasons.map(x=>element('p',x)):[element('p',uncertain?'Current status unavailable.':critical||warning?'Review active security findings.':'No current items requiring attention.')]));}

}

let endpointAck=null,endpointAckEpoch=0,endpointAckBusy=false,endpointScanBusy=false,endpointScanRequested=null,endpointLastSample=null;
const endpointRetryTitles=new Set(['USN journal coverage gap','USN journal unavailable','Watcher coverage incomplete','Real-time queue overflow','Scan incomplete','File scan coverage incomplete','File scan error','File scan limited','Engine scan incomplete','Protected path unavailable','Scan traversal limit reached','endpoint_protection coverage is partial','endpoint_protection coverage is unavailable']);
const endpointAlertActionsBusy=new Set();
const endpointAlertReviewNotes=new Map(),endpointConfirmedReads=new Set();
let endpointReviewRecords=[],endpointReviewKey='',endpointReviewPointer=false,endpointHealthIssued=0,endpointHealthApplied=0;
function endpointAlertFeedback(message,state='info'){
    const node=byId('endpoint-alert-action-status');if(node){node.textContent=message;node.dataset.state=state;}
}
function endpointReviewMessage(e){return e?.name==='AbortError'?'Request timed out. Its outcome is unknown; check the current alert status before retrying.':e?.message||String(e);}
function endpointAlertActions(cell,a,tr){
    const status=healthBadge(a.read===true?'Acknowledged':a.read===false?'Unread':'Review status unavailable',a.read===true?'info':'unknown');
    const group=element('div');group.className='ep-alert-actions';
    const note=endpointAlertReviewNotes.get(a.id);
    cell.className='ep-alert-action-cell';cell.replaceChildren(status,group);
    // All controls share one column; retain the existing investigation dialog and row click behavior.
    if(window.LinkScopeToast?.attachAlertRow)window.LinkScopeToast.attachAlertRow(tr,a,group);
    if(!csrf||!a.id||a.resolved)return;
    const add=(label,action)=>{
        const b=element('button',label);b.type='button';b.className='ep-alert-action-button secondary';b.dataset.epAlertAction=action;b.dataset.epAlertId=a.id;
        b.disabled=endpointAlertActionsBusy.size>0||(action==='read'&&endpointAckBusy);
        b.onclick=async e=>{
            e.stopPropagation();
            if(endpointAlertActionsBusy.size||endpointAckBusy)return;
            endpointAlertActionsBusy.add(a.id);endpointReviewPointer=false;
            const reading=action==='read',quarantining=action==='quarantine',original=b.textContent;
            if(reading){endpointAckEpoch++;endpointAckBusy=true;}endpointAckControls();
            const actionButtons=[...byId('endpoint-alert-review-rows').querySelectorAll('button[data-ep-alert-action]')];actionButtons.forEach(button=>button.disabled=true);
            b.textContent=reading?'Acknowledging…':'Preparing…';
            let submitted=false,accepted=false;
            try{
                if(quarantining&&!(await confirmAction('Quarantine suspicious web script?',a.message+'\nThis removes the original file if verified and may disrupt the application. Sealed evidence is retained. This is not a confirmed malware verdict.','Quarantine',true)))return;
                if(!reading&&!quarantining&&!(await confirmAction('Retry coverage verification?','Request verification of the configured protected directories. If a baseline is running, a follow-up may be scheduled. No findings, counters, policies or evidence are reset.','Retry verification')))return;
                submitted=true;b.textContent=reading?'Acknowledging…':'Requesting…';endpointAlertFeedback(reading?'Saving acknowledgement…':quarantining?'Verifying and sealing the selected script…':'Requesting protected-directory verification…');
                if(reading){
                    const ack=await request('/ui/endpoint-alert-read',{id:a.id});
                    if(!ack||typeof ack.unread!=='number'||typeof ack.activeUnread!=='number')throw new Error('Acknowledgement response was incomplete. Refresh to verify the result.');
                    endpointAck=ack;endpointConfirmedReads.add(a.id);accepted=true;
                    try{window.LinkScopeToast?.individualRead?.(a.id);}catch(e){console.warn('Alert notification synchronization failed',e);}
                    endpointAlertReviewNotes.set(a.id,{state:'info',text:'Acknowledged · finding remains active'});
                    endpointAlertFeedback('Alert acknowledged. Active protection findings remain unchanged.','success');
                }else if(quarantining){
                    const hash=(a.message||'').match(/ · SHA-256: ([a-f0-9]{64})$/)?.[1];
                    if(!hash)throw new Error('Exact SHA-256 is unavailable. Refresh evidence.');
                    const response=await request('/ui/endpoint-web-quarantine',{id:a.id,hash});
                    if(response?.quarantined!==true)throw new Error('Original removal was not verified. Check evidence.');
                    accepted=true;endpointAlertReviewNotes.set(a.id,{state:'info',text:'Quarantined · original removal verified'});
                    endpointAlertFeedback('Suspicious script quarantined. '+response.detail,'success');
                }else{
                    const response=await request('/ui/endpoint-alert-retry',{id:a.id});
                    if(response?.accepted!==true)throw new Error('The service did not confirm the verification request.');
                    accepted=true;const r=endpointLastSample?.result||{};endpointScanRequested={at:Date.now(),previous:r.lastScanUtc,started:r.scanStartedUtc,followup:r.scanRunning===true};
                    endpointAlertReviewNotes.set(a.id,{state:'info',text:'Verification requested at '+new Date().toLocaleTimeString()});
                    endpointAlertFeedback('Verification request accepted. '+(r.scanRunning?'A follow-up scan may be scheduled after the current baseline. ':'The scanner has been signaled. ')+'See Scanning for progress; warnings remain active until verified recovery.','success');
                }
            }catch(e){const message=endpointReviewMessage(e);endpointAlertReviewNotes.set(a.id,{state:'error',text:message});endpointAlertFeedback(message,'error');}
            finally{
                endpointAlertActionsBusy.delete(a.id);if(reading){endpointAckBusy=false;endpointAckEpoch++;}endpointAckControls();
                actionButtons.forEach(button=>button.disabled=false);b.textContent=original;
                if(submitted){endpointReviewKey='';renderEndpointAlertReview();}
            }
            if(accepted){try{await renderHealth();}catch(e){endpointAlertFeedback('Action accepted, but telemetry refresh failed: '+endpointReviewMessage(e),'error');}}
        };
        group.append(b);
    };
    if(a.read===false)add('Acknowledge','read');
    if(a.title==='Suspicious web script'&&a.severity==='warning'&&endpointLastSample?.result?.webProtection?.manualQuarantineEnabled===true&&/ · SHA-256: [a-f0-9]{64}$/.test(a.message||''))add('Quarantine','quarantine');
    if(a.severity==='warning'&&endpointRetryTitles.has(a.title))add('Retry verification','retry');
    if(note){const text=element('small',note.text);text.className='ep-alert-action-note';text.dataset.state=note.state;cell.append(text);}
}
function renderEndpointAlertReview(records){
    const panel=byId('endpoint-alert-diagnostics'),body=byId('endpoint-alert-review-rows');if(!panel||!body)return;
    if(records!==undefined){
        endpointReviewRecords=records.filter(a=>!a.resolved&&a.category==='endpoint_protection'&&['critical','error','warning'].includes(String(a.severity||'').toLowerCase()));
        const ids=new Set(endpointReviewRecords.map(a=>a.id));
        for(const a of endpointReviewRecords)if(a.read===true)endpointConfirmedReads.delete(a.id);
        for(const id of endpointAlertReviewNotes.keys())if(!ids.has(id))endpointAlertReviewNotes.delete(id);
        for(const id of endpointConfirmedReads)if(!ids.has(id))endpointConfirmedReads.delete(id);
    }
    if(endpointReviewPointer||endpointAlertActionsBusy.size||endpointAckBusy)return;
    const items=endpointReviewRecords.map(a=>endpointConfirmedReads.has(a.id)?{...a,read:true}:a);
    const key=JSON.stringify([!!csrf,endpointLastSample?.result?.webProtection?.manualQuarantineEnabled,items,Array.from(endpointAlertReviewNotes)]);if(key===endpointReviewKey)return;
    const focused=document.activeElement,focusId=focused?.dataset?.epAlertId,focusAction=focused?.dataset?.epAlertAction;
    const search=focused?.dataset?.healthSearch,selection=search?[focused.selectionStart,focused.selectionEnd]:null;
    endpointReviewKey=key;byId('endpoint-alert-review-title').textContent='Active alert diagnostics ('+items.length+')';
    body.replaceChildren(items.length?table(items.map(a=>({severity:a.severity,change:a.title,detail:a.message,review:a.read===true?'Acknowledged':a.read===false?'Unread':'Review status unavailable'})),'endpoint active alert diagnostics',items):element('p','No active warning, error or critical alerts reported.'));
    if(focusId){const buttons=[...body.querySelectorAll('button[data-ep-alert-id]')];const next=buttons.find(b=>b.dataset.epAlertId===focusId&&b.dataset.epAlertAction===focusAction)||buttons.find(b=>b.dataset.epAlertId===focusId);if(next&&!next.closest('[hidden]'))next.focus({preventScroll:true});}
    else if(search){const next=[...body.querySelectorAll('[data-health-search]')].find(x=>x.dataset.healthSearch===search);if(next){next.focus({preventScroll:true});if(selection&&selection[0]!=null)next.setSelectionRange(...selection);}}
}
function endpointAckControls(){
    const b=byId('endpoint-ack-previous');if(!b)return;
    b.disabled=!csrf||endpointAckBusy||endpointAlertActionsBusy.size>0||!endpointAck||!endpointAck.unread;
    b.textContent=endpointAckBusy?'Acknowledging…':'Acknowledge previous alerts'+(endpointAck?.unread?' ('+endpointAck.unread+')':'');
    byId('endpoint-ack-count').textContent=endpointAck?endpointAck.unread+' unread endpoint alerts · '+endpointAck.activeUnread+' active unread':'Acknowledgement status unavailable';
}
// Monitoring-provider health is distinct from file signature coverage. Never infer
// a healthy watcher from stale telemetry, an old diagnostic, or journal presence.
function endpointRootPresentation(root){
    const state=root.state,local=root.localWatcher===true,system=root.privilegedWatcher===true,journal=root.journal===true;
    if(state==='Excluded')return ['Excluded by policy','review','Real-time monitoring excluded'];
    if(state==='Scheduled only')return ['Scheduled only','info','Real-time monitoring disabled by policy'];
    if(state==='Watching'&&local)return ['Real-time monitoring active','ok','Local filesystem watcher'];
    if(state==='Watching'&&system)return ['Real-time monitoring active','ok','Privileged SYSTEM watcher · automatic fallback'];
    if(state==='Journal only'&&journal)return ['Journal-only monitoring','review','NTFS journal · no verified live watcher'];
    if(state==='Initializing')return ['Monitoring initializing','review','Awaiting verified monitoring provider'];
    if(state==='Uncovered')return ['Monitoring unavailable','fail','No verified monitoring provider'];
    return ['Monitoring status unverified','review','Provider evidence is incomplete'];
}
function renderEndpointRootCoverage(panel,result,fresh){
    if(!panel)return;
    const roots=Array.isArray(result.rootCoverage)?result.rootCoverage:[];
    const message=result.status==='disabled'?'Endpoint Protection disabled':!fresh?'Awaiting fresh per-folder coverage evidence':!roots.length?'No protected folder coverage reported':null;
    // Avoid replacing unchanged DOM (keeps keyboard focus and disclosures open).
    const key=JSON.stringify(message===null?roots:message);
    if(panel.dataset.coverageKey===key)return;
    const expanded=new Set(Array.from(panel.querySelectorAll('details[open]')).map(d=>d.dataset.root));
    panel.dataset.coverageKey=key;
    if(message!==null){panel.textContent=message;return;}
    const rows=roots.map(root=>{
        const [label,kind,provider]=endpointRootPresentation(root);
        const row=element('div');row.className='endpoint-coverage-row';
        const head=element('div');head.className='endpoint-coverage-heading';
        const path=element('strong',root.path||'Unknown path');path.className='endpoint-coverage-path';
        head.append(path,healthBadge(label,kind));row.append(head);
        const meta=element('div');meta.className='endpoint-coverage-meta';
        meta.append(element('span',provider),element('span','NTFS journal: '+(root.journal===true?'Available (live or replaying)':'Not available')));row.append(meta);
        const diagnostics=element('details');diagnostics.className='endpoint-coverage-diagnostics';diagnostics.dataset.root=root.path||'';diagnostics.open=expanded.has(diagnostics.dataset.root);
        diagnostics.append(element('summary','Technical diagnostics'));
        const body=element('div');body.className='endpoint-coverage-diagnostic-body';
        body.append(element('div','Local watcher: '+(root.localWatcher===true?'Active':root.localWatcherDiagnostic?'Failed / inactive':'Not active')),element('div','SYSTEM watcher: '+(root.privilegedWatcher===true?'Verified active':'Not verified active')));
        if(root.localWatcherDiagnostic)body.append(element('div','Local watcher diagnostic: '+root.localWatcherDiagnostic));
        if(root.privilegedWatcherDiagnostic)body.append(element('div','SYSTEM watcher diagnostic: '+root.privilegedWatcherDiagnostic));
        if(root.localWatcherDiagnostic===undefined&&root.privilegedWatcherDiagnostic===undefined&&root.detail)body.append(element('div',root.detail));
        diagnostics.append(body);row.append(diagnostics);return row;
    });
    panel.replaceChildren(...rows);
}
function renderEndpointResources(r,fresh){
    const panel=byId('endpoint-resources');if(!panel)return;
    const text=(id,value)=>{byId(id).textContent=value;};
    const fmt=v=>v==null?'—':Number(v).toLocaleString()+' MiB';
    const charts=byId('endpoint-resource-charts');
    if(!fresh||!r||!r.sampleUtc){text('endpoint-resource-status','Awaiting fresh resource telemetry');text('endpoint-resource-memory','—');text('endpoint-resource-clam-memory','—');text('endpoint-resource-cpu','—');text('endpoint-resource-detail','');charts.replaceChildren();delete charts.dataset.sample;return;}
    text('endpoint-resource-status',r.memoryStatus+(r.lowMemory?(r.backgroundPauseEnabled?' · Background pause enabled':' · Background pause disabled'):'')+' · Sample '+(Number.isFinite(Date.parse(r.sampleUtc))?new Date(r.sampleUtc).toLocaleString():'Unknown'));
    text('endpoint-resource-memory',fmt(r.availableMiB)+' / '+fmt(r.totalMiB));
    text('endpoint-resource-clam-memory',fmt(r.clamWorkingMiB)+' / '+fmt(r.clamPrivateMiB));
    text('endpoint-resource-cpu',r.clamCpu==null?(r.clamPid?'Awaiting sample':'—'):r.clamCpu+'%');
    text('endpoint-resource-detail','Effective RAM floor: '+fmt(r.effectiveFloorMiB)+' · Resume at: '+fmt(r.recoveryFloorMiB)+' · '+r.clamStatus+(r.clamPid?' · PID '+r.clamPid:''));
    if(charts.dataset.sample===r.sampleUtc)return;charts.dataset.sample=r.sampleUtc;
    const points=Array.isArray(r.history)?r.history.slice(-120):[];
    const ns='http://www.w3.org/2000/svg';const make=(tag,attrs)=>{const e=document.createElementNS(ns,tag);for(const [k,v] of Object.entries(attrs))e.setAttribute(k,String(v));return e;};
    const series=[['Available RAM (MiB)','availableMiB',null],['ClamD working set (MiB)','clamWorkingMiB',null],['ClamD CPU (%)','clamCpu',100]];
    charts.replaceChildren(...series.map(([label,key,fixed])=>{
        const box=element('div');box.className='endpoint-resource-chart';box.append(element('strong',label));
        const valid=points.filter(p=>p[key]!=null&&Number.isFinite(Number(p[key])));
        if(!valid.length){box.append(element('p','No readings available'));return box;}
        const max=fixed||Math.max(1,...valid.map(p=>Number(p[key])));const svg=make('svg',{viewBox:'0 0 300 88',role:'img','aria-label':label+' recent samples, scale zero to '+Math.ceil(max)});
        svg.append(make('path',{d:'M 4 4 V 82 H 296',stroke:'currentColor','stroke-opacity':'.25',fill:'none'}));
        let d='',pen=false;points.forEach((p,i)=>{if(p[key]==null||!Number.isFinite(Number(p[key]))){pen=false;return;}const x=4+292*i/Math.max(1,points.length-1),y=82-78*Math.max(0,Math.min(1,Number(p[key])/max));d+=(pen?' L ':' M ')+x+' '+y;pen=true;svg.append(make('circle',{cx:x,cy:y,r:1.6,fill:'currentColor'}));});
        svg.append(make('path',{d,stroke:'currentColor','stroke-width':1.8,fill:'none'}));box.append(svg,element('small','Scale: 0–'+Math.ceil(max)+' · '+valid.length+' readings'));return box;
    }));
}
function endpointActivity(v,generatedUtc){
    endpointLastSample=v;const r=v?.result||v||{},panel=byId('endpoint-live');if(!panel)return;
    const age=Number(v?.ageSeconds??Infinity),fresh=!v?.stale&&age<=20,now=Date.parse(generatedUtc),recent=Number.isFinite(now)&&r.lastRealTimeScanUtc&&now-Date.parse(r.lastRealTimeScanUtc)<=8000&&now>=Date.parse(r.lastRealTimeScanUtc);
    const resourceAge=now-Date.parse(r.resources?.sampleUtc);
    renderEndpointResources(r.resources,fresh&&r.status!=='disabled'&&Number.isFinite(resourceAge)&&resourceAge>=-1000&&resourceAge<=30000);
    if(endpointScanRequested&&((fresh&&((r.scanRunning&&!endpointScanRequested.followup)||r.baselineFollowupRequired===true||r.lastScanUtc!==endpointScanRequested.previous||r.scanStartedUtc!==endpointScanRequested.started))||Date.now()-endpointScanRequested.at>30000))endpointScanRequested=null;
    let state='waiting',message='Waiting for endpoint telemetry';
    if(r.status==='disabled'){state='disabled';message='Protection disabled · configure application directories in Settings';}
    else if(!fresh){state='waiting';message=v?.collectedUtc?'Awaiting fresh scanner telemetry':'Waiting for endpoint telemetry';}
    else if(r.scanRunning&&r.engineOnline!==true){state='warning';message='Baseline waiting for antivirus engine';}
    else if(r.scanRunning&&r.baselineThrottleReason){state='paused';message='Baseline paused · '+r.baselineThrottleReason;}
    else if(r.scanRunning){state='scanning';message=r.baselineResumed?'Resuming baseline · reconciliation to follow':'Baseline verification in progress';}
    else if(r.engineOnline!==true){state='warning';message='ClamAV unavailable · signature coverage incomplete';}
    else if(endpointScanRequested){state='queued';message='Scan requested · waiting for scanner';}
    else if(Number(r.queueDepth)>0){state='queued';message='Processing real-time file events';}
    else if(recent){state='activity';message='Real-time file scan just completed';}
    else if(r.realTime&&(r.watcherCount>0||r.watcherRootsCoveredByJournal>0||r.watcherRootsCoveredByPrivileged>0)){state=r.status==='partial'?'warning':'watching';message=r.status==='partial'?'Watching files · coverage warning':'Real-time monitoring active · waiting for changes';}
    else if(r.realTime){state='warning';message='Real-time watcher unavailable';}
    else {state='idle';message='Scheduled monitoring · waiting for next scan';}
    panel.dataset.state=state;byId('endpoint-live-state').textContent=message;
    const worker=v?.activity,phase=worker?.phase,elapsed=worker?.phaseUtc&&Number.isFinite(now)?Math.max(0,Math.floor((now-Date.parse(worker.phaseUtc))/1000)):null;
    const workerText=phase?'Worker: '+phase+(elapsed!=null&&phase!=='Waiting for next cycle'?' · '+elapsed+' s in phase':''):'Worker phase unavailable';
    const health=!fresh?'Scan counters are from the last published snapshot.':r.status==='disabled'?'':(r.signatureFreshness!=='Current'?'Signature freshness: '+(r.signatureFreshness||'Unknown')+'. ':'')+(r.engineOnline!==true?'Engine unavailable or unverified. ':'')+((r.rootCoverage||[]).some(x=>['Uncovered','Initializing','Excluded'].includes(x.state))?'Scope monitoring requires review.':'');
    if(byId('endpoint-worker-state'))byId('endpoint-worker-state').textContent=workerText;
    for(const [id,value] of [['ep-count-baseline',r.scannedFiles],['ep-count-realtime',r.realTimeChecked],['ep-count-pending',r.baselineDiscoveredPending],['ep-count-queue',r.queueDepth]])if(byId(id))byId(id).textContent=fresh&&value!=null?Number(value).toLocaleString():'—';
    if(byId('endpoint-scan-health'))byId('endpoint-scan-health').textContent=health;
    if(byId('ep-scan-summary'))byId('ep-scan-summary').textContent=message+(fresh&&r.scanRunning?' · '+(r.scannedFiles??'—')+' files checked':'');
    if(byId('ep-worker-summary'))byId('ep-worker-summary').textContent=workerText;

    if(byId('endpoint-active-scope'))byId('endpoint-active-scope').textContent=!fresh?'Active scan scope: awaiting fresh telemetry':r.status==='disabled'?'Active scan scope: disabled':'Active scan scope: '+(Array.isArray(r.protectedPaths)&&r.protectedPaths.length?r.protectedPaths.join(' · '):'Not reported');
    renderEndpointRootCoverage(byId('endpoint-root-coverage'),r,fresh);
    if(byId('endpoint-usn-state')){const volumes=Array.isArray(r.usnVolumes)?r.usnVolumes:[];byId('endpoint-usn-state').textContent=!fresh?'NTFS journal: awaiting fresh telemetry':!r.realTime?'NTFS journal: real-time disabled':volumes.length?'NTFS journal · '+volumes.map(v=>v.volume+' '+v.status).join(' · ')+' · Durable pending: '+(r.usnQueueDepth??'—'):'NTFS journal: no configured local volumes';byId('endpoint-usn-detail').textContent=fresh?volumes.map(v=>v.volume+' '+v.detail+(v.status==='Live'||v.status==='Replaying'?' · checkpoint '+v.checkpoint+' / '+v.tail:'')).concat((r.privilegedWatcherDetails||[]).map(w=>w.path+' · '+(w.active?'Privileged watcher active':w.detail))).join(' | '):'';}
    byId('endpoint-live-counts').textContent='Full scan: '+(r.scannedFiles??'—')+' files (cached: '+(r.baselineCached??'—')+') · Real-time checks: '+(r.realTimeChecked??'—')+' since reset / policy start · SYSTEM-assisted checks: '+(r.privilegedFileChecks??'—')+' · Pending: '+(r.queueDepth??'—')+' · Priority entries: '+(r.priorityQueueDepth??'—')+' · Durable cooldown: '+(r.deferredQueueDepth??'—')+' · Durable ready: '+(r.durableReadyDepth??'—');
    if(byId('endpoint-download-state'))byId('endpoint-download-state').textContent='Downloads: '+(r.downloadStatus??'Not available')+' · Attempts: '+(r.downloadChecks??'—')+' · Pending: '+(r.downloadPending??'—')+(r.downloadRoots?.length?' · Folders: '+r.downloadRoots.join(' · '):'')+(r.downloadLastPath?' · Last: '+r.downloadLastPath+' · '+(r.downloadLastResult??''):'');
    byId('endpoint-live-file').textContent=r.lastFileScanUtc?'Last successful signature check: '+new Date(r.lastFileScanUtc).toLocaleString()+(r.lastScannedPath?' · '+r.lastScannedPath:''):'No successful file signature check reported yet.';
    if(byId('endpoint-signature-schedule')){const schedule=r.signatureSchedule,day=schedule?.frequency==='weekly'?' on '+(['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'][schedule.weekday]||'—'):schedule?.frequency==='monthly'?' on day '+schedule.monthDay:'';byId('endpoint-signature-schedule').textContent=r.status==='disabled'?'Scheduled refresh · Paused (Endpoint Protection disabled)':!fresh?'Scheduled refresh · Awaiting fresh status':schedule?.enabled?'Scheduled refresh · '+schedule.frequency+day+' at '+schedule.localTime+' (monitoring host) · '+schedule.status+' · Next: '+localEndpointDate(schedule.nextRunUtc)+' · Last request: '+localEndpointDate(schedule.lastScheduledRequestUtc):schedule?'Scheduled refresh · Disabled':'Scheduled refresh · Status not recorded';}
    if(byId('endpoint-signature-comparison'))byId('endpoint-signature-comparison').textContent=fresh&&r.signatureComparison?r.signatureComparison:'Official daily version comparison awaiting telemetry.';
    if(byId('endpoint-signature-log'))byId('endpoint-signature-log').textContent='Latest database update reported by FreshClam log: '+localEndpointDate(r.lastReportedSignatureUpdateUtc)+(r.signatureUpdateLogRecognized?'':' · No recent matching log record');
    const reset=byId('endpoint-reset');if(reset)reset.disabled=!csrf||!fresh||r.status==='disabled'||endpointScanBusy||!!endpointScanRequested;
    const b=byId('endpoint-scan-now');b.disabled=!csrf||endpointScanBusy||!!endpointScanRequested||r.status==='disabled'||!!r.scanRunning||!fresh;b.textContent=r.scanRunning&&fresh?(r.engineOnline!==true?'Waiting for engine':r.baselineThrottleReason?'Background paused':'Scanning…'):endpointScanRequested?'Scan queued…':'Scan now';
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
        const sample=endpointLastSample,reported=sample?.result?.signatureMaintenance,recovered=sample?.stale!==true&&Number(sample?.ageSeconds??Infinity)<=20&&sample?.result?.signatureMaintenanceDefinitionRecovered===true&&reported?.attemptUtc===signatureState.attemptUtc&&reported?.checkedUtc===signatureState.checkedUtc&&reported?.detail===signatureState.detail&&reported?.status===signatureState.status;
        const state=byId('endpoint-signature-state');state.replaceChildren(healthBadge(signatureRequested?'Queued':signatureState.status||'Not recorded',({Running:'info',Updated:'ok',Checked:'ok',Failed:'fail',Warning:'review',Interrupted:'review',Unavailable:'unknown'})[signatureState.status]||'unknown'),document.createTextNode(' '+(startupError||signatureState.detail||'')+(recovered?' · Historical warning reconciled by subsequent live signature verification; see current signature status.':'')+(cooldown&&signatureState.status!=='Running'?' · Next request after '+localEndpointDate(new Date(Date.parse(signatureState.attemptUtc)+3600000).toISOString()):'')+(!m.supported?' · Standard local service/port required.':'')));
        const providerPanel=byId('endpoint-provider-schedules');
        if(providerPanel){
            if(!Array.isArray(m.providers))providerPanel.textContent='Provider separation not yet verified. Run Setup → Third-party signature sources to migrate existing URLs.';
            else if(!m.providers.length)providerPanel.textContent='No third-party providers configured.';
            else{const rows=m.providers.map(p=>({Provider:p.provider,Databases:p.files,'Interval (hours)':p.intervalHours,Status:p.status==='Attempt reserved'?(Date.parse(p.nextUtc)>Date.now()?'Attempt reserved / cooldown':'Previous attempt unconfirmed — due'):p.status==='Failed'?(Date.parse(p.nextUtc)>Date.now()?'Failed — cooldown':'Failed — retry due'):p.status==='Migration cooldown'&&Date.parse(p.nextUtc)>Date.now()?'Migration cooldown':Date.parse(p.nextUtc)>Date.now()?'Cooldown':'Due','Last attempt':localEndpointDate(p.lastAttemptUtc),'Last successful batch':localEndpointDate(p.lastSuccessUtc),'Next eligible attempt':localEndpointDate(p.nextUtc)}));providerPanel.replaceChildren(table(rows,'provider schedules'));}
        }
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
    byId('endpoint-reset').onclick=async()=>{
        if(endpointScanBusy||endpointScanRequested)return;
        if(!(await confirmAction('Reset scan counters and rescan?','Reset scan counters and re-evaluate per-path scan warnings. Journal and watcher coverage gaps remain active until verified recovery. Malware and canary violations, historical incidents, quarantine evidence, and pending journal events are preserved.','Reset & rescan')))return;
        endpointScanBusy=true;byId('endpoint-reset').disabled=true;
        try{await request('/ui/endpoint-reset',{});const r=endpointLastSample?.result||{};endpointScanRequested={at:Date.now(),previous:r.lastScanUtc,started:r.scanStartedUtc};notice('Reset and rescan requested.');}catch(e){failure(e);}finally{endpointScanBusy=false;}
    };
    refreshEndpointMaintenance();
    byId('endpoint-ack-previous').onclick=async()=>{
        if(!endpointAck||!endpointAck.unread||endpointAckBusy||endpointAlertActionsBusy.size)return;
        const cutoff=endpointAck.through,count=endpointAck.unread;endpointAckBusy=true;endpointAckEpoch++;endpointAckControls();
        try{if(!(await confirmAction('Acknowledge previous endpoint alerts?','Mark '+count+' existing unread Endpoint Protection alerts as read. New alerts arriving after this snapshot remain unread. Active threats and history are not cleared.','Acknowledge')))return;
            endpointAck=await request('/ui/endpoint-ack',{through:cutoff});for(const a of endpointReviewRecords)if(a.sequence<=cutoff)endpointConfirmedReads.add(a.id);window.LinkScopeToast?.categoryRead?.('endpoint_protection',cutoff);endpointAlertFeedback('Previous endpoint alerts acknowledged. Active findings remain unchanged.','success');
        }catch(e){endpointAlertFeedback(endpointReviewMessage(e),'error');}finally{endpointAckEpoch++;endpointAckBusy=false;endpointAckControls();renderEndpointAlertReview();}
        try{await renderHealth();}catch(e){endpointAlertFeedback('Could not refresh alert telemetry: '+endpointReviewMessage(e),'error');}
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
    const healthRequest=page==='endpoint'?++endpointHealthIssued:0;
    const data=await request(page==='endpoint'?'/ui/endpoint':page==='integrity'?'/ui/integrity':'/ui/system');
    if(page==='endpoint'){if(healthRequest<endpointHealthApplied)return;endpointHealthApplied=healthRequest;endpointLastSample=data.categories?.endpoint_protection;const alertFreshness=byId('endpoint-alert-review-freshness');if(alertFreshness)alertFreshness.textContent='';if(Array.isArray(data.alerts))renderEndpointAlertReview(data.alerts);else if(alertFreshness)alertFreshness.textContent='Alert records missing from response. Showing last received records.';}
    if(page==='integrity')integrityActivity(data.categories?.data_integrity,data.generatedUtc);
    if(page==='endpoint'){
        if(!epAckPending){epAckPending=true;const epoch=endpointAckEpoch;request('/ui/endpoint-ack').then(ack=>{if(!endpointAckBusy&&epoch===endpointAckEpoch)endpointAck=ack;endpointAckControls();}).catch(()=>{}).finally(()=>{epAckPending=false;});}
        endpointActivity(data.categories?.endpoint_protection,data.generatedUtc);renderContainmentReadiness(data.categories?.endpoint_protection);endpointOverview(data.categories?.endpoint_protection,Array.isArray(data.alerts)?data.alerts.filter(a=>a.category==='endpoint_protection'):null);if(Date.now()-maintenanceLast>4000)refreshEndpointMaintenance();
        const sample=data.categories?.endpoint_protection;byId('endpoint-telemetry-warning').hidden=sample?.status==='disabled'||(!sample?.stale&&Number(sample?.ageSeconds??Infinity)<=20);const key=JSON.stringify([sample?.collectedUtc,sample?.status,!!sample?.stale,Number(sample?.ageSeconds??Infinity)>20,data.alerts]);if(epRenderKey===key&&byId('metrics').children.length){byId('stamp').textContent='Snapshot · '+new Date(data.generatedUtc).toLocaleString();return;}epRenderKey=key;
    }
    const activeAlerts=Array.isArray(data.alerts)?data.alerts:[];const cats=data.categories,metrics=byId('metrics'),alerts=byId('alerts'),results=byId('results');
    const opened=new Set(Array.from(document.querySelectorAll('#results details[open],#metrics details[open]'),d=>d.dataset.category));
    const active=document.activeElement,focusKey=active?.dataset?.healthSearch,selection=focusKey?[active.selectionStart,active.selectionEnd]:null;
    const first=!results.children.length;notice('');byId('stamp').textContent='Snapshot · '+new Date(data.generatedUtc).toLocaleString();
    metrics.replaceChildren();alerts.replaceChildren();results.replaceChildren();
    for(const [key,v] of Object.entries(cats)){
        if(page==='endpoint'?key!=='endpoint_protection':page==='integrity'?key!=='data_integrity':['data_integrity','endpoint_protection'].includes(key))continue;
        const result=v.result||v,rows=result.items||[],state=(v.stale?'Stale · ':'')+'Collection: '+(result.status||'unknown');
        const kind=v.stale?'review':key==='endpoint_protection'&&result.status==='scanning'&&result.engineOnline===true?'unknown':healthKind(result.status);
        const time=v.collectedUtc?' · '+new Date(v.collectedUtc).toLocaleTimeString():'';
        if(key==='cpu'||key==='ram'){const card=metric(label(key),pct(result.usedPercent),state+(key==='ram'&&result.totalBytes?' · '+gib(result.usedBytes)+' of '+gib(result.totalBytes):'')+time,kind,metricAlertState(activeAlerts,key,null,result.usedPercent==null&&kind==='ok'?'unknown':kind));card.id='category-'+key;metrics.append(card);continue;}
        if(key==='disk_usage')for(const disk of rows){const diskKind=v.stale?'review':healthKind(disk.status||result.status);metrics.append(metric('Volume '+disk.volume,pct(disk.usedPercent),gib(disk.freeBytes)+' free · '+state+time,diskKind,metricAlertState(activeAlerts,key,disk.volume,disk.usedPercent==null&&diskKind==='ok'?'unknown':diskKind)));}
        if(key==='smart')for(const disk of rows.filter(d=>d.recommendation==='replace'||d.recommendation==='review')){
            const msg=element('div',(disk.recommendation==='replace'?'Plan disk replacement':'Review disk health')+' · '+disk.model+' (disk '+disk.device+') · '+(disk.estimatedLifeRemainingPercent==null?'Life unavailable':pct(disk.estimatedLifeRemainingPercent)+' estimated life remaining')+' · '+state+time);msg.className='alert health-alert '+verdictClass(disk.recommendation);alerts.append(msg);
        }
        let section=element(page==='integrity'||page==='endpoint'?'section':'details');section.dataset.category=key;section.id='category-'+key;section.open=page==='integrity'||opened.has(key)||(first&&['smart','firewall','antivirus','security','data_integrity'].includes(key));
        const categoryState=categoryAlertState(activeAlerts,key,result,rows,kind);
        if(key==='endpoint_protection'&&result.status==='scanning'&&!categoryState.messages.length&&categoryState.kind!=='fail'){categoryState.kind='unknown';categoryState.status='Verifying';}
        if(key==='endpoint_protection'&&result.status==='disabled'&&!categoryState.messages.length){categoryState.kind='unknown';categoryState.status='Disabled';}
        const infoState=(result.truncated?'Showing the first 256 records. ':'')+state;
        // Endpoint overview is deliberately concise. Preserve the actual severity,
        // but keep raw alert messages (paths, hashes, exceptions) in the evidence area.
        const endpointAlerts=key==='endpoint_protection'?activeAlerts.filter(a=>!a.resolved&&a.category===key&&['critical','error','warning'].includes(String(a.severity||'').toLowerCase())):[];
        decorateHealthSection(section,label(key),infoState,kind,key==='endpoint_protection'?{...categoryState,messages:[]}:categoryState,time);
        if(key==='endpoint_protection'&&(result.status!=='disabled'||endpointAlerts.length)){
            const summary=element('p');summary.className='endpoint-overview-note';
            const malware=Number(result.activeMalware||0),heuristic=Number(result.activeHeuristic||0);
            const critical=endpointAlerts.filter(a=>['critical','error'].includes(String(a.severity||'').toLowerCase())).length;
            const warnings=endpointAlerts.length-critical;
            const parts=[];
            if(malware>0)parts.push(malware+' active malware finding'+(malware===1?'':'s'));
            if(heuristic>0)parts.push(heuristic+' active heuristic finding'+(heuristic===1?'':'s'));
            if(critical>0)parts.push(critical+' critical/error alert'+(critical===1?'':'s'));
            if(warnings>0)parts.push(warnings+' warning'+(warnings===1?'':'s'));
            if(!parts.length&&categoryState.kind!=='ok')parts.push(result.status==='scanning'&&!categoryState.messages.length?'Baseline verification in progress':'Protection status requires review');
            if(parts.length){summary.append(element('span',parts.join(' · ')+'. '));const link=element('a','View findings and diagnostics');link.href=result.status==='disabled'?'/alerts':'#endpoint-alert-diagnostics';if(result.status!=='disabled')link.onclick=()=>{const d=byId('endpoint-alert-diagnostics');if(d){endpointJump(d);d.open=true;}};summary.append(link);section.append(summary);}
        }
        if(key==='smart'&&rows.length){for(const disk of rows)section.append(renderDrive(disk));}
        else if(key==='events'||key==='event_details'){for(const group of rows){const heading=element('h3',group.channel+' ');heading.append(healthBadge(group.status,healthKind(group.status)));if(group.truncated)heading.append(' · capped');section.append(heading,table(group.items||[],key+' · '+group.channel));}}
        else if(key==='endpoint_protection'){
            if(result.status==='disabled')section.append(element('p','Enable Endpoint Protection in Settings.'));
            else {
                const stats=element('div');stats.className='cards integrity-metrics';stats.dataset.endpointView='scan';const behaviorStats=element('div');behaviorStats.className='cards integrity-metrics';behaviorStats.dataset.endpointView='behavior';const engineStats=element('div');engineStats.className='cards integrity-metrics';engineStats.dataset.endpointView='maintenance';
                const danger=Number(result.activeMalware)>0||rows.some(r=>r.severity==='critical')||endpointAlerts.some(a=>['critical','error'].includes(String(a.severity).toLowerCase())),warnings=rows.some(r=>r.severity==='warning')||endpointAlerts.some(a=>String(a.severity).toLowerCase()==='warning');
                const independent=v.stale||Number(v.ageSeconds??Infinity)>20||!Array.isArray(data.alerts)||result.truncated||Number(result.pendingAlertDelivery)>0?'unknown':'ok',coverage=Number(result.activeScanIssues||0)>0||Number(result.coverageIssueCount||0)>0;
                const canaryState=(result.canaries||[]).some(c=>c.status==='critical')?'fail':(result.canaries||[]).some(c=>c.status!=='Enrolled')?'review':independent;
                const cards=[
                    {name:'ClamAV engine',value:result.engineOnline===true?'Online':result.engineOnline===false?'Unavailable':'—',kind:v.stale?'review':result.engineOnline===true?(rows.some(r=>r.path==='ClamAV'&&r.severity==='warning')?'review':'ok'):result.engineOnline===false?'review':'unknown',foot:(result.engineVersion||'Waiting for scan')+' · DB '+(result.signatureDatabaseVersion||'Unknown')+(result.engineRecoveryPending?' · Awaiting successful readiness scan':''),target:'endpoint-signature-state',explanation:'Open signature and engine status'},
                    {name:'Files scanned',value:result.scannedFiles,kind:result.scanRunning&&result.baselineThrottleReason?'review':result.scanRunning?'unknown':(coverage?'review':result.fullScanComplete===true?'ok':'unknown'),foot:(result.scanRunning?(result.baselineThrottleReason?'Baseline paused · '+result.baselineThrottleReason:'Baseline running'):'Last baseline')+' · cached: '+(result.baselineCached??0)+' · baseline totals can include restored progress',target:'ep-scan-evidence',explanation:'Open scan activity and evidence'},
                    {name:'Real-time queue',value:result.queueDepth,kind:rows.some(r=>r.change==='Real-time queue overflow')||(result.usnVolumes||[]).some(v=>v.status==='Backpressure')?'review':'ok',foot:'USN pending: '+(result.usnQueueDepth??'—')+' · Watcher pending: '+(result.watcherQueueDepth??'—')+' · Overflows: '+(result.overflowCount??0)+' · Journal-backed roots: '+(result.watcherRootsCoveredByJournal??0)+' · Privileged watcher roots: '+(result.watcherRootsCoveredByPrivileged??0),target:'endpoint-usn-state',explanation:'Open queue and journal explanation'},
                    {name:'File changes',value:result.changedFiles,kind:rows.some(r=>r.change==='Possible ransomware activity'||r.change==='Possible ransomware activity (extended observation)')?'review':'ok',foot:'Rapid window: '+(result.behaviorWindowSeconds??'—')+' s · change threshold: '+(result.behaviorChangeThreshold??'—'),target:'ep-behavior-evidence',explanation:'Open file activity evidence'},
                    {name:'Entropy changes',value:result.entropyChanges,kind:rows.some(r=>r.change==='Possible ransomware activity')?'review':'ok',foot:'Minimum sample: '+(result.entropyMinimumSampleBytes??'—')+' bytes · current ≥ '+(result.entropyMinimumCurrent??'—')+' · increase ≥ '+(result.entropyMinimumIncrease??'—'),target:'ep-behavior-evidence',explanation:'Open entropy-based evidence'},
                    {name:'Extended entropy changes',value:result.extendedEntropyPeak,kind:rows.some(r=>r.change==='Possible ransomware activity (extended observation)')?'review':'ok',foot:'Peak in one folder · '+(result.extendedEntropyWindowSeconds??'—')+' s · warning threshold: '+(result.extendedEntropyThreshold??'—'),target:'ep-behavior-evidence',explanation:'Open extended entropy evidence'},
                    {name:'Canary files',value:result.canaryCount,kind:rows.some(r=>r.change==='Canary integrity violation')?'fail':result.canaryCount===0?'unknown':((result.canaries||[]).some(c=>c.status==='critical')?'fail':(result.canaries||[]).some(c=>c.status!=='Enrolled')?'review':'ok'),foot:result.canaryCount===0?'Not configured':'Configured canaries',target:'ep-canary-evidence',explanation:'Open canary evidence'},
                    {name:'Active findings',value:result.violations,kind:danger?'fail':warnings||coverage||Number(result.violations)>0?'review':independent,foot:'Active security and operational alert records',target:'endpoint-alert-diagnostics',openId:'endpoint-alert-diagnostics',explanation:'Open findings and diagnostics'},
                    {name:'Mode',value:result.mode,kind:result.mode==='monitor'?'ok':result.responseEngineStatus==='Ready'&&(result.responsePathsReadiness||[]).length&&(result.responsePathsReadiness||[]).every(x=>x.status==='ok')?'ok':'review',foot:(result.mode==='monitor'?'Detection only':'Engine: '+(result.responseEngineStatus||'Not checked')+' · Response paths: '+((result.responsePathsReadiness||[]).length&&(result.responsePathsReadiness||[]).every(x=>x.status==='ok')?'Advisory clear':'Review access'))+' · Process correlation: '+(result.processCorrelation||'Unavailable'),target:'endpoint-evidence',explanation:'Open response and evidence details'}
                ];
                for(const cardInfo of cards){
                    const val=cardInfo.value==null?'—':String(cardInfo.value),state=cardInfo.value==null?'unknown':cardInfo.kind;
                    const status=cardInfo.name==='Files scanned'&&result.scanRunning&&result.baselineThrottleReason?'Paused':cardInfo.name==='Files scanned'&&result.scanRunning?'Verifying':cardInfo.name==='Real-time queue'&&state==='ok'&&Number(cardInfo.value)>0?'Queued':alertStateLabel(state);
                    const card=metric(cardInfo.name,val,cardInfo.foot,state,{kind:state,status,messages:[]});
                    const group=['File changes','Entropy changes','Extended entropy changes','Canary files'].includes(cardInfo.name)?behaviorStats:['ClamAV engine','Mode'].includes(cardInfo.name)?engineStats:stats;
                    if(Number(v.ageSeconds??Infinity)>20||v.stale){card.classList.remove('ok','fail','review');card.classList.add('unknown');card.querySelector('.health-metric-heading .health-badge').replaceWith(healthBadge('Stale sample','unknown'));}
                    group.append(makeMetricJump(card,cardInfo.target,cardInfo.explanation,cardInfo.openId));
                }section.append(stats,behaviorStats,engineStats);
                const countHeading=element('h3','Scan statistics and active findings');countHeading.dataset.endpointView='scan';section.append(countHeading);
                const counts=element('div');counts.className='cards integrity-metrics';counts.dataset.endpointView='scan';
                // Severity is driven by unresolved findings, not cumulative historical scan checks.
                const currentKind=independent;
                const currentCount=(name)=>result[name]==null?null:Number(result[name]);
                const malware=currentCount('activeMalware'),heuristic=currentCount('activeHeuristic'),scanIssues=currentCount('activeScanIssues'),vault=currentCount('quarantineCount');
                const counterCards=[
                    ['Clean signature checks',result.cleanChecks,currentKind,'Strict file verdicts since reset / policy start (not baseline totals)'],
                    ['Shared log snapshot checks',result.snapshotCleanChecks,currentKind,'Whole-file clean snapshots verified by byte recheck; no clean-cache reuse or automatic response'],
                    ['Cached clean verifications',result.cachedChecks,currentKind,'Verified NTFS change stamp or content hash and engine generation match; no new antivirus verdict'],
                    ['Active confirmed malware',malware,malware>0?'fail':currentKind,'Historical infected checks: '+(result.infectedChecks??'—')],
                    ['Active heuristic findings',heuristic,heuristic>0?'review':currentKind,'Historical heuristic checks: '+(result.heuristicChecks??'—')],
                    ['Excluded checks',result.excludedChecks,'unknown','Excluded by policy'],
                    ['Active scan issues',scanIssues,scanIssues>0||coverage?'review':currentKind,'Outstanding file/path checks: '+(result.coverageIssueCount??'—')+' · Historical failed: '+(result.failedChecks??'—')+' · Deferred since reset: '+(result.deferredChecks??'—')],
                    ['Quarantine vault',vault,vault==null?'unknown':vault>0?'review':currentKind,'Historical quarantined checks: '+(result.quarantinedChecks??'—')+' · Deleted payloads: '+(result.quarantineDeletedCount??'—')]
                ];
                for(const [name,val,k,foot] of counterCards){const state=val==null||Number(v.ageSeconds??Infinity)>20||v.stale?'unknown':k;const card=metric(name,val==null?'—':String(val),foot,state,{kind:state,status:val==null?'Not available':name==='Excluded checks'?'Excluded by policy':name==='Quarantine vault'&&val>0?'Isolated evidence':alertStateLabel(state),messages:[]});const target=name==='Quarantine vault'?'endpoint-quarantine-manager':'endpoint-evidence';const openId=name==='Active scan issues'||name==='Active confirmed malware'||name==='Active heuristic findings'?'endpoint-alert-diagnostics':null;counts.append(makeMetricJump(card,target,'Open supporting evidence',openId));}section.append(counts);
                const scanDetails=summaryDetails('Scan & protection details',[
                    ['Last finished baseline attempt',localDate(result.lastScanUtc,'Not completed')],
                    ['Current baseline state',result.scanRunning?(result.baselineThrottleReason?'Paused — '+result.baselineThrottleReason:'Running'):result.fullScanComplete?'Complete':'Incomplete / not verified'],
                    ['Baseline paths visited',result.baselineVisited??'Not reported'],
                    ['Baseline cached clean files',result.baselineCached??'Not reported'],
                    ['Metadata-only cache hits',result.metadataCachedChecks??'Not reported'],
                    ['Background read limit',result.backgroundReadMiB==null?'Not reported':result.backgroundReadMiB+' MiB/s'],
                    ['Background scan pacing',result.baselineThrottleReason||'Not paused'],
                    ['Disk pressure provider',result.diskPressureStatus||'Not sampled'],
                    ['Baseline recovery',result.baselineResumed?'Resumed checkpoint; follow-up reconciliation required':'Normal traversal'],
                    ['Maximum verdict cache age',result.verdictCacheMaxAgeSeconds?Math.round(result.verdictCacheMaxAgeSeconds/86400)+' days':'Not reported'],
                    ['Discovered paths awaiting traversal',result.baselineDiscoveredPending??'Not reported'],
                    ['Baseline traversal cap',result.baselineEntryLimit??'Not reported'],
                    ['Configured per-file size cap',result.configuredMaxFileMiB==null?'Not reported':result.configuredMaxFileMiB+' MiB'],
                    ['Next scheduled scan',localDate(result.nextScanUtc,result.scanRunning?'In progress':'Not scheduled')],
                    ['Signature freshness',result.signatureFreshness||'Unknown'],
                    ['Official daily version comparison',result.signatureComparison||'Not reported'],
                    ['Engine-reported signature date',localDate(result.signatureDatabaseTimestamp,result.signatureDatabaseTimestamp||'Unknown')],
                    ['Last engine status check',localDate(result.lastSignatureCheckUtc,'Not verified')],
                    ['Response engine authentication',result.responseEngineStatus||'Not checked'],
                    ['Response verified',localDate(result.responseCheckedUtc,'Not verified')],
                    ['Queue overflows',result.overflowCount??0],
                    ['Size-limited files',result.sizeLimitedFiles??0],
                    ['Pending alert delivery',result.pendingAlertDelivery??0]
                ],result.protectedPaths,result.responseEngineDetail||'Waiting for response verification');const scanDisclosure=element('details');scanDisclosure.dataset.endpointView='scan';scanDisclosure.dataset.category='ep-scan-details';scanDisclosure.open=opened.has('ep-scan-details');scanDisclosure.append(element('summary','Advanced scan and response details'),scanDetails);section.append(scanDisclosure);
                if(result.mode!=='monitor'&&(result.responsePathsReadiness||[]).length){const d=element('div');d.dataset.endpointView='maintenance';d.append(element('h3','Authorized response path access (advisory)'),table(result.responsePathsReadiness,'endpoint response access'));section.append(d);}
                // Render both statistic groups before the fixed activity/maintenance panel.
                // That panel is never detached or recreated by the two-second telemetry poll.
                const bdetail=element('div');bdetail.dataset.endpointView='behavior';bdetail.id='ep-behavior-evidence';bdetail.append(element('h3','Behavioral findings'),element('p','File changes and significant entropy increases are detection signals, not proof of ransomware. The extended detector is warning-only.'),(rows.filter(x=>String(x.change||'').startsWith('Possible ransomware activity')||x.change==='Canary integrity violation').length?table(rows.filter(x=>String(x.change||'').startsWith('Possible ransomware activity')||x.change==='Canary integrity violation'),'endpoint behavioral findings'):element('p','No active behavioral findings in this snapshot.')));section.append(bdetail);
                metrics.append(section);
                section=element('section');section.id='endpoint-evidence';
                section.append(element('h2','Scan activity & threat evidence'));
                const canaryHeading=element('h3','Registered canary files');canaryHeading.id='ep-canary-evidence';section.append(canaryHeading,(result.canaries||[]).length?table(result.canaries,'endpoint canaries'):element('p','No canaries configured. Use Canary manager above, LinkScope Setup, or register existing decoys under Settings → Endpoint Protection. Do not edit or delete enrolled decoys.'));
                const activityHeading=element('h3','Live file scan activity (latest 100)');activityHeading.id='ep-scan-evidence';section.append(activityHeading,(result.scanActivity||[]).length?table(result.scanActivity,'endpoint scan activity'):element('p','No file scan results yet.'));
                const coverageHeading=element('h3','Scan coverage details');coverageHeading.id='ep-coverage-evidence';section.append(coverageHeading,element('p',result.coverageIssueCount==null?'Coverage details not reported by this service.':String(result.coverageIssueCount)+' outstanding file/path scan issues. Showing up to 100 recent paths. These are coverage gaps, not malware detections.'));
                if((result.coverageBreakdown||[]).length)section.append(table(result.coverageBreakdown,'endpoint coverage categories'));
                if((result.coverageDetails||[]).length)section.append(table(result.coverageDetails,'endpoint scan coverage'));
                const findingHeading=element('h3','Active detections, coverage warnings and response evidence');findingHeading.id='ep-active-evidence';section.append(findingHeading,rows.length?table(rows,key):element('p',result.status==='ok'?'No active findings.':'Scan pending or incomplete.'));
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
    if(page==='endpoint'){applyEndpointView();byId('endpoint-telemetry-warning').hidden=!(Number(data.categories?.endpoint_protection?.ageSeconds??Infinity)>20||data.categories?.endpoint_protection?.stale)||data.categories?.endpoint_protection?.status==='disabled';}
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
    if(d){endpointJump(d);if(d.tagName==='DETAILS')d.open=true;for(let p=d.parentElement;p;p=p.parentElement)if(p.tagName==='DETAILS')p.open=true;d.scrollIntoView({block:'start'});}
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
        if(page==='endpoint'){setupEndpointWorkspace();setupEndpointControls();setupQuarantineManager();}else setupIntegrityControls();
        async function pollIntegrity(){try{await renderHealth();}catch(ex){if(page==='endpoint'){const alertFreshness=byId('endpoint-alert-review-freshness');if(alertFreshness)alertFreshness.textContent='Alert refresh failed. Showing last received records; verify current status before acting.';renderEndpointResources(null,false);renderContainmentReadiness(null);endpointOverview(null,[]);epRenderKey='';byId('endpoint-telemetry-warning').hidden=false;byId('endpoint-live').dataset.state='warning';byId('endpoint-live-state').textContent='Unable to refresh scanner telemetry';byId('ep-scan-summary').textContent='Telemetry refresh failed';byId('ep-worker-summary').textContent='Worker state unknown';byId('endpoint-scan-now').disabled=true;endpointAck=null;endpointAckControls();}else{byId('integrity-live').dataset.state='warning';byId('integrity-live-state').textContent='Unable to refresh scanner telemetry';byId('integrity-scan-now').disabled=true;}failure(ex);}finally{setTimeout(pollIntegrity,2000);}}
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
