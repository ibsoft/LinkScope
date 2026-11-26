'use strict';
const byId=id=>document.getElementById(id);
const page=document.body.dataset.page;
const labels={data_integrity:'Data Integrity & Tamper Detection',ram:'RAM',cpu:'CPU',disk_usage:'Disk usage',smart:'Disk health and SSD life',events:'Event logs · last 24 hours',firewall:'Firewall profiles',antivirus:'Antivirus',security:'Security posture',event_details:'Event message text',ip_addresses:'IP addresses',dns:'DNS',bios:'BIOS',usb:'USB',os:'Operating system'};
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
    keys.forEach(k=>head.append(element('th',k)));
    for(const row of rows){const tr=body.insertRow();for(const k of keys){const v=row[k];const cell=tr.insertCell(),text=v==null?'—':typeof v==='object'?JSON.stringify(v):String(v);const kind=(page==='system'||page==='integrity')?healthCellKind(key,k,v):null;if(kind)cell.append(healthBadge(text,kind));else cell.textContent=text;}}
    container.append(t);LinkScopePages.attach(t,key,label(key),false,page==='system'||page==='integrity');return container;
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
function fillIntegrity(c){const i=c.Integrity;byId('IntegrityEnabled').checked=i.Enabled;byId('IntegrityInterval').value=i.IntervalSeconds;byId('IntegrityRecursive').checked=i.Recursive;byId('IntegrityWriteEvents').checked=i.WriteEvents;for(const key of ['Paths','ExcludedPaths','ExcludedPatterns'])byId('Integrity'+key).value=(i[key]||[]).join('\n');byId('IntegrityReason').value='';}
async function loadSettings(){
    const model=await request('/ui/settings');config=model.config;fillIntegrity(config);fillTelemetryExport(model);fillSiem(model);showRestart(model);formDirty=false;fillDelivery(model);fillLogs(model);fillAi(model);fillDatabaseMaintenance(model);
    byId('origin').textContent='Current listener · '+model.activeOrigin;
    byId('AllowedClientIPs').value=(config.AllowedClientIPs||[]).join('\n');byId('firewall-client-ip').textContent='Current client IP · '+model.clientIp;
    [...numbers,...strings].forEach(k=>byId(k).value=config[k]??'');flags.forEach(k=>byId(k).checked=config[k]);
    byId('certMode').value=config.CertificateThumbprint?'custom':'auto';certFields();
    byId('targets').value=config.Targets.map(t=>t.Address+' '+t.Name).join('\n');
    targetRules.clear();config.Targets.forEach(t=>targetRules.set(t.Address,{...t}));renderRules();
    byId('core').textContent='Default categories · '+model.core.map(label).join(', ');
    checkboxList('channels',model.channels,config.EventChannels);checkboxList('extras',model.extras,config.ExtraCategories);
    checkboxList('scopes',[...model.core,...config.ExtraCategories],model.core);tokenRows(model.tokens);
}
function settingsPage(){
    byId('configForm').addEventListener('input',()=>{formDirty=true;});
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
            next.Integrity=readIntegrity();
            if(Object.keys(next.Integrity).some(k=>JSON.stringify(next.Integrity[k])!==JSON.stringify(config.Integrity[k]))){
                next.IntegrityReason=byId('IntegrityReason').value.trim();
                if(next.IntegrityReason.length<5)throw Error('Enter a reason for the integrity policy change (at least five characters).');
                if(!(await confirmAction('Apply integrity monitoring policy?', 'Verify that all protected files are trusted before the first scan. Changing exclusions can reduce monitoring coverage. Existing trusted hashes will not be replaced.', 'Apply policy')))return;
            }
            next.AllowedClientIPs=byId('AllowedClientIPs').value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
            if(JSON.stringify(next.AllowedClientIPs)!==JSON.stringify(config.AllowedClientIPs||[])&&!(await confirmAction('Apply IP firewall allowlist?', 'All unlisted remote clients will be denied immediately, including API clients. Localhost is always allowed.', 'Apply allowlist')))return;
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
    if(['ok','normal','healthy','enabled','true','pass','passed','success'].includes(v))return 'ok';
    if(['critical','error','fail','failed','replace','disabled','false','unhealthy'].includes(v))return 'fail';
    if(['warning','review','partial','stale','degraded','warming_up'].includes(v))return 'review';
    return 'unknown';
}
function healthBadge(value,kind){const b=element('span',value);b.className='health-badge '+kind;return b;}
function healthCellKind(category,key,value){
    const k=key.toLowerCase();
    if(['status','state','level','severity','health','recommendation','registrationstatus'].includes(k))return healthKind(value);
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
    push(result?.status);push(result?.health);push(result?.severity);push(result?.state);
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
    const summary=element(page==='integrity'?'div':'summary');
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

async function renderHealth(){
    const data=await request(page==='integrity'?'/ui/integrity':'/ui/system');const activeAlerts=Array.isArray(data.alerts)?data.alerts:[];const cats=data.categories,metrics=byId('metrics'),alerts=byId('alerts'),results=byId('results');
    const opened=new Set(Array.from(results.querySelectorAll('details[open]'),d=>d.dataset.category));
    const active=document.activeElement,focusKey=active?.dataset?.healthSearch,selection=focusKey?[active.selectionStart,active.selectionEnd]:null;
    const first=!results.children.length;notice('');byId('stamp').textContent='Snapshot · '+new Date(data.generatedUtc).toLocaleString();
    metrics.replaceChildren();alerts.replaceChildren();results.replaceChildren();
    for(const [key,v] of Object.entries(cats)){
        if((page==='integrity')!==(key==='data_integrity'))continue;
        const result=v.result||v,rows=result.items||[],state=(v.stale?'Stale · ':'')+'Collection: '+(result.status||'unknown');
        const kind=v.stale?'review':healthKind(result.status);
        const time=v.collectedUtc?' · '+new Date(v.collectedUtc).toLocaleTimeString():'';
        if(key==='cpu'||key==='ram'){const card=metric(label(key),pct(result.usedPercent),state+(key==='ram'&&result.totalBytes?' · '+gib(result.usedBytes)+' of '+gib(result.totalBytes):'')+time,kind,metricAlertState(activeAlerts,key,null,result.usedPercent==null&&kind==='ok'?'unknown':kind));card.id='category-'+key;metrics.append(card);continue;}
        if(key==='disk_usage')for(const disk of rows){const diskKind=v.stale?'review':healthKind(disk.status||result.status);metrics.append(metric('Volume '+disk.volume,pct(disk.usedPercent),gib(disk.freeBytes)+' free · '+state+time,diskKind,metricAlertState(activeAlerts,key,disk.volume,disk.usedPercent==null&&diskKind==='ok'?'unknown':diskKind)));}
        if(key==='smart')for(const disk of rows.filter(d=>d.recommendation==='replace'||d.recommendation==='review')){
            const msg=element('div',(disk.recommendation==='replace'?'Plan disk replacement':'Review disk health')+' · '+disk.model+' (disk '+disk.device+') · '+(disk.estimatedLifeRemainingPercent==null?'Life unavailable':pct(disk.estimatedLifeRemainingPercent)+' estimated life remaining')+' · '+state+time);msg.className='alert health-alert '+verdictClass(disk.recommendation);alerts.append(msg);
        }
        const section=element(page==='integrity'?'section':'details');section.dataset.category=key;section.id='category-'+key;section.open=page==='integrity'||opened.has(key)||(first&&['smart','firewall','antivirus','security','data_integrity'].includes(key));
        const categoryState=categoryAlertState(activeAlerts,key,result,rows,kind);
        const infoState=(result.truncated?'Showing the first 256 records. ':'')+state;
        decorateHealthSection(section,label(key),infoState,kind,categoryState,time);
        if(key==='smart'&&rows.length){for(const disk of rows)section.append(renderDrive(disk));}
        else if(key==='events'||key==='event_details'){for(const group of rows){const heading=element('h3',group.channel+' ');heading.append(healthBadge(group.status,healthKind(group.status)));if(group.truncated)heading.append(' · capped');section.append(heading,table(group.items||[],key+' · '+group.channel));}}
        else if(key==='data_integrity'){
            if(result.status==='disabled'){section.className='health-category-card unknown';section.querySelector('.health-category-heading .health-badge').replaceWith(healthBadge('Disabled','unknown'));section.append(element('p','Enable integrity monitoring in Settings.'));}
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
                if(result.sequence!=null){const detail=element('p','Chain sequence: '+result.sequence+' · Head: '+result.chainHead);detail.className='integrity-chain-detail';section.append(detail);}
                if(result.protectedPaths?.length){const detail=element('p','Protected paths: '+result.protectedPaths.join(' · '));detail.className='integrity-chain-detail';section.append(detail);}
                const actions=element('div');actions.className='integrity-actions';
                const b=element('button','Scan now');b.type='button';b.className='secondary';b.disabled=!csrf;b.onclick=async()=>{b.disabled=true;try{await request('/ui/integrity-scan',{});notice('Integrity scan queued.');}catch(e){failure(e);}finally{b.disabled=false;}};actions.append(b);section.append(actions);
                section.append(rows.length?table(rows,key):element('p',result.status==='ok'?'No differences from trusted baseline.':'Integrity verification incomplete.'));
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
    if(d){if(d.tagName==='DETAILS')d.open=true;d.scrollIntoView({block:'start'});}
}
window.addEventListener('linkscope-reveal',revealCategory);window.addEventListener('hashchange',revealCategory);
async function start(){
    if(page==='login'){
        const form=byId('loginForm'), firstUse=byId('firstUse'), button=byId('signInButton');
        const spinner=byId('signInSpinner'), label=byId('signInLabel'), status=byId('notice');
        const destinations={'#integrity':'/integrity','#network':'/','#ai':'/ai','#logs':'/logs','#alerts':'/alerts','#report':'/system#report','#siem':'/settings#siem'};
        let endBusy=null,attempt=0;
        function setBusy(busy){
            button.disabled=busy;
            spinner.hidden=!busy;
            form.setAttribute('aria-busy',String(busy));
            if(busy){
                label.textContent=firstUse.disabled?'Signing in…':'Saving password and signing in…';
                status.textContent=label.textContent;
                endBusy=LinkScopeBusy.begin(label.textContent);
            }else{
                label.textContent=firstUse.disabled?'Sign in':'Save password and sign in';
                if(endBusy){endBusy();endBusy=null;}
            }
        }
        setBusy(false);
        window.addEventListener('pagehide',()=>{++attempt;});
        window.addEventListener('pageshow',event=>{
            if(event.persisted&&endBusy){setBusy(false);status.textContent='';}
        });
        form.onsubmit=async e=>{
            e.preventDefault();
            if(endBusy)return;
            const fields=form.elements, input={user:fields.user.value,password:fields.password.value};
            if(!firstUse.disabled){
                const next=fields.newPassword.value;
                if(next.length<7||next.length>128||!/[A-Z]/.test(next)||!/[a-z]/.test(next)||!/[0-9]/.test(next)||/[\x00-\x1f\x7f-\x9f]/.test(next)){
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
                if(response.changeRequired){
                    firstUse.disabled=false;firstUse.hidden=false;
                    status.textContent='Choose your own password to finish signing in.';fields.newPassword.focus();return;
                }
                form.reset();fields.password.value='';
                location.assign(destinations[location.hash]||'/system');
                navigating=true;
            }catch(ex){if(submitted===attempt)failure(ex);}
            finally{if(submitted===attempt&&!navigating)setBusy(false);}
        };return;
    }
    const session=await request('/ui/session');csrf=session.csrf||'';
    if(page==='settings'){
        await settingsPage();
        if(location.hash==='#siem')revealCategory();
        return;
    }
    if(page==='integrity'){
        async function pollIntegrity(){try{await renderHealth();}catch(ex){failure(ex);}finally{setTimeout(pollIntegrity,15000);}}
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
