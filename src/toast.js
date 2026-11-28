// Monitoring notices and the account controls are shared by all dashboard pages.
(() => {
    'use strict';
    const el=(tag,text)=>{const n=document.createElement(tag);if(text!=null)n.textContent=text;return n;};
    const id=k=>document.getElementById(k), toasts=new Map(), entries=new Map();
    const onHistory=document.body.dataset.page==='alerts';
    let csrf='',admin=false,authenticated=false,pending=false,again=false,nextPoll,through=null,historyVersion=0,historyPage=1,historySize=25;
    let cursor=null,guestReads=[],guestSeen=[],unreadCount=0;
    const readSignal='linkscope.alert-read-change',categoryReadThrough=new Map();
    function stored(store,key,fallback){try{return JSON.parse(store.getItem(key))??fallback;}catch{return fallback;}}
    function keep(store,key,value){try{store.setItem(key,JSON.stringify(value));}catch{}}
    function rememberGuest(){keep(localStorage,'linkscope.read-alerts.v1',guestReads.slice(-512));keep(sessionStorage,'ls-guest-seen',guestSeen.slice(-512));}
    const region=el('div');region.id='linkscope-toasts';region.setAttribute('role','region');region.setAttribute('aria-label','Notifications');document.body.append(region);
    const header=document.querySelector('body > header');
    function positionToasts(){const bottom=header?header.getBoundingClientRect().bottom:0;region.style.setProperty('--ls-toast-top',Math.min(Math.max(16,Math.ceil(bottom)+12),Math.max(16,window.innerHeight-180))+'px');}
    positionToasts();window.addEventListener('resize',positionToasts);window.addEventListener('scroll',positionToasts,{passive:true});
    if(header&&typeof ResizeObserver!=='undefined')new ResizeObserver(positionToasts).observe(header);
    function dismiss(key){
        const item=toasts.get(key);if(!item)return;
        clearTimeout(item.timer);toasts.delete(key);item.node.remove();
    }
    function show(key,severity,title,message,alert,action){
        if(toasts.has(key))return;
        const node=el('article');node.className='ls-toast ls-'+severity;
        const body=el('div');body.setAttribute('role',severity==='critical'||severity==='error'?'alert':'status');body.append(el('strong',title),el('p',message));node.append(body);
        const actions=el('div');actions.className='ls-toast-actions';
        if(alert){
            const button=el('button','Mark as read');button.type='button';button.onclick=async()=>{button.disabled=true;try{await ack(alert);}catch(ex){dismiss(key);feedback(ex);}finally{button.disabled=false;}};
            const link=el('a','View details');link.href=alert.category==='network'?'/':alert.category==='endpoint_protection'?'/endpoint':alert.category==='data_integrity'?'/integrity':'/system#category-'+encodeURIComponent(alert.category);
            link.onclick=async e=>{e.preventDefault();try{if(admin)await ack(alert);location.assign(link.href);}catch(ex){dismiss(key);feedback(ex);}};
            if(admin)actions.append(button);actions.append(link);
        }
        if(action){const link=el('a',action.label);link.href=action.href;actions.append(link);}
        const close=el('button',alert?'Close without marking read':'Dismiss');close.type='button';close.onclick=()=>dismiss(key);actions.append(close);node.append(actions);
        const item={node,alertSequence:alert?.sequence,category:alert?.category,timer:null};toasts.set(key,item);region.prepend(node);
        // Expire every toast after seven seconds without acknowledging the alert.
        item.timer=setTimeout(()=>dismiss(key),7000);
    }
    function feedback(e){if(onHistory)id('history-status').textContent=e.message;show('feedback','error','Action failed',e.message);}
    async function json(path,body){
        const options={credentials:'same-origin',cache:'no-store'};
        if(body!==undefined){options.method='POST';options.headers={'Content-Type':'application/json','X-CSRF-Token':csrf};options.body=JSON.stringify(body);}
        const res=await fetch(path,options);if(!res.ok){if(res.status===401)throw Error('Sign in to continue.');const problem=await res.json().catch(()=>({}));throw Error(problem.error||'Request failed (HTTP '+res.status+').');}return res.json();
    }
    function brand(label){
        const name=label?label+' LinkScope':'LinkScope',b=document.querySelector('.brand');if(!b)return;
        if(document.title.endsWith(b.textContent))document.title=document.title.slice(0,-b.textContent.length)+name;
        const nameNode=b.querySelector('.ls-brand-name');if(nameNode){if(nameNode.textContent!==name)nameNode.textContent=name;}else if(b.textContent!==name)b.textContent=name;
    }
    function applyCategoryRead(category,cutoff){categoryReadThrough.set(category,Math.max(categoryReadThrough.get(category)||0,Number(cutoff)||0));for(const [key,item] of toasts)if(item.category===category&&item.alertSequence!=null&&item.alertSequence<=cutoff)dismiss(key);}
    // Explanations are local, deterministic descriptions of the alert rule, not an AI verdict.
    function explainAlert(a){
        const title=String(a.title||'').toLowerCase(),category=String(a.category||'');
        const has=x=>title.includes(x);
        if(category==='endpoint_protection'){
            if(has('possible ransomware activity'))return ['The behavior detector observed multiple changed files with significant increases in content randomness (entropy). This pattern is consistent with encryption, but legitimate compression or encryption can also produce it. It is not a confirmed malware signature.','Review the recorded counts, observation window and any process attribution. Check the affected files and legitimate jobs before deciding on containment.'];
            if(has('canary integrity violation'))return ['A registered decoy file no longer matches its trusted baseline or could not be found. This is an integrity finding, not proof of ransomware or the identity of a writer.','Investigate the file and any matching audit evidence. Restore verified original content only after investigation.'];
            if(has('malware signature detected'))return ['ClamAV returned a recognized malware signature for an inspected file. A signature finding is different from a behavioral warning and may require verification of a false positive.','Review the recorded signature and SHA-256. Check whether quarantine succeeded in Endpoint Protection; do not assume detection means isolation.'];
            if(has('heuristic'))return ['The antivirus reported a heuristic or policy-related finding rather than a confirmed malware classification.','Review the exact engine verdict and file evidence before taking action.'];
            if(has('quarantine')||has('containment')||has('response engine'))return ['A response action, authorization check, or evidence-management operation was reported. The recorded result determines whether an action completed, was withheld, or failed.','Check the response and quarantine evidence, approved paths and permission diagnostics. Do not assume the file or process was contained.'];
            if(has('provider update')||has('provider schedule'))return ['A third-party signature source update or scheduling operation needs review. This is separate from the official ClamAV database freshness.','Review the provider status and next eligible attempt. Respect the configured cooldown; inspect protected local logs as an administrator.'];
            if(has('signature')&& !has('malware'))return ['A signature freshness or update operation needs attention. A responsive antivirus engine does not necessarily mean its databases are current.','Compare the engine-reported database version, update outcome and provider schedules in Maintenance.'];
            if(has('engine unavailable')||has('engine scan incomplete'))return ['The scanner could not obtain a verified antivirus verdict. The affected file or interval is not confirmed clean.','Check ClamD connectivity and readiness, then verify that pending scans recover.'];
            if(has('coverage')||has('scan incomplete')||has('scan error')||has('scan limited')||has('protected path')||has('queue overflow')||has('journal')||has('traversal'))return ['Some monitoring or file verification could not be completed. This is a coverage gap, not a malware detection.','Inspect the exact path, scan error and watcher/journal state. Verify that pending work or a reconciliation scan completes; investigate persistent gaps.'];
            return ['Endpoint Protection recorded a security or operational finding. The recorded title and evidence identify the specific condition; no additional cause has been established.','Review Endpoint Protection evidence and any related response or coverage records.'];
        }
        if(category==='network'){
            if(has('latency'))return ['The measured round-trip time exceeded the configured threshold. This does not identify which network segment caused the delay.','Review the target, threshold and recent network measurements.'];
            if(has('packet loss')||has('timeout')||has('probe failing'))return ['One or more monitoring probes did not receive an expected reply, or a configured loss/failure threshold was exceeded. A blocked or rate-limited ICMP response is also possible.','Check the recorded target and probe status, then verify reachability and firewall policy independently.'];
            return ['A network monitoring rule reported a condition.','Review the target and recorded measurement in the Network dashboard.'];
        }
        if(['cpu','ram','disk_usage'].includes(category))return [has('unavailable')?'A resource measurement could not be collected. The actual usage is not established.':'Measured resource usage reached or exceeded its configured alert threshold. This does not identify the process or workload responsible.','Review current utilization, the recorded threshold and resource history in System health.'];
        if(category==='smart')return ['Disk health telemetry reported a condition that needs review. The evidence is limited to the attributes and findings the collector recorded.','Review SMART/NVMe details and confirm backups; investigate any replacement recommendation.'];
        if(category==='events'||category==='event_details')return ['The collector reported a Windows Event Log condition. A grouped alert may contain only a count and the latest provider/event ID, not every event message.','Open Windows event details and filter by channel, provider, event ID and time.'];
        if(category==='data_integrity')return ['A file-integrity comparison or baseline verification reported a difference or an operational error. Not every file change is malicious.','Compare recorded expected and actual hashes and verify the authorized change history.'];
        if(category==='firewall'||category==='antivirus'||category==='security')return ['A Windows security control or protection provider reported a state that needs review. This is a posture finding, not a malware verdict.','Review the recorded control or provider and confirm the intended Windows security policy.'];
        return ['A monitoring rule recorded this condition. The available record does not establish a more specific cause.','Use the evidence below and the related dashboard to investigate.'];
    }
    let alertDialog=null;
    function openAlert(a,trigger){
        if(!a)return;
        if(!alertDialog){
            alertDialog=el('dialog');alertDialog.id='ls-alert-detail';alertDialog.className='ls-alert-dialog';alertDialog.setAttribute('aria-labelledby','ls-alert-detail-title');document.body.append(alertDialog);
            alertDialog.addEventListener('click',e=>{if(e.target===alertDialog){const r=alertDialog.getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)alertDialog.close();}});
            alertDialog.addEventListener('close',()=>{if(alertDialog.returnFocus?.isConnected)alertDialog.returnFocus.focus();});
        }
        const title=el('h2',a.title||'Alert details');title.id='ls-alert-detail-title';
        const header=el('div');header.className='ls-alert-dialog-header';const titleWrap=el('div');const kicker=el('small','LINKSCOPE · ALERT INVESTIGATION');titleWrap.append(kicker,title);
        const close=el('button','×');close.type='button';close.className='ls-alert-close';close.setAttribute('aria-label','Close alert details');close.onclick=()=>alertDialog.close();header.append(titleWrap,close);
        const badges=el('div');badges.className='ls-alert-badges';const severity=String(a.severity||'unknown').toLowerCase();const badge=el('span',severity);badge.className='ls-alert-severity '+(['critical','error','warning','info'].includes(severity)?severity:'unknown');badges.append(badge,el('span',a.resolved===true?'Resolved':a.resolved===false?'Active':'Status not recorded'));
        const meta=el('dl');meta.className='ls-alert-meta';const time=v=>v&&Number.isFinite(Date.parse(v))?new Date(v).toLocaleString():'Not recorded';
        for(const [key,value] of [['Category',a.category||'Not recorded'],['First recorded',time(a.sinceUtc)],['Resolved',a.resolved===true?time(a.resolvedUtc):'—'],['Alert ID',a.id||'Not recorded'],['Read status',a.read===true?'Read':a.read===false?'Unread':'Not recorded']]){meta.append(el('dt',key),el('dd',value));}
        const [meaning,action]=explainAlert(a);const detail=el('div');detail.className='ls-alert-evidence';detail.append(el('h3','Recorded evidence'),el('p','Original stored alert message. Historical evidence may not reflect the current state.'),el('pre',a.message||'No detailed evidence was stored for this record.'));
        const actions=el('div');actions.className='ls-alert-dialog-actions';const link=el('a','Open related dashboard');const cat=String(a.category||'');link.href=cat==='network'?'/':cat==='endpoint_protection'?'/endpoint#endpoint-alert-diagnostics':cat==='data_integrity'?'/integrity':'/system#category-'+encodeURIComponent(cat);actions.append(link);
        const done=el('button','Close');done.type='button';done.onclick=()=>alertDialog.close();actions.append(done);
        alertDialog.replaceChildren(header,badges,meta,el('h3','What this means'),el('p',meaning),detail,el('h3','Recommended investigation'),el('p',action),actions);
        alertDialog.returnFocus=trigger||document.activeElement;if(!alertDialog.open)alertDialog.showModal();close.focus();
    }
    function attachAlertRow(node,a,cell){
        if(!node||!cell)return;
        const button=el('button','View details');button.type='button';button.className='ls-alert-detail-button';button.setAttribute('aria-label','View alert details: '+(a.title||'Alert'));
        button.addEventListener('click',e=>{e.stopPropagation();openAlert(a,button);});cell.append(button);node.classList.add('ls-alert-clickable');
        node.addEventListener('click',e=>{if(e.target.closest('button,a,input,select,textarea,label')||window.getSelection()?.toString())return;openAlert(a,button);});
    }
    window.LinkScopeToast={openAlert,attachAlertRow,message:(level,title,text)=>show('ui:'+title,level,title,text),brand,categoryRead:(category,cutoff)=>{applyCategoryRead(category,cutoff);keep(localStorage,readSignal,{category,through:cutoff,at:Date.now()});poll();}};
    if(document.body.dataset.page==='login')return;
    guestReads=stored(localStorage,'linkscope.read-alerts.v1',[]);guestSeen=stored(sessionStorage,'ls-guest-seen',[]);
    // The authenticated response already contains all controls and initial unread count.
    const tools=document.querySelector('.ls-tools'),bell=id('ls-bell'),badge=id('ls-unread-badge');
    const account=tools.querySelector('.ls-account'),summary=account.querySelector('summary');
    const who=id('ls-account-identity'),login=id('ls-account-login'),my=id('ls-account-my'),users=id('ls-account-users'),logoff=id('ls-account-logout');
    const settings=account.querySelector('a[href="/settings"]'),report=id('global-export');
    for(const link of account.querySelectorAll('a'))link.addEventListener('click',()=>{account.open=false;});
    document.addEventListener('pointerdown',e=>{if(!account.contains(e.target))account.open=false;});
    account.onkeydown=e=>{if(e.key==='Escape'){account.open=false;summary.focus();}};
    function badgeCount(n){unreadCount=Math.max(0,Number(n)||0);badge.hidden=unreadCount===0;badge.textContent=unreadCount>99?'99+':String(unreadCount);bell.title=unreadCount+' unread monitoring alerts';bell.setAttribute('aria-label','Alert history, '+unreadCount+' unread');}
    // Preserve the server-rendered count until the first live feed arrives.
    // Account security reminders are UI notifications, not monitoring incidents.
    // Use the authenticated server state, never infer enrollment from the username or role.
    // Keep the deadline across navigation and refresh; separate it for each account.
    const mfaReminderPeriod=5*60*1000, mfaReminderPrefix='linkscope.mfa-reminder.v1:';
    const mfaReminderFallback=new Map();let mfaReminderUser='';
    function maybeRemindMfa(s){
        const username=s.authenticated===true&&typeof s.username==='string'?s.username:'';
        if(username!==mfaReminderUser){dismiss('mfa-reminder');mfaReminderUser=username;}
        if(!username)return;
        const key=mfaReminderPrefix+username;
        if(s.mfaEnabled===true){
            mfaReminderFallback.delete(key);try{localStorage.removeItem(key);}catch{}
            dismiss('mfa-reminder');return;
        }
        if(s.mfaEnabled!==false||document.hidden)return;
        const now=Date.now();let due=stored(localStorage,key,mfaReminderFallback.get(key)??null);
        function schedule(){due=now+mfaReminderPeriod;mfaReminderFallback.set(key,due);keep(localStorage,key,due);}
        // A first visit starts the interval; a backwards clock change cannot suppress reminders indefinitely.
        if(!Number.isFinite(due)||due<=0||due>now+mfaReminderPeriod){schedule();return;}
        if(now<due)return;
        schedule();
        show('mfa-reminder','warning','Protect your account','Multi-factor authentication (MFA) is not enabled. Set it up using Google Authenticator or another compatible app.',null,{label:'Set up MFA',href:'/account'});
    }
    function session(s){admin=s.admin===true;authenticated=s.authenticated===true||admin;csrf=s.csrf||'';login.hidden=authenticated;logoff.hidden=!authenticated;my.hidden=!authenticated;users.hidden=!admin;settings.hidden=!admin;report.hidden=!authenticated;who.hidden=!authenticated;who.textContent=authenticated?(s.username||'admin')+' · '+(s.role||(admin?'Admin':'Viewer')):'';for(const link of document.querySelectorAll('#ls-main-nav a[href="/audit"],#ls-main-nav a[href="/ai"]'))link.hidden=!admin;brand(s.brandLabel);maybeRemindMfa(s);}
    logoff.onclick=async()=>{try{await LinkScopeBusy.run('Signing out…',()=>json('/auth/logout',{}));keep(sessionStorage,'ls-notice-cursor',null);location.assign('/login');}catch(e){feedback(e);}};
    function markRow(key){const row=entries.get(key);if(row){row.state.textContent='Read';row.button.remove();row.node.classList.remove('unread');}}
    async function ack(a){
        if(admin){await LinkScopeBusy.run('Marking alert as read…',()=>json('/ui/alerts/read',{id:a.id}));markRow(a.id);if(onHistory)await history(historyPage,false);}
        else if(!authenticated&&!guestReads.includes(a.id)){guestReads.push(a.id);rememberGuest();}
        dismiss(a.id);keep(localStorage,readSignal,{id:a.id,at:Date.now()});poll();
    }
    function addRow(a){
        const node=el('tr');node.className=a.read?'':'unread';node.dataset.seq=a.sequence;
        const time=el('time',new Date(a.sinceUtc).toLocaleString());time.dateTime=a.sinceUtc;node.insertCell().append(time);
        const description=node.insertCell();description.append(el('strong',a.title),el('p',a.message));attachAlertRow(node,a,description);
        node.insertCell().textContent=a.category;node.insertCell().textContent=a.severity;
        const lifecycle=node.insertCell();lifecycle.textContent=a.resolved?'Resolved':'Active';
        if(a.resolvedUtc)lifecycle.append(el('small',new Date(a.resolvedUtc).toLocaleString()));
        const state=el('span',a.read?'Read':'Unread'),cell=node.insertCell();cell.append(state);
        const button=el('button','Mark as read');button.type='button';
        button.onclick=async()=>{button.disabled=true;try{await ack(a);}catch(e){feedback(e);}finally{button.disabled=false;}};
        if(!a.read&&admin)cell.append(button);entries.set(a.id,{node,button,state});id('history-list').append(node);
    }
    let pager,applied=new URLSearchParams(),totalRows=0,totalPages=1;
    function searchFilters(){
        const q=new URLSearchParams();
        for(const [field,k] of [['alert-query','q'],['alert-category','category'],['alert-severity','severity'],['alert-state','state'],['alert-read','read']]){
            const value=id(field).value.trim();if(value)q.set(k,value);
        }
        const from=id('alert-from').value,end=id('alert-until').value;
        if(from&&end&&from>end)throw Error('The end date must be on or after the start date.');
        for(const [value,k,add] of [[from,'from',0],[end,'until',1]]){
            if(value){const [year,month,day]=value.split('-').map(Number);q.set(k,String(new Date(year,month-1,day+add).getTime()/1000));}
        }
        return q;
    }
    async function history(page,fresh,criteria=applied,requestedSize=historySize){
        const tag=++historyVersion;
        const query=new URLSearchParams(criteria);
        query.set('page',String(page));query.set('size',String(requestedSize));
        if(!fresh&&through!=null)query.set('through',String(through));
        pager.update(historyPage,totalPages,totalRows,historySize,true);id('history-status').textContent='Searching…';
        const done=LinkScopeBusy.begin('Loading alert history…','alert-history');
        try{
            const p=await json('/ui/alerts/search?'+query);
            if(tag!==historyVersion)return;
            applied=criteria;through=p.through;historyPage=p.page;historySize=p.size;totalPages=p.pages;totalRows=p.total;
            entries.clear();id('history-list').replaceChildren();p.alerts.forEach(addRow);
            const cat=id('alert-category'),selected=cat.value;
            const cats=[...new Set([...p.categories,...(selected?[selected]:[])])].sort();
            cat.replaceChildren(new Option('All categories',''),...cats.map(x=>new Option(x,x)));cat.value=selected;
            badgeCount(p.unread);id('history-count').textContent=p.unread+' unread across all alerts';
            id('read-all').disabled=!admin||p.unread===0||through===0;
            id('history-status').textContent=totalRows?'':(applied.toString()?'No alerts match this search.':'No alerts recorded yet.');
        }catch(e){if(tag===historyVersion)feedback(e);}
        finally{done();if(tag===historyVersion)pager.update(historyPage,totalPages,totalRows,historySize);}
    }
    if(onHistory){
        pager=LinkScopePages.controls('Alert history',(p,size)=>history(p,false,applied,size));
        id('history-pager').append(pager.root);
        id('history-search').onsubmit=e=>{e.preventDefault();try{history(1,true,searchFilters());}catch(ex){feedback(ex);}};
        id('clear-search').onclick=()=>{id('history-search').reset();history(1,true,new URLSearchParams());};
        id('refresh-history').onclick=()=>history(1,true);
        id('read-all').onclick=async()=>{const btn=id('read-all');btn.disabled=true;const cutoff=through;
            try{await LinkScopeBusy.run('Marking alerts as read…',()=>json('/ui/alerts/read-all',{through:cutoff}));
                for(const [key,item] of toasts)if(item.alertSequence<=cutoff)dismiss(key);
                await history(historyPage,false);keep(localStorage,readSignal,{through:cutoff,at:Date.now()});poll();
            }catch(e){btn.disabled=false;feedback(e);}};
    }
    function processFeed(s){
        session(s);const f=s.feed;
        if(authenticated){
            for(const a of f.alerts){
                if(a.read||Number(a.sequence)<=(categoryReadThrough.get(a.category)||0))continue;
                show(a.id,a.severity,(a.resolved?'Resolved · ':'')+a.title,a.message,a);
            }
            if(f.unread===0)for(const [key,item] of toasts)if(item.alertSequence!=null)dismiss(key);
            cursor=f.cursor;keep(sessionStorage,'ls-notice-cursor',cursor);badgeCount(f.unread);
            if(onHistory){id('history-count').textContent=f.unread+' unread across all alerts';id('read-all').disabled=!admin||f.unread===0||!through;
                if(through!=null&&f.cursor>through)id('history-status').textContent='New alerts are available. Select Refresh to see them.';}
        }else{
            const unread=f.alerts.filter(a=>!guestReads.includes(a.id));badgeCount(unread.length);
            for(const a of unread)if(!guestSeen.includes(a.id)){guestSeen.push(a.id);show(a.id,a.severity,a.title,a.message,a);}
            rememberGuest();
        }
        return f.more;
    }
    async function poll(){
        if(pending){again=true;return;}
        pending=true;clearTimeout(nextPoll);let more=false;
        try{more=processFeed(await json('/ui/alerts'+(authenticated&&cursor!=null?'?after='+cursor:'')));dismiss('connection');}
        catch(e){if(!document.hidden)show('connection','warning','Notification connection unavailable',e.message);}
        finally{pending=false;nextPoll=setTimeout(poll,more||again?0:5000);again=false;}
    }
    window.addEventListener('storage',e=>{if(e.key===readSignal){try{const change=JSON.parse(e.newValue);if(change?.id)dismiss(change.id);if(change?.through!=null){if(change.category)applyCategoryRead(change.category,change.through);else for(const [key,item] of toasts)if(item.alertSequence!=null&&item.alertSequence<=change.through)dismiss(key);}}catch{}if(!authenticated)guestReads=stored(localStorage,'linkscope.read-alerts.v1',[]);poll();}});
    document.addEventListener('visibilitychange',()=>{if(!document.hidden)poll();});
    (async()=>{try{session(await json('/ui/session'));cursor=authenticated?stored(sessionStorage,'ls-notice-cursor',null):null;
        if(onHistory)await history(1,true);
    }catch(e){feedback(e);}poll();})();
})();
