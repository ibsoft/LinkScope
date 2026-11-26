// Monitoring notices and the account controls are shared by all dashboard pages.
(() => {
    'use strict';
    const el=(tag,text)=>{const n=document.createElement(tag);if(text!=null)n.textContent=text;return n;};
    const id=k=>document.getElementById(k), toasts=new Map(), entries=new Map();
    const onHistory=document.body.dataset.page==='alerts';
    let csrf='',admin=false,pending=false,again=false,nextPoll,through=null,historyVersion=0,historyPage=1,historySize=25;
    let cursor=null,guestReads=[],guestSeen=[],unreadCount=0;
    const readSignal='linkscope.alert-read-change';
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
    function show(key,severity,title,message,alert){
        if(toasts.has(key))return;
        const node=el('article');node.className='ls-toast ls-'+severity;
        const body=el('div');body.setAttribute('role',severity==='critical'||severity==='error'?'alert':'status');body.append(el('strong',title),el('p',message));node.append(body);
        const actions=el('div');actions.className='ls-toast-actions';
        if(alert){
            const button=el('button','Mark as read');button.type='button';button.onclick=async()=>{button.disabled=true;try{await ack(alert);}catch(ex){dismiss(key);feedback(ex);}finally{button.disabled=false;}};
            const link=el('a','View details');link.href=alert.category==='network'?'/':alert.category==='data_integrity'?'/integrity':'/system#category-'+encodeURIComponent(alert.category);
            link.onclick=async e=>{e.preventDefault();try{await ack(alert);location.assign(link.href);}catch(ex){dismiss(key);feedback(ex);}};
            actions.append(button,link);
        }
        const close=el('button',alert?'Close without marking read':'Dismiss');close.type='button';close.onclick=()=>dismiss(key);actions.append(close);node.append(actions);
        const item={node,alertSequence:alert?.sequence,timer:null};toasts.set(key,item);region.prepend(node);
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
        b.textContent=name;
    }
    window.LinkScopeToast={message:(level,title,text)=>show('ui:'+title,level,title,text),brand};
    if(document.body.dataset.page==='login')return;
    guestReads=stored(localStorage,'linkscope.read-alerts.v1',[]);guestSeen=stored(sessionStorage,'ls-guest-seen',[]);
    const icons={bell:'<path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9ZM10 20a2 2 0 0 0 4 0"/>',user:'<circle cx="12" cy="8" r="3.5"/><path d="M4 21v-2a8 8 0 0 1 16 0v2"/>'};
    function icon(kind){const n=el('span');n.setAttribute('aria-hidden','true');n.innerHTML='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">'+icons[kind]+'</svg>';return n;}
    const tools=el('div');tools.className='ls-tools';
    const bell=el('a');bell.href='/alerts';bell.className='ls-icon';bell.title='Alert history';const badge=el('span');badge.className='ls-badge';badge.hidden=true;bell.append(icon('bell'),badge);
    const account=el('details');account.className='ls-account';const summary=el('summary');summary.className='ls-icon';summary.setAttribute('aria-label','User account');summary.title='User account';summary.append(icon('user'));
    const menu=el('div');menu.className='ls-account-menu';const login=el('a','Sign in');login.href='/login';const logoff=el('button','Log off');logoff.type='button';logoff.hidden=true;menu.append(login,logoff);account.append(summary,menu);
    tools.append(bell,account);document.querySelector('header > div').append(tools);
    document.addEventListener('pointerdown',e=>{if(!account.contains(e.target))account.open=false;});
    account.onkeydown=e=>{if(e.key==='Escape'){account.open=false;summary.focus();}};
    function badgeCount(n){unreadCount=Math.max(0,Number(n)||0);badge.hidden=unreadCount===0;badge.textContent=unreadCount>99?'99+':String(unreadCount);bell.title=unreadCount+' unread monitoring alerts';bell.setAttribute('aria-label','Alert history, '+unreadCount+' unread');}
    badgeCount(0);
    function session(s){admin=s.admin;csrf=s.csrf||'';login.hidden=admin;logoff.hidden=!admin;brand(s.brandLabel);}
    logoff.onclick=async()=>{try{await LinkScopeBusy.run('Signing out…',()=>json('/auth/logout',{}));keep(sessionStorage,'ls-notice-cursor',null);location.assign('/login');}catch(e){feedback(e);}};
    function markRow(key){const row=entries.get(key);if(row){row.state.textContent='Read';row.button.remove();row.node.classList.remove('unread');}}
    async function ack(a){
        if(admin){await LinkScopeBusy.run('Marking alert as read…',()=>json('/ui/alerts/read',{id:a.id}));markRow(a.id);if(onHistory)await history(historyPage,false);}
        else if(!guestReads.includes(a.id)){guestReads.push(a.id);rememberGuest();}
        dismiss(a.id);keep(localStorage,readSignal,{id:a.id,at:Date.now()});poll();
    }
    function addRow(a){
        const node=el('tr');node.className=a.read?'':'unread';node.dataset.seq=a.sequence;
        const time=el('time',new Date(a.sinceUtc).toLocaleString());time.dateTime=a.sinceUtc;node.insertCell().append(time);
        node.insertCell().append(el('strong',a.title),el('p',a.message));
        node.insertCell().textContent=a.category;node.insertCell().textContent=a.severity;
        const lifecycle=node.insertCell();lifecycle.textContent=a.resolved?'Resolved':'Active';
        if(a.resolvedUtc)lifecycle.append(el('small',new Date(a.resolvedUtc).toLocaleString()));
        const state=el('span',a.read?'Read':'Unread'),cell=node.insertCell();cell.append(state);
        const button=el('button','Mark as read');button.type='button';
        button.onclick=async()=>{button.disabled=true;try{await ack(a);}catch(e){feedback(e);}finally{button.disabled=false;}};
        if(!a.read)cell.append(button);entries.set(a.id,{node,button,state});id('history-list').append(node);
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
            id('read-all').disabled=p.unread===0||through===0;
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
        if(admin){
            for(const a of f.alerts){
                if(a.read)continue;
                show(a.id,a.severity,(a.resolved?'Resolved · ':'')+a.title,a.message,a);
            }
            if(f.unread===0)for(const [key,item] of toasts)if(item.alertSequence!=null)dismiss(key);
            cursor=f.cursor;keep(sessionStorage,'ls-notice-cursor',cursor);badgeCount(f.unread);
            if(onHistory){id('history-count').textContent=f.unread+' unread across all alerts';id('read-all').disabled=f.unread===0||!through;
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
        try{more=processFeed(await json('/ui/alerts'+(admin&&cursor!=null?'?after='+cursor:'')));dismiss('connection');}
        catch(e){if(!document.hidden)show('connection','warning','Notification connection unavailable',e.message);}
        finally{pending=false;nextPoll=setTimeout(poll,more||again?0:5000);again=false;}
    }
    window.addEventListener('storage',e=>{if(e.key===readSignal){try{const change=JSON.parse(e.newValue);if(change?.id)dismiss(change.id);if(change?.through!=null)for(const [key,item] of toasts)if(item.alertSequence!=null&&item.alertSequence<=change.through)dismiss(key);}catch{}if(!admin)guestReads=stored(localStorage,'linkscope.read-alerts.v1',[]);poll();}});
    document.addEventListener('visibilitychange',()=>{if(!document.hidden)poll();});
    (async()=>{try{session(await json('/ui/session'));cursor=admin?stored(sessionStorage,'ls-notice-cursor',null):null;
        if(onHistory)await history(1,true);
    }catch(e){feedback(e);}poll();})();
})();
