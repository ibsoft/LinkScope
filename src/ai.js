'use strict';
(()=>{
    const id=k=>document.getElementById(k);
    let csrf='',enabled=false,phase='loading',clearing=false,version=0;
    let stage='AI Assist is thinking…';
    function renderActivity(){
        const thinking=['submitting','thinking','cancelling'].includes(phase);
        const label=phase==='submitting'?'Sending request…':phase==='cancelling'?'Cancelling request…':stage;
        const indicator=id('ai-thinking'), caption=id('ai-thinking-text');
        indicator.hidden=!thinking;
        if(caption.textContent!==(thinking?label:''))caption.textContent=thinking?label:'';
        id('thread').setAttribute('aria-busy',String(thinking));
        for(const key of ['send','verdict','question'])id(key).disabled=!enabled||phase!=='idle'||clearing;
        id('new-chat').disabled=clearing||phase==='loading'||phase==='submitting';
        id('cancel-chat').hidden=phase!=='thinking'&&phase!=='cancelling';
        id('cancel-chat').disabled=clearing||phase==='cancelling';
    }
    function finish(v,message){
        if(v!==version)return;
        phase='idle';
        renderActivity();
        id('ai-state').textContent=message;
    }
    async function call(path,body){
        const opt={cache:'no-store',credentials:'same-origin'};
        if(body!==undefined){opt.method='POST';opt.headers={'Content-Type':'application/json','X-CSRF-Token':csrf,'X-Request-Nonce':Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join('')};opt.body=JSON.stringify(body);}
        const res=await fetch(path,opt);
        if(!res.ok){
            const problem=await res.json().catch(()=>({}));
            if(res.status===401)location.assign('/login#ai');
            const error=Error(problem.error||'Request failed (HTTP '+res.status+').');
            error.status=res.status;
            throw error;
        }
        return res.json();
    }
    function formatted(text){
        const div=document.createElement('div');let code=null;
        for(const raw of text.split(/\r?\n/)){
            if(raw.trim().startsWith('```')){if(code){code=null;}else{code=document.createElement('pre');div.append(code);}continue;}
            if(code){code.textContent+=raw+'\n';continue;}
            const t=raw.trim();if(!t)continue;
            const p=document.createElement(/^#{1,4} /.test(t)?'h3':'p');
            const clean=t.replace(/^#{1,4} /,'').replace(/^[-*] /,'• ');
            for(const part of clean.split(/(\*\*[^*]+\*\*|`[^`]+`)/g)){
                if(part.startsWith('**')&&part.endsWith('**')){const b=document.createElement('strong');b.textContent=part.slice(2,-2);p.append(b);}
                else if(part.startsWith('`')&&part.endsWith('`')){const b=document.createElement('code');b.textContent=part.slice(1,-1);p.append(b);}
                else p.append(document.createTextNode(part));
            }
            div.append(p);
        }
        return div;
    }
    function line(who,text){const row=document.createElement('article');row.className='bubble '+(who==='Technician'?'technician':'assistant');
        const title=document.createElement('strong'),p=document.createElement('p');title.textContent=who;p.textContent=text;row.append(title,who==='Technician'?p:formatted(text));id('thread').append(row);row.scrollIntoView({block:'nearest'});}
    async function poll(v,restore=false,firstResult=null){
        let retries=0;
        while(v===version){
            let r;
            try{
                r=firstResult||await call('/ui/ai/result');
                firstResult=null;
                retries=0;
            }catch(e){
                if(v!==version)return;
                if(e.status>=400&&e.status<500&&e.status!==408&&e.status!==429)throw e;
                ++retries;
                stage='Reconnecting to AI Assist…';
                renderActivity();
                await new Promise(done=>setTimeout(done,Math.min(retries,10)*1500));
                continue;
            }
            if(v!==version)return;
            if(r.coverage){const c=r.coverage;id('source-detail').hidden=!c.sources?.length;id('source-list').replaceChildren(...(c.sources||[]).map(s=>{const li=document.createElement('li');li.textContent=s;return li;}));id('coverage').textContent=c.categories+' health categories · '+c.targets+' targets · '+new Date(c.utc).toLocaleString()+(c.unavailable.length?' · Unavailable: '+c.unavailable.join(', '):'');}
            if(!r.busy){
                if(restore&&r.turns){for(const t of r.turns){line('Technician',t.question);line('AI Assist',t.answer);}}
                else if(r.answer)line('AI Assist',r.answer);
                finish(v,r.error||(r.answer?'Response complete.':''));
                return;
            }
            if(phase!=='cancelling')phase='thinking';
            stage=(r.stage||'AI Assist is thinking')+'…';
            renderActivity();
            await new Promise(done=>setTimeout(done,900));
        }
    }
    async function send(verdict){
        if(phase!=='idle'||clearing||!enabled)return;
        const question=id('question').value.trim();
        if(!verdict&&!question)return;
        const v=++version;
        phase='submitting';
        id('ai-state').textContent='';
        renderActivity();
        try{
            await call('/ui/ai/ask',{verdict,question:verdict?'':question});
            if(v!==version)return;
            line('Technician',verdict?'Generate a system verdict.':question);
            id('question').value='';
            phase='thinking';
            stage='AI Assist is thinking…';
            renderActivity();
            await poll(v);
        }catch(e){finish(v,e.message);}
    }
    async function reset(){
        if(clearing||phase==='loading'||phase==='submitting')return;
        clearing=true;
        renderActivity();
        try{
            await LinkScopeBusy.run('Clearing chat…',()=>call('/ui/ai/clear',{}));
            ++version;
            for(const n of id('thread').querySelectorAll('.bubble'))n.remove();
            id('coverage').textContent='';
            id('source-detail').hidden=true;
            id('source-list').replaceChildren();
            id('question').value='';
            finish(version,'Conversation cleared.');
        }catch(e){id('ai-state').textContent=e.message;}
        finally{clearing=false;renderActivity();}
    }
    async function cancel(){
        if(phase!=='thinking'||clearing)return;
        const v=version;
        phase='cancelling';
        renderActivity();
        try{await call('/ui/ai/cancel',{});}
        catch(e){
            if(v!==version||phase!=='cancelling')return;
            phase='thinking';
            renderActivity();
            id('ai-state').textContent=e.message;
        }
    }
    async function openChat(){
        const v=++version;
        try{
            const result=await LinkScopeBusy.run('Loading AI Assist…',async()=>{
                const session=await call('/ui/session');
                csrf=session.csrf;
                const c=await call('/ui/ai');
                enabled=c.enabled;
                id('ai-connection').textContent=enabled?c.provider+' · '+c.model+' · '+c.host:'Disabled. Configure a provider in Settings.';
                return enabled?call('/ui/ai/result'):null;
            });
            if(result)await poll(v,true,result);
            else finish(v,'');
        }catch(e){finish(v,e.message);}
    }
    id('ask').onsubmit=e=>{e.preventDefault();return send(false);};
    id('verdict').onclick=()=>send(true);
    id('new-chat').onclick=reset;
    id('cancel-chat').onclick=cancel;
    id('question').onkeydown=e=>{if((e.ctrlKey||e.metaKey)&&e.key==='Enter'){e.preventDefault();send(false);}};
    renderActivity();
    openChat();
})();
