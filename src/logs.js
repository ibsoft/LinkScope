'use strict';
(()=>{
    const id=k=>document.getElementById(k);
    let filters=new URLSearchParams(),page=1,size=25,pages=1,total=0,through=null,version=0;
    const pager=LinkScopePages.controls('Application logs',(p,s)=>load(p,s,filters,false));
    id('log-pager').append(pager.root);
    function read(){
        const q=new URLSearchParams();
        for(const k of ['q','level','module','operation','status','peer','from','until']){
            const v=id('log-'+k).value.trim();if(!v)continue;
            q.set(k,['from','until'].includes(k)?String(Math.floor(new Date(v).getTime()/1000)):v);
        }
        if(q.has('from')&&q.has('until')&&Number(q.get('until'))<=Number(q.get('from')))throw Error('Until must be later than From.');
        return q;
    }
    function row(item){
        const tr=document.createElement('tr');
        tr.insertCell().textContent=new Date(item.utc).toLocaleString();
        const badge=document.createElement('span');
        badge.className='log-badge log-'+({Debug:'debug',Info:'info',Warning:'warning',Error:'error'}[item.level]||'info');
        badge.textContent=item.level;tr.insertCell().append(badge);
        for(const value of [item.module,item.operation,item.message,item.peer||'—',item.status??'—',item.elapsedMs==null?'—':item.elapsedMs+' ms'])tr.insertCell().textContent=value;
        return tr;
    }
    async function load(p,s,criteria,fresh){
        const v=++version,q=new URLSearchParams(criteria);q.set('page',p);q.set('size',s);
        if(!fresh&&through!=null)q.set('through',through);
        pager.update(page,pages,total,size,true);id('log-feedback').textContent='Searching…';
        const done=LinkScopeBusy.begin('Loading application logs…','logs');
        try{
            const r=await fetch('/ui/logs/search?'+q,{credentials:'same-origin',cache:'no-store'});
            if(r.status===401){location.assign('/login#logs');return;}
            const d=await r.json();if(!r.ok)throw Error(d.error||'Log search failed.');
            if(v!==version)return;
            page=d.page;size=d.size;total=d.total;pages=d.pages;through=d.through;filters=criteria;
            id('log-list').replaceChildren(...d.items.map(row));
            const mod=id('log-module'),selected=mod.value;
            mod.replaceChildren(new Option('All modules',''),...[...new Set([...d.modules,...(selected?[selected]:[])])].sort().map(x=>new Option(x,x)));
            mod.value=selected;id('log-feedback').textContent=total?'':criteria.toString()?'No log entries match these filters.':'No application logs recorded yet.';
        }catch(err){if(v===version)id('log-feedback').textContent=err.message;}
        finally{done();if(v===version)pager.update(page,pages,total,size);}
    }
    id('log-form').onsubmit=e=>{e.preventDefault();try{load(1,size,read(),true);}catch(err){id('log-feedback').textContent=err.message;}};
    id('log-clear').onclick=()=>{id('log-form').reset();load(1,size,new URLSearchParams(),true);};
    id('log-refresh').onclick=()=>load(1,size,filters,true);
    load(1,size,filters,true);
})();
