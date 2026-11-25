'use strict';
window.LinkScopePages=(()=>{
    const sizes=[10,25,50,100],positions=new Map(),attached=new WeakMap();
    function element(tag,text){const e=document.createElement(tag);if(text!=null)e.textContent=text;return e;}
    function controls(name,change){
        const root=element('div');root.className='ls-pager';root.setAttribute('role','group');root.setAttribute('aria-label',name+' pagination');
        const count=element('span');count.className='ls-page-count';count.setAttribute('role','status');
        const previous=element('button','Previous'),next=element('button','Next');previous.type=next.type='button';
        const pageLabel=element('label','Page '),jump=element('input');jump.type='number';jump.min=1;jump.step=1;jump.setAttribute('aria-label',name+' page');
        const of=element('span');pageLabel.append(jump,of);
        const sizeLabel=element('label','Rows '),select=element('select');select.setAttribute('aria-label',name+' rows per page');
        sizes.forEach(n=>select.append(new Option(String(n),String(n))));sizeLabel.append(select);root.append(count,sizeLabel,previous,pageLabel,next);
        let page=1,size=10,pages=1;
        previous.onclick=()=>change(page-1,size);next.onclick=()=>change(page+1,size);select.onchange=()=>change(1,Number(select.value));
        function go(){const n=Number(jump.value);if(Number.isInteger(n)&&n>=1&&n<=pages&&n!==page)change(n,size);else jump.value=page;}
        jump.onchange=go;jump.onkeydown=e=>{if(e.key==='Enter'){e.preventDefault();go();}};
        return {root,update(p,n,total,s,busy=false){
            page=p;pages=n;size=s;jump.value=page;jump.max=pages;select.value=String(size);
            of.textContent=' of '+pages;count.textContent=total?((page-1)*size+1)+'–'+Math.min(page*size,total)+' of '+total:'0 rows';
            previous.disabled=busy||page<=1;next.disabled=busy||page>=pages;jump.disabled=busy||pages===1;select.disabled=busy;
        }};
    }
    function attach(table,key,name,placeholder=false){
        let pager=attached.get(table);
        const state=positions.get(key)||{page:1,size:10};
        positions.set(key,state);
        function render(){
            const rows=[...table.tBodies[0].rows],total=placeholder?0:rows.length,pages=Math.max(1,Math.ceil(total/state.size));
            state.page=Math.max(1,Math.min(state.page,pages));
            rows.forEach((r,i)=>r.hidden=!placeholder&&(i<(state.page-1)*state.size||i>=state.page*state.size));
            pager.widget.update(state.page,pages,total,state.size);pager.widget.root.hidden=total===0;
        }
        function change(page,size){state.page=page;state.size=size;render();}
        if(!pager){
            const widget=controls(name,(p,s)=>pager.change(p,s));
            pager={widget};attached.set(table,pager);table.after(widget.root);
            // Native form validation can discover an invalid control on another page.
            table.addEventListener('invalid',e=>{
                const row=e.target.closest('tr');if(row&&!row.hidden)return;
                if(row&&pager.invalid!==true){
                    pager.invalid=true;pager.reveal(row.sectionRowIndex);
                    queueMicrotask(()=>{pager.invalid=false;});
                }
            },true);
        }
        pager.change=change;pager.reveal=i=>change(Math.floor(i/state.size)+1,state.size);
        render();
    }
    return {controls,attach};
})();
