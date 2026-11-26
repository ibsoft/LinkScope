'use strict';
const fmt=(x,n=1)=>x==null?'—':Number(x).toLocaleString(undefined,{maximumFractionDigits:n}), local=t=>new Date(t*1000).toLocaleString();
const ranges={day:'24 hours',week:'7 days',month:'30 days',year:'365 days'};
const colours={avg:'#007d76',loss:'#b85025',tx:'#5368a4',band:'#b6c9d6'};
function summarizeMetrics(points){
 let ok=0,lost=0,to=0,err=0,sum=0,lo=null,hi=null;
 for(const p of points){ok+=p[1];lost+=p[2];to+=p[3];err+=p[4];sum+=p[5];if(p[6]!=null){lo=lo==null?p[6]:Math.min(lo,p[6]);hi=hi==null?p[7]:Math.max(hi,p[7]);}}
 const sent=ok+lost;
 return {ok,lost,to,err,sum,lo,hi,sent};
}
function drawChart(id,d,c,w,h,dpi,tickLabel,tip){
 if(w<1)return;c.width=Math.round(w*dpi);c.height=Math.round(h*dpi);
 const g=c.getContext('2d');g.scale(dpi,dpi);
 if(tip){tip.hidden=true;c.onpointermove=null;c.onkeydown=null;}
 if(!d)return;
 const left=42,right=w-14,top=10,bottom=h-23,width=right-left;
 const resource=id==='resource',rate=id==='traffic',loss=id==='packet',rows=rate?d.rates:d.points,by=new Map(rows.map(p=>[p[0],p])),count=(d.end-d.start)/d.step;
 const val=(r,k)=>!r?null:resource?r[2]:rate?r[k]:loss?(r[1]+r[2]?r[2]*100/(r[1]+r[2]):null):(r[1]?r[5]/r[1]:null);
 let max=0;for(const p of rows)max=Math.max(max,resource?p[4]:rate?Math.max(p[1],p[2]):loss?(val(p,1)||0):(p[7]||0));
 const base=Math.pow(10,Math.floor(Math.log10(max||1)));const ceiling=resource?100:max?([1,2,5,10].find(n=>n*base>=max)||10)*base:1;
 const x=i=>left+(i+.5)*width/count,y=v=>bottom-v/ceiling*(bottom-top);
 const dark=document.documentElement.dataset.theme==='dark';
 g.font='11px "Segoe UI", Arial';g.fillStyle=dark?'#b9cdd8':'#536b74';g.lineWidth=1;
 for(let i=0;i<=4;i++){const yy=top+i*(bottom-top)/4;g.strokeStyle=dark?'#354956':'#e2e9e9';g.beginPath();g.moveTo(left,yy);g.lineTo(right,yy);g.stroke();g.textAlign='right';g.fillText(fmt(ceiling*(4-i)/4,ceiling<1?4:2),left-5,yy+4);}
 const labels=w<520?3:5;for(let j=0;j<labels;j++){let i=Math.round(j*(count-1)/(labels-1));g.textAlign=j===0?'left':j===labels-1?'right':'center';g.fillText(tickLabel(d.start+i*d.step),j===0?left:j===labels-1?right:x(i),h-4);}
 function each(fn){for(let i=0;i<count;i++)fn(i,by.get(d.start+i*d.step));}
 if(!rate&&!loss){g.strokeStyle=colours.band;g.lineWidth=Math.max(1,width/count*.7);g.beginPath();each((i,p)=>{if(p){const lo=p[resource?3:6],hi=p[resource?4:7];if(lo!=null){g.moveTo(x(i),y(lo));g.lineTo(x(i),y(hi));}}});g.stroke();}
 function series(k,color){g.strokeStyle=color;g.fillStyle=color;g.lineWidth=1.8;let prev=false;g.beginPath();
 each((i,p)=>{const v=val(p,k);if(v==null){prev=false;return;}if(prev)g.lineTo(x(i),y(v));else{g.moveTo(x(i),y(v));g.fillRect(x(i)-1.2,y(v)-1.2,2.4,2.4);}prev=true;});g.stroke();}
 if(loss){g.fillStyle=dark?'#fb923c':colours.loss;each((i,p)=>{const v=val(p,1);if(v!=null)g.fillRect(x(i)-width/count*.42,y(v)-1,Math.max(1,width/count*.84),Math.max(2,bottom-y(v)+1));});}
 else {series(1,dark?'#5eead4':colours.avg);if(rate)series(2,dark?'#a5b4fc':colours.tx);}
 if(!rows.some(p=>val(p,1)!=null)){
  const message=rows.length&&!resource&&!rate&&!loss?'No successful replies in this range':'No measurements in this range';
  const midX=(left+right)/2,midY=(top+bottom)/2,textWidth=g.measureText(message).width;
  g.fillStyle=dark?'#172733':'#ffffff';g.fillRect(midX-textWidth/2-6,midY-12,textWidth+12,16);
  g.fillStyle=dark?'#b9cdd8':'#536b74';g.textAlign='center';g.fillText(message,midX,midY);
 }
 if(!tip)return;
 let index=count-1;
 function inspect(i){index=Math.min(count-1,Math.max(0,i));const t=d.start+index*d.step,p=by.get(t);const v=val(p,1);
 let msg='No observations';if(p){if(resource)msg=fmt(v,1)+'% average · '+fmt(p[3],1)+'–'+fmt(p[4],1)+'% · '+fmt(p[1])+' samples';else if(rate)msg='Receive '+fmt(p[1],3)+' · Transmit '+fmt(p[2],3)+' Mbps';else if(loss)msg=fmt(v,3)+'% loss · '+fmt(p[3])+' timeouts · '+fmt(p[4])+' errors';else msg=p[1]?fmt(v,2)+' ms average · '+fmt(p[6])+'–'+fmt(p[7])+' ms':'No successful replies';}
 tip.textContent=local(t)+'\n'+msg;tip.hidden=false;tip.style.left=Math.max(2,Math.min(x(index)+8,w-tip.offsetWidth-2))+'px';}
 c.onpointermove=e=>inspect(Math.floor((e.clientX-c.getBoundingClientRect().left-left)*count/width));c.onpointerleave=()=>tip.hidden=true;c.onblur=()=>tip.hidden=true;
 c.onkeydown=e=>{if(e.key==='ArrowLeft'||e.key==='ArrowRight'){e.preventDefault();inspect(index+(e.key==='ArrowRight'?1:-1));}else if(e.key==='Escape')tip.hidden=true;};
}

if(document.body.dataset.page==='system'){
    (() => {
        const container=document.getElementById('trend-charts'),caption=document.getElementById('trend-caption');
        const buttons=[...document.querySelectorAll('#trend-periods button')],figures=new Map();
        const dialog=document.getElementById('resource-modal'),large=document.getElementById('expanded-canvas'),largeTip=document.getElementById('expanded-tip');
        let period='day',revision=0,snapshot,timer,selected=null,opener=null,historyError=false;
        const refreshDelay=()=>dialog.open?5000:60000;
        const tick=t=>{const d=new Date(t*1000);return period==='day'?d.toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit'}):d.toLocaleDateString(undefined,{day:'numeric',month:'short'});};
        function drawLarge(){
            if(!dialog.open||!snapshot||selected===null)return;
            const serie=snapshot.series.find(x=>x.metric===selected),rect=large.getBoundingClientRect();
            drawChart('resource',{...snapshot,points:serie?.points||[]},large,rect.width,rect.height,window.devicePixelRatio||1,tick,largeTip);
            const bucket=snapshot.step<3600?(snapshot.step/60)+' min':(snapshot.step/3600)+' h';
            document.getElementById('expanded-range').textContent=ranges[period]+' · '+local(snapshot.start)+' – '+local(Math.min(snapshot.end,snapshot.now))+' · '+bucket+' per interval · 0–100% · '+(historyError?'Update failed — last snapshot':'Live · refreshed '+new Date(snapshot.now*1000).toLocaleTimeString()+' · every 5 s');
        }
        function expand(name,trigger){
            if(!snapshot)return;selected=name;opener=trigger;document.getElementById('expanded-title').textContent=name+' usage (%)';
            dialog.showModal();drawLarge();load();
        }
        document.getElementById('expanded-close').onclick=()=>dialog.close();
        dialog.addEventListener('close',()=>{selected=null;largeTip.hidden=true;if(opener?.isConnected)opener.focus();opener=null;});
        dialog.addEventListener('click',e=>{if(e.target!==dialog)return;const r=dialog.getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)dialog.close();});
        function draw(){
            if(!snapshot)return;
            const values=new Map(snapshot.series.map(m=>[m.metric,m.points]));
            const names=[...new Set(['CPU','RAM',...values.keys()])];
            for(const [name,figure] of figures)if(!names.includes(name)){figure.remove();figures.delete(name);}
            for(const name of names){
                let figure=figures.get(name);
                if(!figure){
                    figure=document.createElement('figure');
                    const heading=document.createElement('figcaption');heading.textContent=name+' usage (%)';
                    const expandBtn=document.createElement('button');expandBtn.type='button';expandBtn.className='trend-expand';expandBtn.textContent='Expand';expandBtn.setAttribute('aria-label','Expand '+name+' usage chart');expandBtn.setAttribute('aria-haspopup','dialog');
                    expandBtn.onclick=()=>expand(name,expandBtn);heading.append(expandBtn);
                    const area=document.createElement('div');area.className='trend-plot';
                    const canvas=document.createElement('canvas');canvas.tabIndex=0;canvas.setAttribute('aria-label',name+' usage, 0 to 100 percent. Use left and right arrows to inspect samples.');
                    const tip=document.createElement('span');tip.className='trend-tip';tip.hidden=true;tip.setAttribute('role','status');
                    canvas.onclick=()=>expand(name,expandBtn);area.append(canvas,tip);figure.append(heading,area);container.append(figure);figures.set(name,figure);
                }
                const canvas=figure.querySelector('canvas'),rect=canvas.getBoundingClientRect();
                drawChart('resource',{...snapshot,points:values.get(name)||[]},canvas,rect.width,rect.height,window.devicePixelRatio||1,tick,canvas.nextElementSibling);
            }
            drawLarge();
        }
        async function load(foreground=false){
            const done=foreground?LinkScopeBusy.begin('Loading system health graphs…','resource-history'):null;
            clearTimeout(timer);const ticket=++revision;
            try{
                const r=await fetch('/ui/resource-history?range='+period,{cache:'no-store'});
                if(!r.ok)throw Error('HTTP '+r.status);
                const value=await r.json();if(ticket!==revision)return;
                snapshot=value;historyError=false;draw();
                caption.textContent=local(value.start)+' – '+local(Math.min(value.end,value.now))+' · '+(value.step<3600?value.step/60+' min':value.step/3600+' h')+' per interval. Dark line: average. Pale bars: minimum to maximum.';
            }catch(e){if(ticket===revision){historyError=true;caption.textContent='Resource history unavailable ('+e.message+'). Retrying automatically.';drawLarge();}}
            finally{done?.();if(ticket===revision)timer=setTimeout(load,refreshDelay());}
        }
        for(const b of buttons)b.onclick=()=>{if(b.dataset.period===period)return;period=b.dataset.period;
            buttons.forEach(x=>x.setAttribute('aria-pressed',String(x===b)));snapshot=null;figures.clear();container.replaceChildren();caption.textContent='Loading history…';load(true);};
        window.addEventListener('resize',draw);load(true);
    })();
}
