// PDF files are built in the browser. The service supplies the data and embedded scripts.
const LinkScopeReport = (() => {
    const periods = {day:'Day', week:'Week', month:'Month', year:'Year'};
    const navy='#153940', ink='#152f3b', muted='#486370', teal='#007d76', orange='#b85025';
    const paper='#f1f6f5', line='#cfdedc', blue='#5368a4', band='#a0b8c8';
    const pageWidth=595.28, pageHeight=841.89, margin=35, inside=pageWidth-2*margin;
    const number=(value, digits=0)=>value==null?'—':value.toLocaleString('en-GB',{maximumFractionDigits:digits});
    const iso=seconds=>new Date(seconds*1000).toISOString();
    const utc=(seconds, withSeconds=false)=>iso(seconds).slice(0,withSeconds?19:16).replace('T',' ');
    const clean=value=>String(value==null?'':value).replace(/[\u0000-\u001f\u007f]/g,' ').trim();
    let loading;

    function loadLibrary() {
        if(window.PDFLib)return Promise.resolve(window.PDFLib);
        if(!loading)loading=new Promise((resolve,reject)=>{
            const script=document.createElement('script');
            script.src='/assets/pdf-lib.js';
            script.onload=()=>{
                if(window.PDFLib)resolve(window.PDFLib);
                else {loading=null;script.remove();reject(Error('The PDF library could not initialize'));}
            };
            script.onerror=()=>{loading=null;script.remove();reject(Error('The PDF library could not load'));};
            document.head.append(script);
        });
        return loading;
    }

    async function build(sections, health, trends, history, manifest) {
        const lib=await loadLibrary();
        const doc=await lib.PDFDocument.create();
        const regular=await doc.embedFont(lib.StandardFonts.Helvetica);
        const bold=await doc.embedFont(lib.StandardFonts.HelveticaBold);
        const targets=sections[0].targets;
        doc.setTitle('LinkScope - Complete monitoring report');
        doc.setAuthor('LinkScope');doc.setCreator('LinkScope Network Monitor');
        doc.setSubject('All configured ping targets, system health and alert history');
        doc.setCreationDate(new Date(sections[0].now*1000));
        const color=hex=>lib.rgb(...[1,3,5].map(i=>parseInt(hex.slice(i,i+2),16)/255));
        const shortDate=new Intl.DateTimeFormat('en-GB',{day:'numeric',month:'short',timeZone:'UTC'});
        const cover=doc.addPage([pageWidth,pageHeight]);
        cover.drawRectangle({x:0,y:pageHeight-55,width:pageWidth,height:55,color:color(navy)});
        cover.drawText('LinkScope',{x:margin,y:pageHeight-35,size:20,font:bold,color:color('#ffffff')});
        cover.drawText('Complete monitoring report',{x:margin,y:pageHeight-135,size:27,font:bold,color:color(ink)});
        const contents=[
            'Generated '+utc(sections[0].now,true)+' UTC',
            targets.length+' configured network target'+(targets.length===1?'':'s')+'  /  Day, Week, Month and Year',
            'CPU, RAM and volume usage history',
            'Windows health, SMART, security posture, events, firewall and antivirus',
            history.length+' monitoring alert records',
            'The raw report data is attached as LinkScope-report.json.'
        ];
        contents.forEach((v,i)=>cover.drawText(v,{x:margin,y:pageHeight-185-i*32,size:11,font:regular,color:color(muted)}));
        for(const d of sections) {
            await new Promise(resolve=>setTimeout(resolve,0));
            const ip=d.target,target=targets.find(t=>t.Address===ip);
            if(!target)throw Error('A configured target is missing from the report');
            const page=doc.addPage([pageWidth,pageHeight]);
            function box(x,top,width,height,fill) {
                page.drawRectangle({x,y:pageHeight-top-height,width,height,color:color(fill)});
            }
            function text(value,x,top,size=10,font=regular,fill=ink) {
                page.drawText(String(value),{x,y:pageHeight-top-size,size,font,color:color(fill)});
            }
            function right(value,rightEdge,top,size=10,font=regular,fill=muted) {
                text(value,rightEdge-font.widthOfTextAtSize(value,size),top,size,font,fill);
            }
            function fitted(value,x,top,maxWidth,size,font=regular,fill=ink) {
                const minSize=7;
                while(size>minSize && font.widthOfTextAtSize(value,size)>maxWidth)size-=0.5;
                let display=value;
                while(display && font.widthOfTextAtSize(display,size)>maxWidth)display=display.slice(0,-1);
                if(display!==value)display=display.slice(0,-2)+'…';
                text(display,x,top,size,font,fill);
            }
            async function localText(value,x,top,maxWidth,size,font=regular,fill=ink) {
                value=clean(value);
                try {font.encodeText(value);fitted(value,x,top,maxWidth,size,font,fill);return;}
                catch(e) { /* The standard PDF fonts only cover WinAnsi. Use the browser's script fallback. */ }
                const canvas=document.createElement('canvas'), scale=4;
                canvas.width=Math.ceil(maxWidth*scale);canvas.height=Math.ceil(size*1.55*scale);
                const g=canvas.getContext('2d');g.scale(scale,scale);
                g.font=(font===bold?'600 ':'')+size+'px "Segoe UI", Arial, sans-serif';
                const chars=Array.from(value);
                while(chars.length && g.measureText(chars.join('')).width>maxWidth-g.measureText('…').width)chars.pop();
                const display=chars.length===Array.from(value).length?value:chars.join('')+'…';
                g.fillStyle=fill;g.textBaseline='alphabetic';g.fillText(display,0,size);
                const png=await doc.embedPng(canvas.toDataURL('image/png'));
                page.pushOperators(lib.PDFOperator.of('BDC',[lib.PDFName.of('Span'),
                    doc.context.obj({ActualText:lib.PDFHexString.fromText(value)})]));
                // A text run gives PDF readers a selectable anchor for the Unicode ActualText.
                page.drawText(' ',{x,y:pageHeight-top-size,size,font:regular,opacity:0});
                page.drawImage(png,{x,y:pageHeight-top-canvas.height/scale,width:canvas.width/scale,height:canvas.height/scale});
                page.pushOperators(lib.PDFOperator.of('EMC'));
            }
            function legend(entries,top) {
                let edge=pageWidth-margin;
                for(const [label,swatch] of entries.slice().reverse()) {
                    const width=regular.widthOfTextAtSize(label,9);
                    text(label,edge-width,top,9,regular,muted);
                    box(edge-width-16,top+4,11,2.5,swatch);
                    edge-=width+27;
                }
            }
            async function chart(kind,top,height) {
                const canvas=document.createElement('canvas');
                const w=700, h=height*w/inside;
                const tick=t=>d.range==='day'?iso(t).slice(11,16):shortDate.format(new Date(t*1000));
                drawChart(kind,d,canvas,w,h,1.7,tick,null);
                const image=await doc.embedPng(canvas.toDataURL('image/png'));
                page.drawImage(image,{x:margin,y:pageHeight-top-height,width:inside,height});
            }
            const summary=summarizeMetrics(d.points), {ok,lost,to,err,sum,lo,hi,sent}=summary;
            const observed=d.points.length>0;
            box(0,0,pageWidth,43,navy);
            box(margin,13,3,15,'#82d6bd');text('LinkScope',margin+10,10,16,bold,'#ffffff');
            right('Network monitoring report',pageWidth-margin,15,10,regular,'#e5f3ee');
            text(periods[d.range],margin,54,31,bold);
            right(ranges[d.range]+'  /  UTC',pageWidth-margin,70,11,bold,teal);
            await localText(target.Name,margin,99,inside,14,bold);
            text(ip,margin,121,10,regular,muted);
            text(utc(d.start)+'  to  '+utc(Math.min(d.end,d.now))+' UTC',margin,141,10);
            right('Probe interval  '+number(d.interval)+' s',pageWidth-margin,141,9);
            box(margin,166,inside,65,paper);
            const cards=[
                ['Average RTT',ok?number(sum/ok,2)+' ms':'—',lo==null?'No successful replies':number(lo)+'–'+number(hi)+' ms range'],
                ['Packet loss',sent?number(100*lost/sent,3)+'%':'—',number(lost)+' of '+number(sent)+' probes'],
                ['Timeouts',observed?number(to):'—','Within this period'],
                ['Successful replies',observed?number(ok):'—',number(err)+' local errors']
            ];
            cards.forEach(([title,value,detail],i)=>{
                const cell=inside/4, x=margin+i*cell+10;
                if(i)box(x-10,178,.65,40,line);
                text(title,x,173,9,regular,muted);
                fitted(value,x,188,cell-17,17,bold);
                fitted(detail,x,213,cell-16,8,regular,muted);
            });
            text('Round-trip latency',margin,245,14,bold);
            legend([['Average RTT (ms)',teal],['Min–max',band]],249);
            await chart('latency',270,92);
            text('Packet loss',margin,373,14,bold);
            legend([['Unanswered probes (%)',orange]],377);
            await chart('packet',396,84);
            text('Monitor adapter traffic',margin,494,14,bold);
            legend([['Receive (Mbps)',teal],['Transmit (Mbps)',blue]],498);
            await localText(d.nic||'Adapter counters unavailable',margin,515,inside,9,regular,muted);
            await chart('traffic',533,83);
            box(margin,627,inside,.7,line);
            text('Recent probe failures',margin,637,13,bold);
            right('Latest 3 within period and retained 48 h',pageWidth-margin,641,8);
            if(!d.events.length) {
                text(observed?'No failures recorded in the retained window.':'No probe observations recorded.',margin,666,10,regular,muted);
            } else {
                for(const [i,event] of d.events.slice(0,3).entries()) {
                    const top=664+i*19;
                    text(utc(event[0],true),margin,top,9);
                    await localText(event[1],margin+131,top,inside-133,9,regular,muted);
                }
            }
            if(d.error)await localText('Collector warning: '+d.error,margin,724,inside,9,regular,orange);
            const resolution=d.step<3600?number(d.step/60)+' min':number(d.step/3600)+' h';
            box(margin,750,inside,.8,line);
            text(number(d.points.length)+' of '+number((d.end-d.start)/d.step)+' intervals observed',margin,762,10,bold);
            right(resolution+' per interval',pageWidth-margin,763,9);
            text('Gaps indicate missing measurements. Local probe errors are excluded from packet loss.',margin,781,8.5,regular,muted);
            text('Generated '+utc(d.now,true)+' UTC',margin,809,8,regular,muted);

        }
        await addWindowsPages(doc,lib,regular,bold,health,sections,color,trends,history,manifest);
        return doc.save();
    }

    async function addWindowsPages(doc,lib,regular,bold,health,sections,color,trends,history,manifest) {
        if(!health||!health.categories)throw Error('Windows health snapshot is missing');
        const ctx=document.createElement('canvas').getContext('2d');
        const names={cpu:'CPU',ram:'RAM',disk_usage:'Disk usage',smart:'Disk health and SSD replacement',events:'Event logs - previous 24 hours',firewall:'Firewall profiles',antivirus:'Antivirus',security:'Security posture',event_details:'Event messages - previous 24 hours'};
        let page,y,sectionTitle='';
        function newPage(){
            page=doc.addPage([pageWidth,pageHeight]);y=64;
            page.drawRectangle({x:0,y:pageHeight-43,width:pageWidth,height:43,color:color(navy)});
            page.drawText('LinkScope  /  System reports',{x:margin,y:pageHeight-27,size:15,font:bold,color:color('#ffffff')});
            page.drawText('Snapshot '+health.generatedUtc.replace('T',' ').slice(0,19)+' UTC',{x:margin,y:27,size:8,font:regular,color:color(muted)});
            if(sectionTitle){page.drawText(sectionTitle+' (continued)',{x:margin,y:pageHeight-y,size:11,font:bold,color:color(teal)});y+=20;}
        }
        async function line(raw,{size=9,indent=0,font=regular,fill=ink}={}){
            const text=String(raw).replace(/[\x00-\x1f\x7f]/g,' '),limit=inside-indent;
            ctx.font=(font===bold?'bold ':'')+size+'px Arial, sans-serif';
            function width(s){try{return font.widthOfTextAtSize(s,size);}catch{return ctx.measureText(s).width;}}
            async function draw(s){
                if(y>pageHeight-58)newPage();
                const pos={x:margin+indent,y:pageHeight-y-size,size,font,color:color(fill)};
                try{font.encodeText(s);page.drawText(s,pos);}
                catch{
                    const canvas=document.createElement('canvas'),scale=2;
                    canvas.width=Math.ceil(limit*scale);canvas.height=Math.ceil((size+5)*scale);
                    const g=canvas.getContext('2d');g.scale(scale,scale);g.font=ctx.font;g.fillStyle=fill;g.fillText(s,0,size);
                    const image=await doc.embedPng(canvas.toDataURL('image/png'));
                    page.pushOperators(lib.PDFOperator.of('BDC',[lib.PDFName.of('Span'),doc.context.obj({ActualText:lib.PDFHexString.fromText(s)})]));
                    page.drawText(' ',{...pos,opacity:0});page.drawImage(image,{x:pos.x,y:pageHeight-y-canvas.height/scale,width:canvas.width/scale,height:canvas.height/scale});page.pushOperators(lib.PDFOperator.of('EMC'));
                }
                y+=size+4;
            }
            let current='';
            for(const word of text.split(/\s+/)){
                if(current&&width(current+' '+word)>limit){await draw(current);current='';}
                if(width(word)>limit){for(const c of word){if(current&&width(current+c)>limit){await draw(current);current='';}current+=c;}}
                else current+=(current?' ':'')+word;
            }
            await draw(current);
        }
        async function heading(title){
            sectionTitle='';if(y>pageHeight-118)newPage();y+=7;await line(title,{size:14,font:bold,fill:teal});sectionTitle=title;y+=3;
        }
        const scalar=v=>v==null?'unavailable':typeof v==='boolean'?(v?'true':'false'):String(v);
        async function fields(value,indent=0){
            if(Array.isArray(value)){
                if(!value.length){await line('No records.',{indent,fill:muted});return;}
                for(const [i,item] of value.entries()){
                    if(item&&typeof item==='object'){await fields(item,indent);if(i<value.length-1)y+=3;}
                    else await line(scalar(item),{indent});
                }
                return;
            }
            if(value==null||typeof value!=='object'){await line(scalar(value),{indent});return;}
            let parts=[];const nested=[];
            for(const [k,v] of Object.entries(value)){
                if(Array.isArray(v)&&v.every(x=>x===null||typeof x!=='object'))parts.push(k+' = '+(v.length?v.map(scalar).join(', '):'[]'));
                else if(v!==null&&typeof v==='object')nested.push([k,v]);
                else parts.push(k+' = '+scalar(v));
            }
            if(parts.length)await line(parts.join('   |   '),{indent});
            for(const [k,v] of nested){await line(k,{indent,font:bold,size:9});await fields(v,Math.min(indent+8,40));}
        }
        async function diskRows(disks){
            for(const d of disks){
                if(y>pageHeight-175)newPage();y+=7;
                await line('State: '+(d.headline||'UNABLE TO DETERMINE'),{font:bold,size:11,fill:d.recommendation==='replace'?orange:d.recommendation==='normal'?teal:ink});
                await line(d.model||'Physical disk',{font:bold,size:11});
                await line('Firmware: '+(d.firmware||'unavailable')+'   |   Serial: '+(d.serial||'unavailable')+'   |   Capacity: '+scalar(d.capacityBytes)+' bytes');
                await line('Vendor: '+(d.vendor||'unavailable')+'   |   Bus: '+(d.bus||'unavailable')+'   |   Scan: '+(d.scanUtc||'unavailable'));
                await line('S.M.A.R.T. Report',{font:bold,fill:teal});
                const cols=[0,52,81,310,345,381,463],head=['State','Num','Attribute Name','Value','Worst','Raw (hex)','Threshold'];
                function smartLine(cells,header){
                    if(header)page.drawRectangle({x:margin,y:pageHeight-y-12,width:inside,height:14,color:color(paper)});
                    cells.forEach((v,i)=>page.drawText(String(v),{x:margin+cols[i]+2,y:pageHeight-y-8,size:8,font:header?bold:regular,color:color(!header&&i===0?(v==='FAIL'?orange:v==='OK'?teal:muted):ink)}));y+=15;
                }
                if(d.attributes?.length){
                    if(y>pageHeight-98)newPage();smartLine(head,true);
                    const fmt=v=>v==null?'—':String(v).padStart(3,'0');
                    for(const a of d.attributes){if(y>pageHeight-60){newPage();smartLine(head,true);}
                        smartLine([a.state,fmt(a.id),a.name,fmt(a.value),fmt(a.worst),a.rawHex,fmt(a.threshold)],false);}
                }else await line('No ATA attributes available for this drive.',{fill:muted});
                await line('Findings / Advice',{font:bold,fill:teal});await line(d.advice||'Unavailable');
                for(const f of d.findings||[])await line(f,{indent:8});
                await line('Diagnostics / NVMe',{font:bold,fill:teal});
                const rest={...d};for(const key of ['model','headline','firmware','serial','capacityBytes','vendor','bus','scanUtc','attributes','advice','findings'])delete rest[key];
                await fields(rest);
            }
        }

        newPage();await line(health.monitorHost||'Monitoring host',{size:21,font:bold});await line('System readings belong to the monitoring computer. Network pages identify the ping target.',{fill:muted});
        await heading('Disk replacement alerts');
        const smart=health.categories.smart,smartResult=smart?.result,flagged=(smartResult?.items||[]).filter(x=>x.recommendation==='replace'||x.recommendation==='review');
        if(flagged.length){for(const d of flagged)await line((d.recommendation==='replace'?'Plan replacement':'Review disk')+' - '+d.model+' / disk '+d.device+' / remaining life '+(d.estimatedLifeRemainingPercent==null?'unavailable':d.estimatedLifeRemainingPercent+'%'),{font:bold,fill:orange});}
        else await line(smartResult?.status==='ok'?'No replacement or review flags in the available readings. See per-drive coverage below.':'Disk assessment unavailable or still collecting.',{fill:muted});
        await heading('Network probe alert rules');
        for(const t of manifest.targets){
            const failures=t.FailureCount??manifest.probeAlertCount;
            await line(t.Name+' ('+t.Address+')',{font:bold});
            await line(t.AlertsEnabled===false?'Alerts disabled':[
                'Consecutive failures: '+(failures||'off'),'RTT: '+(t.HighRttMs?t.HighRttMs+' ms':'off'),
                'Packet loss: '+(t.LossPercent?t.LossPercent+'% over '+t.LossWindowProbes+' probes':'off')].join('  /  '));
        }
        await heading('Active monitoring alerts');
        if(health.alerts?.length)await fields(health.alerts);else await line('No active alerts in the collected data.',{fill:muted});
        await heading('Resource usage by reporting period');
        for(const d of sections.filter(x=>x.target===sections[0].target)){
            await line(periods[d.range]+'  /  '+utc(d.start)+' to '+utc(Math.min(d.end,d.now))+' UTC',{font:bold});
            if(!d.resourceUsage?.length)await line('No resource samples recorded for this period.',{indent:8,fill:muted});
            else for(const u of d.resourceUsage)await line(u.metric+'  |  average '+number(u.averagePercent,1)+'%  |  min '+number(u.minPercent,1)+'%  |  peak '+number(u.peakPercent,1)+'%  |  '+number(u.samples)+' samples  |  '+u.firstUtc.slice(0,16)+' to '+u.lastUtc.slice(0,16)+' UTC',{indent:8});
        }
        for(const trend of trends){
            sectionTitle='';newPage();await heading(periods[trend.range]+' resource graphs');
            await line(utc(trend.start)+' to '+utc(Math.min(trend.now,trend.end))+' UTC. Usage on a 0-100% scale. Dark line: average. Pale bars: min-max.');
            const values=new Map(trend.series.map(m=>[m.metric,m.points]));
            for(const metric of new Set(['CPU','RAM',...values.keys()])){
                if(y>pageHeight-190)newPage();
                await line(metric+' usage (%)',{font:bold});
                const canvas=document.createElement('canvas');
                const tick=t=>trend.range==='day'?iso(t).slice(11,16):iso(t).slice(0,10);
                drawChart('resource',{...trend,points:values.get(metric)||[]},canvas,700,146,1.7,tick,null);
                const image=await doc.embedPng(canvas.toDataURL('image/png')),height=inside*146/700;
                page.drawImage(image,{x:margin,y:pageHeight-y-height,width:inside,height});y+=height+13;
            }
        }
        sectionTitle='';newPage();
        for(const [key,entry] of Object.entries(health.categories)){
            await heading(names[key]||key.replace(/_/g,' '));
            await line((entry.collectedUtc?'Sample '+entry.collectedUtc:'Awaiting first sample')+(entry.stale?'  /  STALE':'')+'  /  '+(entry.result?.status||entry.status||'unknown'),{size:9,fill:muted});
            const result=entry.result||entry;
            if(result.truncated)await line('The configured collection limit was reached.',{fill:orange});
            if(key==='smart'&&result.items?.length){const metadata={...result};delete metadata.items;await fields(metadata);await diskRows(result.items);}
            else await fields(result);y+=4;
        }
        sectionTitle='';newPage();await heading('Alert history');
        if(!history.length)await line('No monitoring alerts recorded.');
        for(const a of history){
            if(y>pageHeight-105)newPage();
            await line(a.sinceUtc.slice(0,19).replace('T',' ')+' UTC  /  '+a.category+'  /  '+a.severity+'  /  '+(a.read?'Read':'Unread')+'  /  '+(a.resolved?'Resolved':'Active'),{size:9,fill:teal});
            await line(a.title,{font:bold});await line(a.message);
            if(a.resolvedUtc)await line('Resolved '+a.resolvedUtc+' UTC',{size:8,fill:muted});
            y+=5;
        }
        sectionTitle='';newPage();await heading('Retained application logs');
        if(!manifest.logSummary.rows.length)await line('No application log entries yet.');
        for(const r of manifest.logSummary.rows)await line(r.module+'  /  '+r.level+'  /  '+r.count+' entries');
        const extraFailures=sections.filter(d=>d.events.length>3);
        if(extraFailures.length){
            sectionTitle='';newPage();await heading('Additional retained probe failures');
            for(const d of extraFailures){
                await line(d.target+' / '+periods[d.range],{font:bold});
                for(const e of d.events.slice(3))await line(utc(e[0],true)+' UTC  /  '+e[1]);
            }
        }
        const snapshot=new TextEncoder().encode(JSON.stringify({windows:health,network:sections,resourceHistory:trends,alertHistory:history,applicationLogSummary:manifest.logSummary,probeAlertRules:{defaultFailures:manifest.probeAlertCount,targets:manifest.targets}}));
        await doc.attach(snapshot,'LinkScope-report.json',{mimeType:'application/json',description:'Complete network, resource, Windows health and alert history report data.'});
        const pages=doc.getPages();
        pages.forEach((p,i)=>p.drawText((i+1)+' / '+pages.length,{x:pageWidth-margin-32,y:25,size:9,font:bold,color:color(teal)}));
    }

    async function get(url){
        const response=await fetch(url,{cache:'no-store',credentials:'same-origin'});
        if(response.status===401){location.assign('/login#report');throw Error('Sign in to export the complete report.');}
        if(!response.ok)throw Error('Report data unavailable (HTTP '+response.status+').');
        return response.json();
    }
    async function exportAll(){
        const button=document.getElementById('global-export'),status=document.getElementById('pdf-status');
        if(button.disabled)return;button.disabled=true;
        const done=LinkScopeBusy.begin('Exporting complete PDF…');
        try{
            status.textContent='Collecting the application report…';
            const manifest=await get('/ui/report');
            manifest.logSummary=await get('/ui/logs/summary');
            const sections=[],trends=[],history=[],keys=Object.keys(periods);
            let alerts=await get('/ui/alerts/history');
            while(true){
                history.push(...alerts.alerts);
                if(!alerts.more)break;
                alerts=await get('/ui/alerts/history?before='+alerts.alerts[alerts.alerts.length-1].sequence);
            }
            for(const range of keys)trends.push(await get('/ui/resource-history?'+new URLSearchParams({range,at:manifest.now})));
            for(const [i,target] of manifest.targets.entries()){
                status.textContent='Collecting network history '+(i+1)+' of '+manifest.targets.length+' · '+target.Address;
                const query=new URLSearchParams({target:target.Address,range:'all',at:manifest.now});
                const periodsData=await get('/api/history?'+query);
                if(periodsData.length!==4||periodsData.some((d,n)=>d.target!==target.Address||d.range!==keys[n]||d.now!==manifest.now))throw Error('Network report is incomplete for '+target.Address);
                sections.push(...periodsData);
            }
            status.textContent='Building PDF with '+manifest.targets.length+' targets and '+history.length+' alert records…';
            const bytes=await build(sections,manifest.windows,trends,history,manifest);
            const stamp=iso(manifest.now).slice(0,19).replace(/:/g,'-')+'Z';
            const filename='LinkScope_Complete_'+stamp+'.pdf';
            const url=URL.createObjectURL(new Blob([bytes],{type:'application/pdf'}));
            const link=document.createElement('a');link.href=url;link.download=filename;
            try{document.body.append(link);link.click();}finally{link.remove();setTimeout(()=>URL.revokeObjectURL(url),60000);}
            status.textContent='Downloaded '+filename;
            window.LinkScopeToast.message('success','PDF downloaded',filename);
        }catch(e){status.textContent='PDF export failed. '+e.message;window.LinkScopeToast.message('error','PDF export failed',e.message);}
        finally{done();button.disabled=false;}
    }
    const button=document.getElementById('global-export');
    if(button){button.onclick=exportAll;if(location.hash==='#report'){window.history.replaceState(null,'',location.pathname);exportAll();}}
    return {exportAll};
})();
