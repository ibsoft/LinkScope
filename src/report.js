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
            'Endpoint, Web Server Protection, Data Integrity and delivery status',
            history.length+' monitoring alert records',
            'The raw report data is attached as LinkScope-report.json.'
        ];
        if(!manifest.aiVerdict || !manifest.aiVerdict.answer) contents.forEach((v,i)=>cover.drawText(v,{x:margin,y:pageHeight-185-i*32,size:11,font:regular,color:color(muted)}));
        if(manifest.aiVerdict && manifest.aiVerdict.answer) {
            await addVerdictPages(doc,lib,regular,bold,color,cover,manifest.aiVerdict,sections[0].now);
        }
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
        // Decode the same embedded ICO used by the executable and browser header.
        try {
            const icon = new Image();
            await new Promise((resolve,reject)=>{icon.onload=resolve;icon.onerror=reject;icon.src='/assets/linkscope.ico';});
            const canvas=document.createElement('canvas');canvas.width=64;canvas.height=64;
            canvas.getContext('2d').drawImage(icon,0,0,64,64);
            const logo=await doc.embedPng(canvas.toDataURL('image/png'));
            for(const page of doc.getPages()) page.drawImage(logo,{x:page.getWidth()-margin-24,y:page.getHeight()-30,width:24,height:24});
        } catch(e) { console.warn('Report icon unavailable',e); }
        return doc.save();
    }

    async function addVerdictPages(doc,lib,regular,bold,color,cover,verdict,reportNow) {
        let page=cover,y=155;
        const ctx=document.createElement('canvas').getContext('2d');
        function newPage(){
            page=doc.addPage([pageWidth,pageHeight]);y=64;
            page.drawRectangle({x:0,y:pageHeight-43,width:pageWidth,height:43,color:color(navy)});
            page.drawText('LinkScope / AI verdict (continued)',{x:margin,y:pageHeight-27,size:15,font:bold,color:color('#ffffff')});
        }
        async function write(raw,size=10,font=regular,fill=ink){
            const text=clean(raw);
            ctx.font=(font===bold?'bold ':'')+size+'px "Segoe UI", Arial, sans-serif';
            function width(s){try{return font.widthOfTextAtSize(s,size);}catch{return ctx.measureText(s).width;}}
            async function draw(s){
                if(y+size+5>pageHeight-55)newPage();
                const pos={x:margin,y:pageHeight-y-size,size,font,color:color(fill)};
                try{font.encodeText(s);page.drawText(s,pos);}
                catch{
                    const canvas=document.createElement('canvas'),scale=3;
                    canvas.width=Math.ceil(inside*scale);canvas.height=Math.ceil((size+5)*scale);
                    const g=canvas.getContext('2d');g.scale(scale,scale);g.font=ctx.font;g.fillStyle=fill;g.fillText(s,0,size);
                    const image=await doc.embedPng(canvas.toDataURL('image/png'));
                    page.pushOperators(lib.PDFOperator.of('BDC',[lib.PDFName.of('Span'),doc.context.obj({ActualText:lib.PDFHexString.fromText(s)})]));
                    page.drawText(' ',{...pos,opacity:0});
                    page.drawImage(image,{x:margin,y:pageHeight-y-canvas.height/scale,width:canvas.width/scale,height:canvas.height/scale});
                    page.pushOperators(lib.PDFOperator.of('EMC'));
                }
                y+=size+5;
            }
            let current='';
            for(const word of text.split(/\s+/)){
                if(current&&width(current+' '+word)>inside){await draw(current);current='';}
                if(width(word)>inside){for(const c of word){if(current&&width(current+c)>inside){await draw(current);current='';}current+=c;}}
                else current+=(current?' ':'')+word;
            }
            if(current)await draw(current);else y+=6;
        }
        await write('AI executive summary - latest completed verdict',17,bold,teal);
        await write('Report generated: '+utc(reportNow,true)+' UTC',9,regular,muted);
        await write('Evidence snapshot: '+verdict.evidenceUtc+' | Completed: '+verdict.completedUtc,9,regular,muted);
        await write('Provider: '+verdict.provider+' | Model: '+verdict.model,9,regular,muted);
        const evidenceTime=Date.parse(verdict.evidenceUtc),completedTime=Date.parse(verdict.completedUtc);
        const age=reportNow-Math.floor(evidenceTime/1000);
        const valid=Number.isFinite(age)&&age>=0&&Number.isFinite(completedTime)&&completedTime>=evidenceTime;
        await write('Historical AI interpretation - not a live verdict. Evidence age: '+(valid?Math.floor(age/60)+' min '+age%60+' sec':'unverified')+'.',9,bold,orange);
        if(!valid||age>300||verdict.evidenceSchema!==2)await write('STALE OR LEGACY VERDICT: generate a new system verdict before relying on its conclusions. A five-minute report advisory is not a guarantee of freshness.',9,bold,orange);
        else await write('Recent saved verdict; compare with the current report because findings can change at any time.',9,regular,muted);
        if(verdict.coverage){await write('AI evidence sources: '+(verdict.coverage.sources||[]).join(', '),9,regular,muted);await write('AI unavailable/incomplete: '+((verdict.coverage.unavailable||[]).join(', ')||'None recorded by collector'),9,regular,muted);}
        else await write('AI coverage metadata unavailable (legacy verdict).',9,regular,muted);
        y+=8;
        for(const raw of verdict.answer.split(/\r?\n/)){
            const heading=/^\s*#{1,6}\s+/.test(raw);
            const value=raw.replace(/^\s*#{1,6}\s+/,'').replace(/\*\*/g,'').replace(/^\s*[-*]\s+/,'• ');
            await write(value,heading?12:10,heading?bold:regular,heading?teal:ink);
        }
    }

    async function addWindowsPages(doc,lib,regular,bold,health,sections,color,trends,history,manifest) {
        if(!health||!health.categories)throw Error('Windows health snapshot is missing');
        const ctx=document.createElement('canvas').getContext('2d');
        const names={endpoint_protection:'Endpoint Protection',data_integrity:'Data Integrity & Tamper Detection',cpu:'CPU',ram:'RAM',disk_usage:'Disk usage',smart:'Disk health and SSD replacement',events:'Event logs - previous 24 hours',firewall:'Firewall profiles',antivirus:'Antivirus',security:'Security posture',event_details:'Event messages - previous 24 hours'};
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
        if(health.categories.endpoint_protection){
            await heading('Endpoint Protection - threat and response summary');
            const ep=health.categories.endpoint_protection,er=ep.result||ep;
            await line('Mode: '+scalar(er.mode)+' / Coverage: '+scalar(er.status)+(ep.stale?' / STALE':'')+' / Last full scan: '+scalar(er.lastScanUtc),{font:bold,fill:er.status==='ok'&&!ep.stale?teal:orange});
            await line('Engine: '+scalar(er.engineVersion)+' / Signature DB: '+scalar(er.signatureDatabaseVersion)+' / Engine-reported date: '+scalar(er.signatureDatabaseTimestamp));
            await line('Active warning/critical findings: '+scalar(er.violations)+' / Files scanned: '+scalar(er.scannedFiles)+' / Canary paths: '+scalar(er.canaryCount)+' / Entropy changes: '+scalar(er.entropyChanges));
            await line('Pending incident delivery: '+scalar(er.pendingAlertDelivery)+' / Watcher queue: '+scalar(er.queueDepth)+' / Overflow count: '+scalar(er.overflowCount)+' / Process evidence: '+scalar(er.processCorrelation));
            await line('Definition freshness: '+scalar(er.signatureFreshness)+' / Last successful engine check: '+scalar(er.lastSignatureCheckUtc));
            await line('Last successful LinkScope FreshClam check: '+scalar(er.lastSuccessfulSignatureRefreshUtc)+' / Last confirmed changed signature database: '+scalar(er.lastSuccessfulSignatureUpdateUtc));
            await line('Latest database update reported by FreshClam log: '+scalar(er.lastReportedSignatureUpdateUtc)+' (log evidence, not cryptographic verification).');
            await line('Signature maintenance: '+scalar(er.signatureMaintenance?.status)+' / '+scalar(er.signatureMaintenance?.detail),{fill:er.signatureMaintenance?.status==='Failed'?orange:muted});
            if(er.signatureSchedule){const ss=er.signatureSchedule;await line('Scheduled signatures: '+(ss.enabled?scalar(ss.frequency)+' at '+scalar(ss.localTime)+' ('+scalar(ss.timeZone)+') / '+scalar(ss.status)+' / Next UTC: '+scalar(ss.nextRunUtc)+' / Last request UTC: '+scalar(ss.lastScheduledRequestUtc):'Disabled')+'. Native FreshClam updates remain independent.');}
            await line('Automatic response readiness: '+scalar(er.responseEngineStatus)+' / '+scalar(er.responseEngineDetail)+' / Checked: '+scalar(er.responseCheckedUtc));
            for(const r of er.responsePathsReadiness||[])await line('Response path access (advisory): '+scalar(r.path)+' / '+scalar(r.status)+' / '+scalar(r.detail),{fill:r.status==='warning'?orange:muted});
            await line('Signature check outcomes (since policy start): clean '+scalar(er.cleanChecks)+' / confirmed malware '+scalar(er.infectedChecks)+' / heuristic '+scalar(er.heuristicChecks)+' / excluded '+scalar(er.excludedChecks)+' / failed or limited '+scalar(er.failedChecks)+' / quarantined '+scalar(er.quarantinedChecks));
            await line('Active malware: '+scalar(er.activeMalware)+' / Active heuristic findings: '+scalar(er.activeHeuristic)+' / Active scan issues: '+scalar(er.activeScanIssues)+' / Quarantine payloads: '+scalar(er.quarantineCount)+' / Permanently deleted: '+scalar(er.quarantineDeletedCount));
            for(const d of er.quarantineDeletions||[])await line('Quarantine deletion: '+scalar(d.deletedUtc)+' / '+scalar(d.actor)+' / '+scalar(d.path)+' / SHA-256 '+scalar(d.sha256));
            for(const canary of er.canaries||[])await line('Canary: '+scalar(canary.path)+' / '+scalar(canary.status)+' / '+scalar(canary.detail),{fill:canary.status==='critical'?orange:muted});
            for(const finding of er.items||[])await line('Detection: '+scalar(finding.change)+' / '+scalar(finding.severity)+' / '+scalar(finding.path)+' / '+scalar(finding.detail),{fill:orange});
            if(er.truncated)await line('Active detail snapshot capped; see full Alert History and endpoint database.',{fill:orange});
            await line('Detection and restricted response only; no kernel interception. Missing or incomplete coverage does not imply a clean endpoint.',{fill:muted});
        }
        await heading('Web Server Protection - supplemental detection and coverage');
        const assessment=manifest.webAssessment, ep=health.categories.endpoint_protection, er=ep?.result||{};
        if(!assessment)await line('Assessment unavailable. No clean or healthy verdict can be established.',{fill:orange});
        else {
            await line('Assessment: '+scalar(assessment.assessment),{font:bold,fill:assessment.assessment==='Requires attention'?orange:muted});
            await line('Endpoint enabled: '+scalar(assessment.endpointEnabled)+' / Web script inspection enabled: '+scalar(assessment.enabled)+' / Process audit enabled: '+scalar(assessment.processAuditEnabled));
            await line('Administrator-approved suspicious script quarantine: '+scalar(assessment.manualQuarantineEnabled));
            await line('Telemetry: '+scalar(assessment.collectedUtc)+' / Fresh: '+scalar(assessment.fresh)+' / Matches current policy: '+scalar(assessment.telemetryPolicyMatches));
            await line('Shared scanner: '+scalar(assessment.sharedScannerStatus)+' / Baseline verified: '+scalar(assessment.sharedBaselineVerified)+' / Configured paths covered: '+scalar(assessment.configuredPathsCovered));
            await line('Last script inspection: '+scalar(assessment.lastScriptCheckUtc)+' / Process audit: '+scalar(assessment.processAuditState));
            if(assessment.historicalAuditLimitation)await line('Historical audit limitation (current monitoring recovered): '+scalar(assessment.historicalAuditLimitation),{fill:orange});
            const counts=assessment.reportedCounts||{};
            await line('Last reported active counters (not lifetime totals):',{font:bold});
            for(const [key,label] of [['suspiciousScripts','Suspicious scripts'],['inspectionIssues','Inspection issues'],['processFindings','Suspicious process findings'],['auditIssues','Audit issues']])await line(label+': '+scalar(counts[key]),{fill:counts[key]>0?orange:muted});
            await line('Configured web paths:',{font:bold});
            if(!assessment.configuredPaths?.length)await line('None configured.',{fill:muted});
            for(const path of assessment.configuredPaths||[])await line(path,{indent:8});
            await line('Coverage and limitations: '+scalar(assessment.limitations),{fill:muted});
            await line('Supplemental script limit: '+scalar(assessment.scriptInspectionLimitBytes)+' bytes. A heuristic finding does not confirm malware. Acknowledgement does not resolve a finding.',{fill:muted});
            const webChanges=new Set(['Suspicious web script quarantined','Suspicious web script','Web script inspection incomplete','Suspicious web server child process','Web process audit unavailable','Web process audit history gap']);
            const active=(er.items||[]).filter(x=>webChanges.has(x.change));const recent=(er.recentIncidents||[]).filter(x=>webChanges.has(x.change));
            await line('Active finding details (returned '+active.length+'; global snapshot truncated: '+scalar(assessment.activeSnapshotTruncated)+')',{font:bold});
            if(!active.length)await line('No matching detail rows returned. Refer to reported counts and coverage; empty rows are not proof of absence.',{fill:muted});
            for(const f of active)await line([f.lastUtc,f.change,f.severity,f.path,f.detail].map(scalar).join(' / '),{fill:orange});
            await line('Recent historical incidents (returned '+recent.length+' from bounded endpoint history; not current findings)',{font:bold});
            for(const f of recent)await line([f.utc,f.change,f.severity,f.path,f.detail].map(scalar).join(' / '));
            await line('Investigation: verify suspicious scripts against trusted deployments, review associated process events, check audit and file-access coverage, then verify recovery. Do not equate heuristic warnings with confirmed malware.',{fill:muted});
        }
        await heading('Collection scope and optional inventory');
        await line('Disabled optional categories: '+(manifest.disabledInventory?.join(', ')|| (Array.isArray(manifest.disabledInventory)?'None':'Unknown')));
        await heading('Native active connections');
        if(!manifest.connections||!Array.isArray(manifest.connections.rows))await line('Connection snapshot unavailable.',{fill:orange});
        else {const c=manifest.connections;await line('Sample UTC: '+(typeof c.now==='number'?utc(c.now,true):'Unknown')+' / Returned '+c.rows.length+' of '+scalar(c.total)+' entries. No process attribution.',{fill:c.total>c.rows.length?orange:muted});await fields(c.rows);}
        await heading('Alert delivery, logging and SIEM');
        if(manifest.delivery)await fields(manifest.delivery);else await line('Delivery status unavailable or restricted to administrators.',{fill:orange});
        if(manifest.logging)await fields(manifest.logging);else await line('Logging and SIEM status unavailable or restricted to administrators.',{fill:orange});
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
        const snapshot=new TextEncoder().encode(JSON.stringify({aiVerdict:manifest.aiVerdict||undefined,webAssessment:manifest.webAssessment,disabledInventory:manifest.disabledInventory,connections:manifest.connections,delivery:manifest.delivery,logging:manifest.logging,windows:health,network:sections,resourceHistory:trends,alertHistory:history,applicationLogSummary:manifest.logSummary,probeAlertRules:{defaultFailures:manifest.probeAlertCount,targets:manifest.targets}}));
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
        if(button.getAttribute('aria-disabled')==='true')return;button.setAttribute('aria-disabled','true');button.setAttribute('aria-busy','true');
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
        finally{done();button.removeAttribute('aria-disabled');button.removeAttribute('aria-busy');}
    }
    const button=document.getElementById('global-export');
    if(button){button.onclick=e=>{e.preventDefault();exportAll();};if(location.hash==='#report'){window.history.replaceState(null,'',location.pathname);exportAll();}}
    return {exportAll};
})();
