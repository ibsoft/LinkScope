using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace LinkScope {
    internal sealed class AiEvidence {
        readonly List<string> records=new List<string>();
        readonly List<string> facts=new List<string>();
        readonly List<string> securityFacts=new List<string>();
        internal string SecurityFacts(){return string.Join("\n",securityFacts);}
        internal string SystemFacts(){return string.Join("\n",facts)+"\nUnavailable or incomplete: "+(Missing.Count==0?"none reported":string.Join(", ",Missing));}
        void Exact(string section,object value){facts.Add("- "+section+": "+Config.Json().Serialize(value));}
        static object Decode(object value){var j=Config.Json();return j.DeserializeObject(j.Serialize(value));}
        internal readonly List<string> Sources=new List<string>();
        internal string NetworkVerdict="Network evidence unavailable; packet loss and timeouts cannot be assessed.";
        internal int Categories,Targets;internal string Utc;internal readonly List<string> Missing=new List<string>();
        internal object Coverage(){return new {utc=Utc,categories=Categories,targets=Targets,records=records.Count,sources=Sources.ToArray(),unavailable=Missing.ToArray()};}
        internal List<string> Chunks(){
            var result=new List<string>();var b=new StringBuilder();
            foreach(string record in records){
                if(b.Length>0&&b.Length+record.Length>20000){result.Add(b.ToString());b.Clear();}
                b.AppendLine(record);
            }
            if(b.Length>0)result.Add(b.ToString());return result;
        }
        void Fact(string group,object value){if(!Sources.Contains(group))Sources.Add(group);records.Add(Config.Json().Serialize(new {source=group,data=value}));}
        void Read(string section,Action action){try{action();}catch(Exception){Missing.Add(section);Fact(section,"Evidence unavailable.");}}
        static readonly HashSet<string> Omit=new HashSet<string>(StringComparer.OrdinalIgnoreCase){"serial","MACAddress","message","diagnostics","reason","description","commandline","password","apikey","protectedkey","token","secret","databasecustomurl","providerurl","subscriptionurl","mfaProtected","authorization","cookie"};
        static object Safe(object x,int depth){
            if(x==null||depth>12)return null;
            var d=x as Dictionary<string,object>;
            if(d!=null)return d.Where(k=>!Omit.Contains(k.Key)).ToDictionary(k=>k.Key,k=>Safe(k.Value,depth+1));
            if(x is string){string s=System.Text.RegularExpressions.Regex.Replace((string)x,@"(?i)https?://[^\s<>\x22]+","[URL redacted]");return s.Length>320?s.Substring(0,320):s;}
            if(x is IEnumerable){var a=AiProvider.List(x);return a.Select(i=>Safe(i,depth+1)).ToArray();}
            return x;
        }
        void Health(Telemetry monitor,Config cfg){
            var json=Config.Json();
            var snap=json.DeserializeObject(json.Serialize(monitor.Snapshot(cfg.Categories().Where(x=>x!="data_integrity"&&x!="endpoint_protection"))));
            var cats=AiProvider.Map(AiProvider.Get(snap,"categories"));Categories+=cats.Count;
            foreach(var c in cats){
                var wrapper=AiProvider.Map(c.Value);var result=AiProvider.Map(AiProvider.Get(wrapper,"result"));
                string state=Convert.ToString(AiProvider.Get(wrapper,"status")??AiProvider.Get(result,"status"));
                if(state!="ok"||Equals(AiProvider.Get(wrapper,"stale"),true)||Equals(AiProvider.Get(result,"truncated"),true))
                    Missing.Add(c.Key+" ("+(Equals(AiProvider.Get(wrapper,"stale"),true)?"stale":state)+")");
                var items=AiProvider.List(AiProvider.Get(result,"items"));
                Exact(c.Key,new {status=state,stale=AiProvider.Get(wrapper,"stale"),collectedUtc=AiProvider.Get(wrapper,"collectedUtc"),itemCount=items.Length,truncated=AiProvider.Get(result,"truncated")});
                var fields=result.Where(k=>k.Key!="items").ToDictionary(k=>k.Key,k=>k.Value);
                Fact(c.Key,new {status=AiProvider.Get(wrapper,"status")??AiProvider.Get(result,"status"),collectedUtc=AiProvider.Get(wrapper,"collectedUtc"),
                    ageSeconds=AiProvider.Get(wrapper,"ageSeconds"),stale=AiProvider.Get(wrapper,"stale"),details=Safe(fields,0),itemCount=items.Length});
                if(c.Key=="cpu"||c.Key=="ram"||c.Key=="antivirus")Exact(c.Key+" readings",Safe(fields,0));
                foreach(var item in items){
                    var row=AiProvider.Map(item);
                    if(c.Key=="smart"){
                        var attrs=AiProvider.List(AiProvider.Get(item,"attributes"));
                        Fact("smart",Safe(row.Where(k=>k.Key!="attributes").ToDictionary(k=>k.Key,k=>k.Value),0));
                        var flagged=attrs.Where(a=>new[]{"FAIL","REVIEW"}.Contains(AiProvider.Text(a,"state"))).ToArray();
                        foreach(var a in attrs)Fact("smart-attribute",new {disk=AiProvider.Get(row,"diskId"),attribute=Safe(a,0)});
                        Fact("smart-counts",new {disk=AiProvider.Get(row,"diskId"),attributes=attrs.Length,flagged=flagged.Length});
                        Exact("SMART disk",new {disk=AiProvider.Get(row,"diskId"),model=AiProvider.Get(row,"model"),health=AiProvider.Get(row,"health"),lifeRemaining=AiProvider.Get(row,"estimatedLifeRemainingPercent"),recommendation=AiProvider.Get(row,"recommendation"),temperatureC=AiProvider.Get(row,"temperatureC"),predictFailure=AiProvider.Get(row,"predictFailure"),flagged=flagged.Length});
                    }else if(c.Key=="events"||c.Key=="event_details"){
                        var events=AiProvider.List(AiProvider.Get(row,"items"));
                        Fact(c.Key,new {channel=AiProvider.Get(row,"channel"),status=AiProvider.Get(row,"status"),truncated=AiProvider.Get(row,"truncated"),
                            total=events.Length,byLevel=events.GroupBy(v=>AiProvider.Text(v,"level")).Select(g=>new {level=g.Key,count=g.Count()}),
                            byProviderAndId=events.GroupBy(v=>AiProvider.Text(v,"provider")+" #"+AiProvider.Get(v,"eventId")).Select(g=>new {eventType=g.Key,count=g.Count()}),recent=events.Take(12).Select(v=>Safe(v,0))});
                        Exact(c.Key+" channel",new {channel=AiProvider.Get(row,"channel"),status=AiProvider.Get(row,"status"),truncated=AiProvider.Get(row,"truncated"),total=events.Length,critical=events.Count(v=>AiProvider.Text(v,"level")=="Critical"),errors=events.Count(v=>AiProvider.Text(v,"level")=="Error"),warnings=events.Count(v=>AiProvider.Text(v,"level")=="Warning")});
                        foreach(var ev in events)Fact(c.Key+"-record",Safe(ev,0));
                    }else {Fact(c.Key,Safe(item,0));if(new[]{"disk_usage","security","firewall","antivirus"}.Contains(c.Key))Exact(c.Key+" reading",Safe(item,0));}
                }
            }
        }
        // Security readings are kept out of the general (potentially very large) inventory payload.
        // The final model receives these facts even after evidence-group summarization.
        static readonly string[] IntegrityFields={"chainValid","sequence","chainHead","monitoredFiles","excludedEntries","violations"};
        static readonly string[] EndpointFields={"engineOnline","engineVersion","signatureDatabaseVersion","signatureDatabaseTimestamp","signatureFreshness","lastSuccessfulSignatureUpdateUtc","lastSuccessfulSignatureRefreshUtc","lastReportedSignatureUpdateUtc","signatureUpdateLogRecognized","lastSignatureCheckUtc","mode","responseEngineStatus","responseEngineDetail","responseCheckedUtc","realTime","watcherCount","queueDepth","overflowCount","scanRunning","scanStartedUtc","lastScanUtc","nextScanUtc","lastRealTimeScanUtc","lastFileScanUtc","scannedFiles","sizeLimitedFiles","excludedEntries","cleanChecks","infectedChecks","heuristicChecks","excludedChecks","failedChecks","quarantinedChecks","activeMalware","activeHeuristic","activeScanIssues","quarantineCount","quarantineDeletedCount","changedFiles","entropyChanges","canaryCount","processCorrelation","violations","pendingAlertDelivery","realTimeChecked"};
        static Dictionary<string,object> Pick(object value,IEnumerable<string> fields){
            var map=AiProvider.Map(value);return fields.Where(map.ContainsKey).ToDictionary(k=>k,k=>Safe(map[k],0));
        }
        static object[] PriorityRows(object[] rows,int count){return rows.OrderBy(v=>{
            string severity=AiProvider.Text(v,"severity");if(severity.Length==0)severity=AiProvider.Text(v,"status");
            return severity=="critical"||severity=="error"?0:severity=="warning"?1:2;
        }).Take(count).ToArray();}
        static object RowCounts(object[] rows,string field){return rows.GroupBy(x=>AiProvider.Text(x,field)).Select(g=>new {value=Safe(g.Key,0),count=g.Count()}).ToArray();}
        static readonly string[] FindingFields={"id","path","change","severity","status","detail","expectedHash","actualHash","hash","firstUtc","lastUtc","utc"};
        void SecurityRows(string category,string field,object[] rows,int sampleLimit,string[] fields){
            // All returned rows contribute to counts; only a bounded subset is sent to the model.
            var sample=field=="items"||field=="canaries"?PriorityRows(rows,sampleLimit):rows.Take(sampleLimit).ToArray();
            Fact(category+"-"+field+"-coverage",new {returned=rows.Length,sent=sample.Length,omitted=rows.Length-sample.Length,scope="returned snapshot rows only"});
            foreach(var row in sample)Fact(category+"-"+field,Pick(row,fields));
        }
        internal void SecuritySnapshot(string category,object wrapper,bool enabled){
            Categories++;
            var result=AiProvider.Map(AiProvider.Get(wrapper,"result"));
            string state=Convert.ToString(AiProvider.Get(wrapper,"status")??AiProvider.Get(result,"status"));
            if(string.IsNullOrEmpty(state))state="unavailable";
            bool stale=Equals(AiProvider.Get(wrapper,"stale"),true),truncated=Equals(AiProvider.Get(result,"truncated"),true);
            var items=AiProvider.List(AiProvider.Get(result,"items"));
            bool endpoint=category=="endpoint_protection";
            if(!enabled||stale||truncated||(state!="ok"&&state!="scanning"))Missing.Add(category+" ("+(!enabled?"disabled":stale?"stale":truncated?"truncated":state)+")");
            // Keep raw observations separate from threat conclusions, including scan coverage limits.
            var summary=new Dictionary<string,object>{
                {"enabled",enabled},{"status",state},{"stale",stale},{"collectedUtc",AiProvider.Get(wrapper,"collectedUtc")},
                {"ageSeconds",AiProvider.Get(wrapper,"ageSeconds")},{"truncated",truncated},{"returnedFindings",items.Length},
                {"findingsBySeverity",RowCounts(items,"severity")},{"findingsByChange",RowCounts(items,"change")},
                {"readings",Pick(result,endpoint?EndpointFields:IntegrityFields)},
                {"priorityFindings",PriorityRows(items,8).Select(x=>Pick(x,FindingFields)).ToArray()},
                {"findingsInExactSummary",Math.Min(8,items.Length)}
            };
            // Paths, file names, hashes and detection labels are evidence, never executable instructions.
            var paths=AiProvider.List(AiProvider.Get(result,"protectedPaths"));
            summary["protectedPathCount"]=paths.Length;
            summary["protectedPathSample"]=paths.Take(10).Select(x=>Safe(x,0)).ToArray();
            if(endpoint){
                var canaries=AiProvider.List(AiProvider.Get(result,"canaries"));
                var scans=AiProvider.List(AiProvider.Get(result,"scanActivity"));
                var history=AiProvider.List(AiProvider.Get(result,"recentIncidents"));
                var quarantine=AiProvider.List(AiProvider.Get(result,"quarantineItems"));
                summary["signatureMaintenance"]=Pick(AiProvider.Get(result,"signatureMaintenance"),new[]{"status","attemptUtc","checkedUtc","updatedUtc","detail"});
                summary["signatureSchedule"]=Pick(AiProvider.Get(result,"signatureSchedule"),new[]{"enabled","frequency","localTime","weekday","monthDay","timeZone","status","nextRunUtc","lastScheduledRequestUtc"});
                summary["canaryStatusCounts"]=RowCounts(canaries,"status");
                summary["canarySample"]=PriorityRows(canaries,6).Select(x=>Pick(x,new[]{"path","status","detail","expectedHash"})).ToArray();
                summary["recentScanSampleCounts"]=RowCounts(scans,"result");
                summary["recentScanRows"]=scans.Length;summary["recentScanLimit"]=AiProvider.Get(result,"scanActivityLimit");
                summary["recentIncidentRows"]=history.Length;summary["incidentHistoryLimit"]=AiProvider.Get(result,"historyLimit");
                summary["recentIncidentSampleCounts"]=RowCounts(history,"severity");
                summary["quarantineRecentDeletionCount"]=AiProvider.List(AiProvider.Get(result,"quarantineDeletions")).Length;summary["quarantineReturnedRows"]=quarantine.Length;summary["quarantineSampleCounts"]=RowCounts(quarantine,"state");
                summary["scopeNote"]="Scan counters are checks, not unique files; recent scan and incident rows are bounded samples, not lifetime totals. Signature version/freshness is engine-reported, not proof of every third-party feed being current.";
                SecurityRows(category,"canaries",canaries,20,new[]{"path","status","detail","expectedHash"});
                SecurityRows(category,"scanActivity",scans,20,new[]{"utc","path","source","result","durationMs","detail"});
                SecurityRows(category,"recentIncidents",history,20,FindingFields);
                SecurityRows(category,"quarantineItems",quarantine,15,new[]{"id","path","sha256","state","utc"});
            }else summary["scopeNote"]="The authenticated chain and file integrity readings are distinct: a valid chain does not establish that protected files are unchanged. Incomplete scans and unavailable data do not prove files are safe.";
            securityFacts.Add("- "+category+": "+Config.Json().Serialize(summary));
            Fact(category,summary);SecurityRows(category,"items",items,30,FindingFields);
        }
        void SecurityHealth(Telemetry monitor,string category,bool enabled){
            var snapshot=Decode(monitor.Snapshot(new[]{category}));
            SecuritySnapshot(category,AiProvider.Get(AiProvider.Get(snapshot,"categories"),category),enabled);
        }
        // Keep exact recent network facts separate from model-generated summaries.
        internal static string ProbeWindowText(object[] row){
            long ok=Convert.ToInt64(row[0]),lost=Convert.ToInt64(row[1]),timeouts=Convert.ToInt64(row[2]),errors=Convert.ToInt64(row[3]);
            long sent=ok+lost;
            string loss=sent==0?"unknown (no valid probes)":(100.0*lost/sent).ToString("0.###",System.Globalization.CultureInfo.InvariantCulture)+"%";
            return "loss "+loss+" ("+lost+"/"+sent+"), timeouts "+timeouts+", replies "+ok+", local errors "+errors+(row.Length>=7?", RTT avg/min/max ms: "+string.Join("/",row.Skip(4).Take(3).Select(v=>v==null||v==DBNull.Value?"unknown":Convert.ToString(v,System.Globalization.CultureInfo.InvariantCulture))):"");
        }
        void RecentNetwork(Config running,long now){
            Targets=running.Targets.Length;
            var lines=new List<string>();int affected=0,unknown=0;
            using(var db=new Sqlite(true)){
                db.Exec("BEGIN");
                foreach(var target in running.Targets){
                    var windows=new List<object[]>();
                    foreach(int seconds in new[]{3600,86400}){
                        windows.Add(db.Rows(@"SELECT COUNT(CASE WHEN rtt IS NOT NULL THEN 1 END),
                            COUNT(CASE WHEN rtt IS NULL AND status NOT LIKE 'Probe error:%' THEN 1 END),
                            COUNT(CASE WHEN status='TimedOut' THEN 1 END),
                            COUNT(CASE WHEN status LIKE 'Probe error:%' THEN 1 END),ROUND(AVG(rtt),2),MIN(rtt),MAX(rtt)
                            FROM raw WHERE target=? AND t>=? AND t<=?",target.Address,now-seconds,now)[0]);
                    }
                    var latest=db.Rows("SELECT t,CASE WHEN status LIKE 'Probe error:%' THEN 'Local probe error' ELSE status END FROM raw WHERE target=? AND t<=? ORDER BY t DESC,rowid DESC LIMIT 1",target.Address,now).FirstOrDefault();
                    bool stale=latest==null||now-Convert.ToInt64(latest[0])>Math.Max(3L*running.IntervalSeconds,15L);
                    bool failed=windows.Any(r=>Convert.ToInt64(r[1])>0||Convert.ToInt64(r[2])>0||Convert.ToInt64(r[3])>0);
                    bool insufficient=stale||windows.Any(r=>Convert.ToInt64(r[0])+Convert.ToInt64(r[1])==0);
                    if(failed)affected++;if(insufficient)unknown++;
                    string state=latest==null?"no samples":(stale?"STALE; last ":"")+Convert.ToString(latest[1])+" at "+Telemetry.Utc(Convert.ToInt64(latest[0]));
                    lines.Add("- "+target.Address+": "+(failed?"FAILURES OBSERVED":insufficient?"INSUFFICIENT DATA":"NO OBSERVED FAILURES")+"; "+state+"; 1h: "+ProbeWindowText(windows[0])+"; 24h: "+ProbeWindowText(windows[1]));
                }
                db.Exec("COMMIT");
            }
            NetworkVerdict=(Targets==0?"UNKNOWN - no targets configured":affected>0?"NETWORK FAILURES OBSERVED":unknown>0?"NETWORK STATUS INCOMPLETE":"NO OBSERVED NETWORK FAILURES")+
                " | targets with failures: "+affected+"/"+Targets+"; targets with insufficient or stale data: "+unknown+"/"+Targets+". Windows use available samples, not guaranteed full coverage. Timeouts are included in loss; local probe errors are excluded. ICMP failure alone does not prove service downtime.\n"+string.Join("\n",lines);
            if(!Sources.Contains("network-recent-exact"))Sources.Add("network-recent-exact");
        }
        void Network(Config running,Config rules,long now){
            using(var db=new Sqlite(true)){
                db.Exec("BEGIN");
                var ranges=new[]{1,7,30,365};
                var sums=new Dictionary<int,Dictionary<string,object[]>>();
                foreach(int days in ranges){
                    int res=days>35?3600:300;long since=(now-days*86400L)/res*res;
                    sums[days]=db.Rows("SELECT target,SUM(ok),SUM(lost),SUM(timeouts),SUM(errors),ROUND(1.0*SUM(total)/NULLIF(SUM(ok),0),2),MIN(lo),MAX(hi) FROM ping_roll WHERE res=? AND t BETWEEN ? AND ? GROUP BY target",res,since,now).ToDictionary(r=>(string)r[0]);
                    var hosts=db.Rows("SELECT metric,SUM(n),ROUND(SUM(total)/SUM(n),2),MIN(lo),MAX(hi) FROM resource_roll WHERE res=? AND t BETWEEN ? AND ? GROUP BY metric",res,since,now);
                    Fact("resource-history",new {days=days,columns="metric,samples,mean%,min%,max%",rows=hosts});
                    if(days==1)Exact("24h resource history (metric,samples,mean%,min%,max%)",hosts);
                    var rates=db.Rows("SELECT nic,ROUND(SUM(rx)/NULLIF(SUM(seconds),0),2),ROUND(SUM(tx)/NULLIF(SUM(seconds),0),2) FROM traffic_roll WHERE res=? AND t BETWEEN ? AND ? GROUP BY nic",res,since,now);
                    Fact("traffic-history",new {days=days,columns="adapter,meanRxBytesPerSecond,meanTxBytesPerSecond",rows=rates});
                    if(days==1)Exact("24h adapter traffic (adapter,mean RX B/s,mean TX B/s)",rates);
                }
                Targets=running.Targets.Length;
                foreach(var target in running.Targets){
                    var configured=rules.Targets.FirstOrDefault(x=>x.Address==target.Address)??target;
                    var last=db.Rows("SELECT t,CASE WHEN status LIKE 'Probe error:%' THEN 'Local probe error' ELSE status END,rtt FROM raw WHERE target=? ORDER BY t DESC,rowid DESC LIMIT 1",target.Address).FirstOrDefault();
                    Fact("network",new {ip=target.Address,name=target.Name,latest=last,latestColumns="UTC Unix seconds,status,RTT ms",intervalSeconds=running.IntervalSeconds,timeoutMs=running.TimeoutMs,
                        alertRules=new {enabled=configured.AlertsEnabled,failures=configured.FailureCount??rules.ProbeAlertCount,rttMs=configured.HighRttMs,lossPct=configured.LossPercent,window=configured.LossWindowProbes},
                        periodColumns="replies,lost,timeouts,probeErrors,avgRTTms,minRTTms,maxRTTms",
                        periods=ranges.ToDictionary(day=>day.ToString(),day=>sums[day].ContainsKey(target.Address)?sums[day][target.Address].Skip(1).ToArray():null)});
                }
                var counts=db.Rows("SELECT category,severity,resolved,COUNT(*) FROM alert_events WHERE resolved=0 OR since>=? GROUP BY category,severity,resolved",now-86400);
                Exact("Alert counts (category,severity,resolved,count)",counts);
                Fact("alert-counts",new {columns="category,severity,resolved,count",scope="all active plus openings in 24 hours",rows=counts});
                foreach(var row in db.Rows("SELECT id,category,severity,title,since FROM alert_events WHERE resolved=0 ORDER BY seq DESC")){
                    var alert=new {id=row[0],category=row[1],severity=row[2],title=row[3],openedUnix=row[4]};
                    Fact("active-alert",alert);Exact("Active alert",alert);
                }
                foreach(var row in db.Rows("SELECT id,category,severity,title,since,ended FROM alert_events WHERE resolved=1 ORDER BY seq DESC LIMIT 60"))
                    Fact("recent-recovery",new {id=row[0],category=row[1],severity=row[2],title=row[3],openedUnix=row[4],endedUnix=row[5]});
                db.Exec("COMMIT");
            }
        }
        internal static AiEvidence Collect(Telemetry monitor,Config running,Config rules,Func<object> deliveryState=null){
            long now=History.Now();var e=new AiEvidence{Utc=Telemetry.Utc(now)};
            e.Fact("monitor",new {host=Environment.MachineName,utc=e.Utc,cpuAlertPercent=rules.CpuAlertPercent,ramAlertPercent=rules.RamAlertPercent,diskAlertPercent=rules.DiskAlertPercent,lowLifePercent=rules.LowLifePercent});
            e.Read("Recent network probes",()=>e.RecentNetwork(running,now));
            e.Read("Data Integrity",()=>e.SecurityHealth(monitor,"data_integrity",rules.Integrity.Enabled));
            e.Read("ClamAV Endpoint Protection",()=>e.SecurityHealth(monitor,"endpoint_protection",rules.Endpoint.Enabled));
            e.Read("Windows health",()=>e.Health(monitor,rules));
            var disabled=Config.Extras.Except(rules.ExtraCategories).ToArray();e.Exact("Optional inventory not enabled",disabled);e.Fact("disabled-inventory",disabled);
            e.Read("Active connections",()=>{var snapshot=Decode(NativeConnections.Snapshot());var rows=AiProvider.List(AiProvider.Get(snapshot,"rows"));
                var counts=rows.GroupBy(r=>AiProvider.Text(r,"protocol")+"/"+AiProvider.Text(r,"state")).Select(g=>new {type=g.Key,count=g.Count()}).ToArray();
                var summary=new {total=AiProvider.Get(snapshot,"total"),sampleCount=rows.Length,byState=counts};
                e.Exact("Native connection snapshot (counts based on returned rows)",summary);e.Fact("connections-summary",summary);
                for(int i=0;i<rows.Length;i+=100)e.Fact("connections",new {columns="protocol,local,remote,state",rows=rows.Skip(i).Take(100).Select(r=>new[]{AiProvider.Text(r,"protocol"),AiProvider.Text(r,"local"),AiProvider.Text(r,"remote"),AiProvider.Text(r,"state")}).ToArray()});
            });
            if(deliveryState!=null)e.Read("Alert delivery status",()=>{var d=AiProvider.Map(Decode(deliveryState()));var state=Safe(d.Where(k=>k.Key=="queued"||k.Key=="email"||k.Key=="files"||k.Key=="testState").ToDictionary(k=>k.Key,k=>k.Value),0);e.Exact("Alert delivery status",state);e.Fact("alert-delivery",state);});
            e.Read("Logging and SIEM status",()=>{var state=Safe(Decode(AppJournal.Current.State()),0);e.Exact("Logging and SIEM status",state);e.Fact("logging-siem-status",state);});
            e.Read("Network and history",()=>e.Network(running,rules,now));
            e.Read("Application logs",()=>{using(var db=new Sqlite(AppJournal.Filename,true)){
                var counts=db.Rows("SELECT module,level,COUNT(*) FROM app_log WHERE t>=? GROUP BY module,level",now-86400);
                var recent=db.Rows("SELECT t,module,operation,status FROM app_log WHERE t>=? AND level>=2 ORDER BY id DESC LIMIT 30",now-86400);
                e.Exact("24h application logs (module,level,count)",counts);
                e.Fact("module-log-counts",new {windowHours=24,columns="module,level (0 Debug to 3 Error),count",rows=counts});
                e.Fact("warning-error-sample",new {columns="unixTime,module,operation,httpStatus",rows=recent});
            }});
            return e;
        }
    }
}
