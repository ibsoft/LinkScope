using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace LinkScope {
    public sealed class HealthAlert {
        public string Id {get;set;} public string Key {get;set;} public string Category {get;set;}
        public string Severity {get;set;} public string Title {get;set;} public string Message {get;set;} public string Revision {get;set;}
        public long Since {get;set;} public bool Read {get;set;} public bool Resolved {get;set;}
        internal long Sequence;
        internal long? Ended;
        internal object View(bool showRead){return new {id=Id,sequence=Sequence,category=Category,severity=Severity,title=Title,message=Message,sinceUtc=Telemetry.Utc(Since),resolved=Resolved,resolvedUtc=Ended.HasValue?Telemetry.Utc(Ended.Value):null,read=showRead?(bool?)Read:null};}
    }
    internal sealed class Alerts {
        readonly string database;
        readonly Dictionary<string,HealthAlert> current;
        internal DeliverySettings Policy=new DeliverySettings();
        internal event Action OutputChanged;
        void Changed(){var handler=OutputChanged;if(handler!=null)handler();}
        internal const string Columns="seq,id,alert_key,category,severity,title,message,revision,since,is_read,resolved,ended";
        const int PageSize=50;
        internal Alerts():this(Config.Db,Path.Combine(Config.Data,"alert-state.json")){}
        internal Alerts(string dbPath,string legacyFile){
            database=dbPath;
            using(var db=Open()){
                db.Exec("PRAGMA journal_mode=WAL");
                db.Exec("BEGIN IMMEDIATE");
                try{
                    db.Exec("CREATE TABLE IF NOT EXISTS alert_events(seq INTEGER PRIMARY KEY,id TEXT NOT NULL UNIQUE,alert_key TEXT NOT NULL,category TEXT NOT NULL,severity TEXT NOT NULL,title TEXT NOT NULL,message TEXT NOT NULL,revision TEXT,since INTEGER NOT NULL,is_read INTEGER NOT NULL,resolved INTEGER NOT NULL,ended INTEGER)");
                    db.Exec("CREATE TABLE IF NOT EXISTS alert_sequence(singleton INTEGER PRIMARY KEY CHECK(singleton=1),last_seq INTEGER NOT NULL)");
                    db.Exec("INSERT OR IGNORE INTO alert_sequence SELECT 1,COALESCE(MAX(seq),0) FROM alert_events");
                    db.Exec("UPDATE alert_sequence SET last_seq=MAX(last_seq,(SELECT COALESCE(MAX(seq),0) FROM alert_events)) WHERE singleton=1");
                    db.Exec("CREATE INDEX IF NOT EXISTS alerts_by_read ON alert_events(is_read,seq)");
                    db.Exec("CREATE INDEX IF NOT EXISTS alerts_open ON alert_events(resolved,alert_key)");
                    db.Exec("CREATE TABLE IF NOT EXISTS alert_search_index(seq INTEGER PRIMARY KEY,words TEXT NOT NULL)");
                    db.Exec("CREATE INDEX IF NOT EXISTS alerts_by_category ON alert_events(category,seq)");
                    db.Exec("CREATE INDEX IF NOT EXISTS alerts_by_start ON alert_events(since,seq)");
                    AlertDelivery.Init(db);
                    db.Exec("CREATE TABLE IF NOT EXISTS alert_migrations(name TEXT PRIMARY KEY)");
                    if(db.Rows("SELECT 1 FROM alert_migrations WHERE name='json-v1'").Count==0){
                        if(File.Exists(legacyFile)){
                            var legacy=Config.Json().Deserialize<Dictionary<string,HealthAlert>>(File.ReadAllText(legacyFile));
                            foreach(var a in legacy.Values.OrderBy(x=>x.Since).ThenBy(x=>x.Id,StringComparer.Ordinal))Insert(db,a);
                        }
                        db.Exec("INSERT INTO alert_migrations VALUES('json-v1')");
                    }
                    AlertSearch.Migrate(db);
                    current=db.Rows("SELECT "+Columns+" FROM alert_events WHERE resolved=0").Select(FromRow).ToDictionary(a=>a.Key);
                    db.Exec("COMMIT");
                }catch{db.Exec("ROLLBACK");throw;}
            }
        }
        Sqlite Open(){return new Sqlite(database,false);}
        internal static HealthAlert FromRow(object[] r){
            return new HealthAlert{Sequence=(long)r[0],Id=(string)r[1],Key=(string)r[2],Category=(string)r[3],Severity=(string)r[4],
                Title=(string)r[5],Message=(string)r[6],Revision=(string)r[7],Since=(long)r[8],Read=(long)r[9]!=0,Resolved=(long)r[10]!=0,Ended=(long?)r[11]};
        }
        static void Insert(Sqlite db,HealthAlert a){
            db.Exec("UPDATE alert_sequence SET last_seq=last_seq+1 WHERE singleton=1");
            a.Sequence=Head(db);
            db.Exec("INSERT INTO alert_events(seq,id,alert_key,category,severity,title,message,revision,since,is_read,resolved,ended) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                a.Sequence,a.Id,a.Key,a.Category,a.Severity,a.Title,a.Message,a.Revision,a.Since,a.Read,a.Resolved,a.Ended);
            AlertSearch.Index(db,a);
        }
        static HealthAlert Signal(string cat,string key,string severity,string title,string message,string revision=""){
            return new HealthAlert{Category=cat,Key=cat+"/"+key,Severity=severity,Title=title,Message=message,Revision=revision};
        }
        internal object[] List(IEnumerable<string> categories,bool showRead){
            lock(this)return current.Values.Where(a=>categories.Contains(a.Category)).OrderBy(a=>a.Severity=="critical"?0:1).ThenByDescending(a=>a.Since).Select(a=>a.View(showRead)).ToArray();
        }
        static long Head(Sqlite db){return (long)db.Rows("SELECT last_seq FROM alert_sequence WHERE singleton=1")[0][0];}
        static long Unread(Sqlite db){return (long)db.Rows("SELECT COUNT(*) FROM alert_events WHERE is_read=0")[0][0];}
        // Header count is a best-effort snapshot; a database read failure must not block navigation.
        internal long? HeaderUnread(){try{lock(this)using(var db=new Sqlite(database,true))return Unread(db);}catch(Exception){return null;}}
        internal object Page(long before){
            lock(this)using(var db=new Sqlite(database,true)){
                var rows=(before==0?db.Rows("SELECT "+Columns+" FROM alert_events ORDER BY seq DESC LIMIT ?",PageSize+1):
                    db.Rows("SELECT "+Columns+" FROM alert_events WHERE seq<? ORDER BY seq DESC LIMIT ?",before,PageSize+1)).Select(FromRow).ToList();
                return new {alerts=rows.Take(PageSize).Select(a=>a.View(true)).ToArray(),more=rows.Count>PageSize,through=Head(db),unread=Unread(db)};
            }
        }
        internal object Feed(long? after){
            lock(this)using(var db=new Sqlite(database,true)){
                long head=Head(db);
                // A fresh tab shows recent notices. Later polls catch up in order, including short-lived incidents.
                var rows=after.HasValue?db.Rows("SELECT "+Columns+" FROM alert_events WHERE is_read=0 AND seq>? ORDER BY seq LIMIT 51",after.Value):
                    db.Rows("SELECT "+Columns+" FROM alert_events WHERE is_read=0 ORDER BY seq DESC LIMIT 3");
                bool more=rows.Count>50;
                var events=rows.Take(50).Select(FromRow).ToList();
                if(!after.HasValue)events.Reverse();
                return new {alerts=events.Select(a=>a.View(true)).ToArray(),cursor=more?events.Last().Sequence:head,more=more,unread=Unread(db)};
            }
        }
        internal void Read(string id){
            lock(this)using(var db=Open()){
                db.Exec("UPDATE alert_events SET is_read=1 WHERE id=? AND is_read=0",id);
                foreach(var a in current.Values)if(a.Id==id){a.Read=true;break;}
                Changed();
            }
        }
        internal void ReadAll(long through){
            lock(this)using(var db=Open()){
                db.Exec("UPDATE alert_events SET is_read=1 WHERE seq<=? AND is_read=0",through);
                foreach(var a in current.Values)if(a.Sequence<=through)a.Read=true;
                Changed();
            }
        }
        static object EndpointAckState(Sqlite db){
            var row=db.Rows("SELECT COALESCE(MAX(seq),0),COALESCE(SUM(CASE WHEN is_read=0 THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN is_read=0 AND resolved=0 THEN 1 ELSE 0 END),0) FROM alert_events WHERE category='endpoint_protection'")[0];
            return new {through=Convert.ToInt64(row[0]),unread=Convert.ToInt64(row[1]),activeUnread=Convert.ToInt64(row[2])};
        }
        internal object EndpointAcknowledgement(){lock(this)using(var db=new Sqlite(database,true))return EndpointAckState(db);}
        internal object ReadEndpointThrough(long through){
            lock(this)using(var db=Open()){
                if(through<0||through>Head(db))throw new HttpError(400,"Invalid endpoint acknowledgement cursor.");
                db.Exec("UPDATE alert_events SET is_read=1 WHERE category='endpoint_protection' AND seq<=? AND is_read=0",through);
                foreach(var a in current.Values)if(a.Category=="endpoint_protection"&&a.Sequence<=through)a.Read=true;
                Changed();return EndpointAckState(db);
            }
        }
        internal void Trim(string[] categories){
            lock(this)foreach(string cat in current.Values.Select(a=>a.Category).Except(categories).ToArray())Update(cat,new List<HealthAlert>());
        }
        void Update(string cat,List<HealthAlert> signals){
            lock(this){
                var live=new HashSet<string>(signals.Select(a=>a.Key));
                var closed=current.Values.Where(a=>a.Category==cat&&!live.Contains(a.Key)).ToList();
                var added=new List<HealthAlert>();
                var refreshed=new List<HealthAlert>();
                long now=History.Now();
                foreach(var a in signals){
                    HealthAlert old;
                    if(current.TryGetValue(a.Key,out old)&&a.Revision==old.Revision&&a.Severity==old.Severity){
                        if(a.Title==old.Title&&a.Message==old.Message)continue;
                        a.Id=old.Id;a.Sequence=old.Sequence;a.Since=old.Since;a.Read=old.Read;
                        refreshed.Add(a);
                    }else{
                        if(old!=null)closed.Add(old);
                        a.Id=Guid.NewGuid().ToString("N");a.Since=now;added.Add(a);
                    }
                }
                if(closed.Count+added.Count+refreshed.Count==0)return;
                using(var db=Open()){
                    db.Exec("BEGIN IMMEDIATE");
                    try{
                        foreach(var a in closed){
                            db.Exec("UPDATE alert_events SET resolved=1,ended=? WHERE id=?",now,a.Id);
                            if(Policy.EmailEnabled&&Policy.EmailRecovery)AlertDelivery.Queue(db,a,true,now);
                        }
                        foreach(var a in refreshed){
                            db.Exec("UPDATE alert_events SET title=?,message=? WHERE id=?",a.Title,a.Message,a.Id);
                            AlertSearch.Index(db,a);
                        }
                        foreach(var a in added){
                            Insert(db,a);
                            if(Policy.EmailEnabled)AlertDelivery.Queue(db,a,false,now);
                        }
                        db.Exec("COMMIT");
                    }catch{db.Exec("ROLLBACK");throw;}
                }
                foreach(var a in closed)AppJournal.Event(LogLevel.Info,"Alerts","resolve",a.Category+" alert "+a.Id+" resolved.");
                foreach(var a in added)AppJournal.Event(LogLevel.Warning,"Alerts","open",a.Category+" alert "+a.Id+" opened.");
                foreach(var a in closed)current.Remove(a.Key);
                foreach(var a in refreshed.Concat(added))current[a.Key]=a;
                Changed();
            }
        }
        // Apply durable endpoint transitions independently of the bounded dashboard snapshot.
        // The cursor and central alerts are committed together; a crash can replay safely.
        internal void EndpointTransitions(string stream,List<object[]> events,Config cfg){
            lock(this){var changed=new Dictionary<string,HealthAlert>();var opened=new List<HealthAlert>();var closed=new List<HealthAlert>();
                using(var db=Open()){
                    db.Exec("CREATE TABLE IF NOT EXISTS endpoint_delivery_cursor(stream TEXT PRIMARY KEY,seq INTEGER NOT NULL)");
                    db.Exec("BEGIN IMMEDIATE");try{
                        var saved=db.Rows("SELECT seq FROM endpoint_delivery_cursor WHERE stream=?",stream);long through=saved.Count==0?0:Convert.ToInt64(saved[0][0]);
                        foreach(var e in events){long seq=Convert.ToInt64(e[0]);if(seq<=through)continue;string key="endpoint_protection/"+(string)e[2];HealthAlert old;
                            if(!changed.TryGetValue(key,out old))current.TryGetValue(key,out old);
                            long utc=Convert.ToInt64(e[1]);bool active=Convert.ToInt64(e[8])!=0;
                            if(old!=null){db.Exec("UPDATE alert_events SET resolved=1,ended=? WHERE id=?",utc,old.Id);if(Policy.EmailEnabled&&Policy.EmailRecovery)AlertDelivery.Queue(db,old,true,utc);closed.Add(old);}
                            if(active){string message=(string)e[3]+" · "+(string)e[6]+(string.IsNullOrEmpty((string)e[7])?"":" · SHA-256: "+(string)e[7]);var alert=Signal("endpoint_protection",(string)e[2],(string)e[5],(string)e[4],message,stream+":"+seq);alert.Id=Guid.NewGuid().ToString("N");alert.Since=utc;Insert(db,alert);if(Policy.EmailEnabled)AlertDelivery.Queue(db,alert,false,utc);changed[key]=alert;opened.Add(alert);}else changed[key]=null;through=seq;
                        }
                        db.Exec("INSERT OR REPLACE INTO endpoint_delivery_cursor VALUES(?,?)",stream,through);db.Exec("COMMIT");
                    }catch{db.Exec("ROLLBACK");throw;}
                }
                foreach(var x in changed){if(x.Value==null)current.Remove(x.Key);else current[x.Key]=x.Value;}
                foreach(var a in closed)AppJournal.Event(LogLevel.Info,"Endpoint","resolve",a.Title+" · "+a.Message);
                foreach(var a in opened){var level=a.Severity=="critical"?LogLevel.Error:a.Severity=="warning"?LogLevel.Warning:LogLevel.Info;AppJournal.Event(level,"Endpoint",a.Title,a.Message);if(cfg.Endpoint.WriteEvents)try{System.Diagnostics.EventLog.WriteEntry("Unixfor LinkScope",a.Title+" · "+a.Message,a.Severity=="critical"?System.Diagnostics.EventLogEntryType.Error:a.Severity=="warning"?System.Diagnostics.EventLogEntryType.Warning:System.Diagnostics.EventLogEntryType.Information,4201);}catch(Exception ex){AppJournal.Fault("Endpoint","event-log",ex);}}
                if(changed.Count>0)Changed();
            }
        }
        // The endpoint database is the source of truth for active findings. Keep
        // coverage/limit notices under Sample, and preserve the history/read flags.
        internal void ReconcileEndpointFindings(HashSet<string> activeIds){
            const string cat="endpoint_protection",prefix=cat+"/";
            lock(this){
                var live=current.Values.Where(a=>a.Category==cat&&(a.Key==prefix+"coverage"||a.Key==prefix+"limit"||(a.Key.StartsWith(prefix,StringComparison.Ordinal)&&activeIds.Contains(a.Key.Substring(prefix.Length))))).ToList();
                Update(cat,live);
            }
        }
        static Dictionary<string,object> Map(object v){return v as Dictionary<string,object>??new Dictionary<string,object>();}
        static object Field(Dictionary<string,object> o,string key){object v;return o.TryGetValue(key,out v)?v:null;}
        static string S(Dictionary<string,object> o,string key){return Convert.ToString(Field(o,key),System.Globalization.CultureInfo.InvariantCulture);}
        static IEnumerable<Dictionary<string,object>> Rows(Dictionary<string,object> o,string key="items"){
            var a=Field(o,key) as IEnumerable;return a==null?Enumerable.Empty<Dictionary<string,object>>():a.Cast<object>().Select(Map);}
        internal void Sample(string cat,object result,Config cfg){
            var value=result as Dictionary<string,object>??Map(Config.Json().DeserializeObject(Config.Json().Serialize(result)));
            var list=new List<HealthAlert>();string status=S(value,"status");
            string sampleModule=cat=="security"?"Security":cat=="smart"?"SMART":Config.Extras.Contains(cat)?"Inventory":"Health";
            AppJournal.Event(status=="unavailable"||status=="partial"?LogLevel.Warning:LogLevel.Debug,sampleModule,cat,
                status=="unavailable"?"Collection unavailable.":status=="partial"?"Partial collection.":"Collection completed.");
            AppJournal.Event(LogLevel.Debug,"Alerts","evaluate","Evaluated "+cat+" alert rules.");
            if(status=="warming_up")return;
            if(status=="unavailable"||status=="partial")list.Add(Signal(cat,"coverage","warning",cat+" coverage is "+status,"Check the Windows provider, driver or access permissions."));
            if(S(value,"truncated")=="True")list.Add(Signal(cat,"limit","info",cat+" inventory limit reached",cat=="endpoint_protection"?"Dashboard snapshot is limited; durable incidents continue through the alert queue.":"The response contains the first 256 records."));
            if(cat=="endpoint_protection"){
                // The endpoint worker publishes every durable finding transition, including ones
                // outside the display cap. Sampling may update only the coverage/limit notices.
                lock(this){list.AddRange(current.Values.Where(x=>x.Category==cat&&x.Key!=cat+"/coverage"&&x.Key!=cat+"/limit"));Update(cat,list);}return;
            }
            if(cat=="data_integrity"){
                lock(this){
                    foreach(var item in Rows(value)){
                        string id=S(item,"id"),severity=S(item,"severity"),title=S(item,"change"),message=S(item,"path")+" · "+S(item,"detail")+" Expected: "+S(item,"expectedHash")+" Actual: "+S(item,"actualHash");
                        var a=Signal(cat,id,severity,title,message,S(item,"actualHash"));list.Add(a);HealthAlert previous;
                        if(!current.TryGetValue(a.Key,out previous)||previous.Revision!=a.Revision||previous.Severity!=a.Severity){
                            AppJournal.Event(severity=="critical"?LogLevel.Error:LogLevel.Warning,cat=="data_integrity"?"Integrity":"Endpoint",title,message);
                            if(cat=="data_integrity"?cfg.Integrity.WriteEvents:cfg.Endpoint.WriteEvents)try{System.Diagnostics.EventLog.WriteEntry("Unixfor LinkScope",title+" · "+message,severity=="critical"?System.Diagnostics.EventLogEntryType.Error:System.Diagnostics.EventLogEntryType.Warning,4201);}catch(Exception ex){AppJournal.Fault("Integrity","event-log",ex);}
                        }
                    }
                    if(status=="unavailable"||status=="partial")list.AddRange(current.Values.Where(x=>x.Category==cat&&!list.Any(y=>y.Key==x.Key)));
                    Update(cat,list);
                }return;
            }
            if(cat=="cpu"||cat=="ram")Usage(list,cat,cat.ToUpperInvariant(),value,cat=="cpu"?cfg.CpuAlertPercent:cfg.RamAlertPercent);
            if(cat=="disk_usage")foreach(var d in Rows(value)){
                if(S(d,"status")=="unavailable")list.Add(Signal(cat,"unavailable-"+S(d,"volume"),"warning","Volume data unavailable",S(d,"volume")));
                else Usage(list,cat,S(d,"volume"),d,cfg.DiskAlertPercent);
            }
            if(cat=="smart")foreach(var d in Rows(value)){
                string decision=S(d,"recommendation"),title=S(d,"headline");
                if(decision=="normal")continue;
                var findings=Field(d,"findings") as IEnumerable;
                string reason=findings==null?S(d,"advice"):string.Join(" ",findings.Cast<object>().Select(x=>Convert.ToString(x)).Take(2));
                list.Add(Signal(cat,S(d,"diskId"),decision=="replace"?"critical":"warning",S(d,"model")+" · "+title,reason,title));
            }
            if(cat=="events"||cat=="event_details")foreach(var group in Rows(value)){
                string channel=S(group,"channel");
                if(S(group,"status")=="unavailable")list.Add(Signal(cat,channel+"/coverage","warning","Event channel unavailable",channel));
                // Event messages are another view of the same records. Raise one alert per channel and level.
                if(cat!="events")continue;
                foreach(var level in Rows(group).GroupBy(e=>S(e,"level"))){
                    var first=level.First();string severity=level.Key=="Critical"?"critical":level.Key=="Error"?"error":"warning";
                    list.Add(Signal(cat,channel+"/"+level.Key,severity,channel+" · "+level.Key,level.Count()+" in the returned 24-hour window. Latest: "+S(first,"provider")+" #"+S(first,"eventId"),S(first,"recordId")+"@"+S(first,"utc")));}
            }
            if(cat=="security"){
                lock(this){
                    foreach(var item in Rows(value)){
                        string key=S(item,"control"),state=S(item,"state");
                        if(!SecurityPosture.Controls.Contains(key))continue;
                        if(state=="disabled")list.Add(Signal(cat,key,"warning",key+" needs review",S(item,"detail")));
                        else if(state=="unavailable"){HealthAlert old;if(current.TryGetValue("security/"+key,out old))list.Add(old);}
                    }
                    if(status=="unavailable")list.AddRange(current.Values.Where(x=>x.Category==cat&&!list.Any(y=>y.Key==x.Key)));
                    Update(cat,list);
                }
                return;
            }
            if(cat=="firewall")foreach(var p in Rows(value))if(string.Equals(S(p,"enabled"),"False",StringComparison.OrdinalIgnoreCase))
                list.Add(Signal(cat,S(p,"profile"),"critical","Firewall disabled · "+S(p,"profile"),"Windows reports that this firewall profile is disabled."));
            if(cat=="antivirus"){
                string wsc=S(value,"windowsSecurityCenter");
                if(wsc=="poor"||wsc=="snoozed")list.Add(Signal(cat,"wsc","critical","Antivirus protection needs attention","Windows Security Center reports "+wsc+".",wsc));
                foreach(var item in Rows(value)){var defender=Map(Field(item,"defender"));
                    if(wsc!="good"&&!Rows(item,"registeredProducts").Any()&&(S(defender,"RealTimeProtectionEnabled")=="False"||S(defender,"AntivirusEnabled")=="False"))
                        list.Add(Signal(cat,"defender","warning","Defender protection is disabled","Check the active antivirus provider and real-time protection."));
                    int age;if(int.TryParse(S(defender,"AntivirusSignatureAge"),out age)&&age>=7&&S(defender,"AntivirusEnabled")=="True")
                        list.Add(Signal(cat,"definitions","warning","Antivirus definitions are out of date","Defender signature age: "+age+" days."));
                }
            }
            if(status=="unavailable"){ // Preserve unresolved safety alerts until a successful reading supersedes them.
                lock(this){list.AddRange(current.Values.Where(x=>x.Category==cat&&!x.Resolved&&!list.Any(y=>y.Key==x.Key)));Update(cat,list);}return;
            }Update(cat,list);
        }
        static void Usage(List<HealthAlert> list,string cat,string name,Dictionary<string,object> data,int limit){
            var v=Field(data,"usedPercent");if(v==null)return;double used=Convert.ToDouble(v);
            if(used>=limit)list.Add(Signal(cat,name,"warning",name+" usage is high",Math.Round(used,1)+"% used. Configured threshold: "+limit+"%."));
        }
        // Keep at most the largest configurable window. Local errors have no packet-loss observation.
        sealed class ProbeWindow {
            readonly bool[] losses=new bool[1000];
            int next,count;
            internal int Failures;
            internal void Add(Probe p){
                Failures=p.Status=="Success"?0:Math.Min(1000000,Failures+1);
                if(p.LocalError)return;
                losses[next]=!p.Rtt.HasValue;next=(next+1)%losses.Length;count=Math.Min(count+1,losses.Length);
            }
            internal int? Lost(int window){
                if(count<window)return null;
                int lost=0;
                for(int i=0;i<window;i++)if(losses[(next+losses.Length-1-i)%losses.Length])lost++;
                return lost;
            }
        }
        readonly Dictionary<string,ProbeWindow> windows=new Dictionary<string,ProbeWindow>();
        internal void RestoreProbeWindows(Sqlite db,Target[] targets){
            foreach(var t in targets){
                var window=new ProbeWindow();
                var rows=db.Rows("SELECT status,rtt FROM raw WHERE target=? ORDER BY t DESC,rowid DESC LIMIT 1000",t.Address);
                for(int i=rows.Count-1;i>=0;i--){
                    string status=(string)rows[i][0];
                    window.Add(new Probe{Status=status,Rtt=(long?)rows[i][1],LocalError=status.StartsWith("Probe error:",StringComparison.Ordinal)});
                }
                windows[t.Address]=window;
            }
        }
        void KeepActive(List<HealthAlert> list,string key){
            HealthAlert prior;if(current.TryGetValue("network/"+key,out prior))list.Add(prior);
        }
        internal void Probes(Probe[] probes,Config rules){
            lock(this){
                AppJournal.Event(LogLevel.Debug,"Alerts","probe-rules","Evaluated network probe rules.");
                var signals=new List<HealthAlert>();
                var targets=rules.Targets.ToDictionary(t=>t.Address);
                foreach(var p in probes){
                    ProbeWindow w;
                    if(!windows.TryGetValue(p.Address,out w))windows[p.Address]=w=new ProbeWindow();
                    w.Add(p);
                    Target t;if(!targets.TryGetValue(p.Address,out t)||!t.AlertsEnabled)continue;
                    string label=string.IsNullOrEmpty(t.Name)||t.Name==p.Address?p.Address:t.Name+" ("+p.Address+")";
                    // Immediate incidents are independent of the optional rolling-loss and consecutive-failure rules.
                    // A continuous run is one incident; a successful reply closes it so the next failure is new.
                    string lossIncident=p.Address+"/packet-loss-incident", timeoutIncident=p.Address+"/timeout-incident";
                    if(p.LocalError){
                        KeepActive(signals,lossIncident);KeepActive(signals,timeoutIncident);
                    }else{
                        if(!p.Rtt.HasValue && p.Status!="Success")
                            signals.Add(Signal("network",lossIncident,"warning","Packet loss detected · "+label,
                                "ICMP probe unanswered. Latest status: "+p.Status+"."));
                        if(p.Status=="TimedOut")
                            signals.Add(Signal("network",timeoutIncident,"warning","Network timeout · "+label,
                                "No ICMP reply before the configured timeout."));
                    }
                    int fails=t.FailureCount??rules.ProbeAlertCount;
                    if(fails>0&&w.Failures>=fails)signals.Add(Signal("network",p.Address,"error","Network probe failing · "+label,
                        w.Failures+" consecutive failed probes. Latest status: "+p.Status));
                    string latencyKey=p.Address+"/latency";
                    if(t.HighRttMs.HasValue){
                        if(p.Rtt>=t.HighRttMs.Value)signals.Add(Signal("network",latencyKey,"warning","High round-trip latency · "+label,
                            p.Rtt+" ms. Configured threshold: "+t.HighRttMs+" ms."));
                        else if(!p.Rtt.HasValue)KeepActive(signals,latencyKey);
                    }
                    if(t.LossPercent.HasValue){
                        string key=p.Address+"/loss";int n=t.LossWindowProbes;
                        int? lost=w.Lost(n);
                        if(!lost.HasValue)KeepActive(signals,key);
                        else if(100*lost.Value>=t.LossPercent.Value*n)signals.Add(Signal("network",key,"warning","High packet loss · "+label,
                            lost+" of "+n+" probes unanswered ("+Math.Round(100.0*lost.Value/n,1)+"%). Configured threshold: "+t.LossPercent+"%."));
                    }
                }
                Update("network",signals);
            }
        }
    }
}
