using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace LinkScope {
    internal sealed class AiEvidence {
        readonly List<string> records=new List<string>();
        internal readonly List<string> Sources=new List<string>();
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
        static readonly HashSet<string> Omit=new HashSet<string>(StringComparer.OrdinalIgnoreCase){"serial","MACAddress","message","diagnostics","reason","description","commandline","password","apikey","protectedkey","token","secret"};
        static object Safe(object x,int depth){
            if(x==null||depth>7)return null;
            var d=x as Dictionary<string,object>;
            if(d!=null)return d.Where(k=>!Omit.Contains(k.Key)).ToDictionary(k=>k.Key,k=>Safe(k.Value,depth+1));
            if(x is string){string s=(string)x;return s.Length>320?s.Substring(0,320):s;}
            if(x is IEnumerable){var a=AiProvider.List(x);return a.Length<=24?(object)a.Select(i=>Safe(i,depth+1)).ToArray():new {count=a.Length,sample=a.Take(24).Select(i=>Safe(i,depth+1)).ToArray()};}
            return x;
        }
        void Health(Telemetry monitor,Config cfg){
            var json=Config.Json();
            var snap=json.DeserializeObject(json.Serialize(monitor.Snapshot(cfg.Categories())));
            var cats=AiProvider.Map(AiProvider.Get(snap,"categories"));Categories=cats.Count;
            foreach(var c in cats){
                var wrapper=AiProvider.Map(c.Value);var result=AiProvider.Map(AiProvider.Get(wrapper,"result"));
                string state=Convert.ToString(AiProvider.Get(wrapper,"status")??AiProvider.Get(result,"status"));
                if(state=="collecting"||state=="partial"||state=="unavailable"||Equals(AiProvider.Get(wrapper,"stale"),true))
                    Missing.Add(c.Key+" ("+(Equals(AiProvider.Get(wrapper,"stale"),true)?"stale":state)+")");
                var items=AiProvider.List(AiProvider.Get(result,"items"));var fields=result.Where(k=>k.Key!="items").ToDictionary(k=>k.Key,k=>k.Value);
                Fact(c.Key,new {status=AiProvider.Get(wrapper,"status")??AiProvider.Get(result,"status"),collectedUtc=AiProvider.Get(wrapper,"collectedUtc"),
                    ageSeconds=AiProvider.Get(wrapper,"ageSeconds"),stale=AiProvider.Get(wrapper,"stale"),details=Safe(fields,0),itemCount=items.Length});
                foreach(var item in items){
                    var row=AiProvider.Map(item);
                    if(c.Key=="smart"){
                        var attrs=AiProvider.List(AiProvider.Get(item,"attributes"));
                        Fact("smart",Safe(row.Where(k=>k.Key!="attributes").ToDictionary(k=>k.Key,k=>k.Value),0));
                        var flagged=attrs.Where(a=>new[]{"FAIL","REVIEW"}.Contains(AiProvider.Text(a,"state"))).ToArray();
                        foreach(var a in flagged)Fact("smart-attribute",new {disk=AiProvider.Get(row,"diskId"),attribute=Safe(a,0)});
                        Fact("smart-counts",new {disk=AiProvider.Get(row,"diskId"),attributes=attrs.Length,flagged=flagged.Length});
                    }else if(c.Key=="events"||c.Key=="event_details"){
                        var events=AiProvider.List(AiProvider.Get(row,"items"));
                        Fact(c.Key,new {channel=AiProvider.Get(row,"channel"),status=AiProvider.Get(row,"status"),truncated=AiProvider.Get(row,"truncated"),
                            total=events.Length,byLevel=events.GroupBy(v=>AiProvider.Text(v,"level")).Select(g=>new {level=g.Key,count=g.Count()}),
                            byProviderAndId=events.GroupBy(v=>AiProvider.Text(v,"provider")+" #"+AiProvider.Get(v,"eventId")).Select(g=>new {eventType=g.Key,count=g.Count()}),recent=events.Take(12).Select(v=>Safe(v,0))});
                    }else Fact(c.Key,Safe(item,0));
                }
            }
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
                    var rates=db.Rows("SELECT nic,ROUND(SUM(rx)/NULLIF(SUM(seconds),0),2),ROUND(SUM(tx)/NULLIF(SUM(seconds),0),2) FROM traffic_roll WHERE res=? AND t BETWEEN ? AND ? GROUP BY nic",res,since,now);
                    Fact("traffic-history",new {days=days,columns="adapter,meanRxBytesPerSecond,meanTxBytesPerSecond",rows=rates});
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
                Fact("alert-counts",new {columns="category,severity,resolved,count",scope="all active plus openings in 24 hours",rows=counts});
                foreach(var row in db.Rows("SELECT id,category,severity,title,since FROM alert_events WHERE resolved=0 ORDER BY seq DESC"))
                    Fact("active-alert",new {id=row[0],category=row[1],severity=row[2],title=row[3],openedUnix=row[4]});
                foreach(var row in db.Rows("SELECT id,category,severity,title,since,ended FROM alert_events WHERE resolved=1 ORDER BY seq DESC LIMIT 60"))
                    Fact("recent-recovery",new {id=row[0],category=row[1],severity=row[2],title=row[3],openedUnix=row[4],endedUnix=row[5]});
                db.Exec("COMMIT");
            }
        }
        internal static AiEvidence Collect(Telemetry monitor,Config running,Config rules){
            long now=History.Now();var e=new AiEvidence{Utc=Telemetry.Utc(now)};
            e.Fact("monitor",new {host=Environment.MachineName,utc=e.Utc,cpuAlertPercent=rules.CpuAlertPercent,ramAlertPercent=rules.RamAlertPercent,diskAlertPercent=rules.DiskAlertPercent,lowLifePercent=rules.LowLifePercent});
            e.Read("Windows health",()=>e.Health(monitor,rules));
            e.Read("Network and history",()=>e.Network(running,rules,now));
            e.Read("Application logs",()=>{using(var db=new Sqlite(AppJournal.Filename,true)){
                var counts=db.Rows("SELECT module,level,COUNT(*) FROM app_log WHERE t>=? GROUP BY module,level",now-86400);
                var recent=db.Rows("SELECT t,module,operation,message,peer,status FROM app_log WHERE t>=? AND level>=2 ORDER BY id DESC LIMIT 30",now-86400);
                e.Fact("module-log-counts",new {windowHours=24,columns="module,level (0 Debug to 3 Error),count",rows=counts});
                e.Fact("warning-error-sample",new {columns="unixTime,module,operation,message,peer,httpStatus",rows=recent});
            }});
            return e;
        }
    }
}
