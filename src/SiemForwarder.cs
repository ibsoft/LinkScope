using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace LinkScope {
    internal sealed class SiemPlan {
        internal readonly SiemSettings Settings;
        internal readonly string[] Routes;
        internal readonly LogLevel[] Levels;
        internal readonly int Days;
        readonly DatabaseMaintenanceSettings maintenance;
        internal long Cutoff(long now){return maintenance==null?now-Days*History.Day:maintenance.LogCutoff(now,Days);}
        internal SiemPlan(SiemSettings settings,int days,DatabaseMaintenanceSettings maintenancePolicy=null){
            maintenance=maintenancePolicy;
            Settings=settings;Days=days;Routes=SiemSettings.Kinds.Select(settings.Route).ToArray();
            Levels=SiemSettings.Kinds.Select(settings.Minimum).ToArray();
        }
    }
    internal sealed class SiemForwarder:IDisposable {
        sealed class Worker {
            internal readonly string Name;
            internal readonly int Index;
            internal readonly AutoResetEvent Ready=new AutoResetEvent(false),Changed=new AutoResetEvent(false);
            internal Thread Thread;
            internal string Status="Disabled.";
            internal Worker(string name,int index){Name=name;Index=index;}
        }
        readonly Worker[] workers=SiemSettings.Kinds.Select((name,i)=>new Worker(name,i)).ToArray();
        readonly string path,origin;
        readonly Action<string,string> warn;
        readonly CancellationToken stop;
        readonly object gate=new object();
        volatile SiemPlan current;
        internal SiemForwarder(string path,CancellationToken stop,Action<string,string> warn){
            this.path=path;this.stop=stop;this.warn=warn;
            using(var db=new Sqlite(path,false)){
                db.Exec("CREATE TABLE IF NOT EXISTS siem_origin(id INTEGER PRIMARY KEY, value TEXT NOT NULL)");
                db.Exec("INSERT OR IGNORE INTO siem_origin VALUES(1,?)",Guid.NewGuid().ToString("N"));
                origin=(string)db.Rows("SELECT value FROM siem_origin WHERE id=1")[0][0];
                db.Exec("CREATE TABLE IF NOT EXISTS siem_queue(receiver TEXT NOT NULL, log_id INTEGER NOT NULL, route TEXT NOT NULL, PRIMARY KEY(receiver,log_id)) WITHOUT ROWID");
                db.Exec("CREATE TRIGGER IF NOT EXISTS prune_siem AFTER DELETE ON app_log BEGIN DELETE FROM siem_queue WHERE log_id=OLD.id; END");
                db.Exec("CREATE INDEX IF NOT EXISTS siem_by_log ON siem_queue(log_id)");
            }
        }
        internal void Configure(SiemPlan plan){
            lock(gate)using(var db=new Sqlite(path,false)){
                var prior=current;db.Exec("BEGIN IMMEDIATE");
                foreach(var w in workers){
                    if(prior==null||prior.Routes[w.Index]!=plan.Routes[w.Index])
                        db.Exec("DELETE FROM siem_queue WHERE receiver=? AND route<>?",w.Name,plan.Routes[w.Index]);
                }
                db.Exec("COMMIT");current=plan;
                foreach(var w in workers){
                    if(prior==null||prior.Routes[w.Index]!=plan.Routes[w.Index])
                        w.Status=plan.Routes[w.Index]==""?"Disabled.":"Waiting for events.";
                    w.Changed.Set();w.Ready.Set();
                }
            }
        }
        internal void Start(){
            foreach(var w in workers){var worker=w;w.Thread=new Thread(delegate(){Run(worker);}){IsBackground=true,Name="LinkScope "+w.Name+" logs"};w.Thread.Start();}
        }
        internal static bool Queue(Sqlite db,LogLevel level,SiemPlan captured,SiemPlan active){
            if(captured==null)return false;
            bool pending=false;
            for(int i=0;i<SiemSettings.Kinds.Length;i++){
                string route=captured.Routes[i];
                if(route==""||route!=active.Routes[i]||level<captured.Levels[i])continue;
                // The queue is WITHOUT ROWID, so last_insert_rowid() stays on the app_log INSERT.
                db.Exec("INSERT INTO siem_queue(receiver,log_id,route) VALUES(?,last_insert_rowid(),?)",SiemSettings.Kinds[i],route);
                pending=true;
            }
            return pending;
        }
        internal string QueueTest(Sqlite db,string receiver){
            int i=Array.IndexOf(SiemSettings.Kinds,receiver);
            if(i<0)throw new InvalidDataException("Unknown SIEM receiver.");
            string route=current.Routes[i];if(route=="")throw new InvalidDataException("Enable this receiver and save settings before testing.");
            db.Exec("INSERT INTO siem_queue(receiver,log_id,route) VALUES(?,last_insert_rowid(),?)",receiver,route);
            return origin+"-"+db.Rows("SELECT last_insert_rowid()")[0][0];
        }
        internal void Wake(){foreach(var w in workers)if(current.Routes[w.Index]!="")w.Ready.Set();}
        internal object State(){lock(gate)return workers.ToDictionary(w=>w.Name,w=>w.Status);}
        void Run(Worker w){
            int delay=1;
            while(!stop.IsCancellationRequested){
                var p=current;string route=p.Routes[w.Index];
                try{
                    if(route!=""){
                        List<object[]> rows;
                        using(var db=new Sqlite(path,true))rows=db.Rows("SELECT a.id,a.t,a.level,a.module,a.operation,a.message,a.peer,a.status,a.elapsed FROM siem_queue q JOIN app_log a ON a.id=q.log_id WHERE q.receiver=? AND q.route=? AND a.t>=? ORDER BY q.log_id LIMIT 64",w.Name,route,p.Cutoff(History.Now()));
                        if(rows.Count>0&&current.Routes[w.Index]==route){
                            var result=SiemSender.Send(w.Name,p.Settings,origin,rows,stop);
                            using(var db=new Sqlite(path,false)){
                                db.Exec("BEGIN IMMEDIATE");
                                foreach(long id in result.Accepted)db.Exec("DELETE FROM siem_queue WHERE receiver=? AND route=? AND log_id=?",w.Name,route,id);
                                db.Exec("COMMIT");
                            }
                            if(result.Problem!="")throw new InvalidDataException(result.Problem);
                            lock(gate)if(current.Routes[w.Index]==route)w.Status=(w.Name=="Wazuh"?"Last sent":"Last accepted")+" at "+Telemetry.Utc(History.Now())+" · "+rows.Count+" events.";
                            delay=1;continue;
                        }
                    }
                    WaitHandle.WaitAny(new WaitHandle[]{stop.WaitHandle,w.Ready},30000);
                }catch(Exception ex){
                    if(stop.IsCancellationRequested)break;
                    string issue=(ex is InvalidDataException?ex.Message:"Delivery failed ("+ex.GetBaseException().GetType().Name+").")+" Retrying.";
                    lock(gate){
                        if(current.Routes[w.Index]!=route){delay=1;continue;}
                        if(w.Status!=issue)warn(w.Name,issue);
                        w.Status=issue;
                    }
                    WaitHandle.WaitAny(new WaitHandle[]{stop.WaitHandle,w.Changed},delay*1000);delay=Math.Min(60,delay*2);
                }
            }
        }
        public void Dispose(){foreach(var w in workers){if(w.Thread!=null)w.Thread.Join();w.Ready.Dispose();w.Changed.Dispose();}}
    }
}
