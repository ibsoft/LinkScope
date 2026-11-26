using System;
using System.IO;
using System.Threading;

namespace LinkScope {
    public sealed class DatabaseMaintenanceSettings {
        public bool Enabled {get;set;}
        public int Age {get;set;}
        public string Unit {get;set;}
        public bool KeepLatestMonth {get;set;}
        public DatabaseMaintenanceSettings(){Age=1;Unit="years";KeepLatestMonth=true;}
        internal void Validate(){
            int max=Unit=="days"?3650:Unit=="months"?120:Unit=="years"?10:0;
            if(Age<1||Age>max)throw new InvalidDataException("Choose 1–3650 days, 1–120 months or 1–10 years for database maintenance.");
        }
        static DateTime Date(long now){return new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc).AddSeconds(now);}
        static long Stamp(DateTime date){return (long)(date-new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc)).TotalSeconds;}
        internal long Protect(long cutoff,long now){return KeepLatestMonth?Math.Min(cutoff,Stamp(Date(now).AddMonths(-1))):cutoff;}
        internal long Cutoff(long now){var d=Date(now);return Protect(Stamp(Unit=="days"?d.AddDays(-Age):Unit=="months"?d.AddMonths(-Age):d.AddYears(-Age)),now);}
        internal long LogCutoff(long now,int legacyDays){return Enabled?Cutoff(now):Protect(now-legacyDays*History.Day,now);}
    }
    internal sealed class DatabaseMaintenance:IDisposable {
        readonly object gate=new object();
        readonly ManualResetEvent stop=new ManualResetEvent(false);
        readonly AutoResetEvent wake=new AutoResetEvent(false);
        DatabaseMaintenanceSettings policy;
        Thread worker;
        string status="Not started",lastSuccess="";
        long historyDeleted,alertsDeleted,logsDeleted;
        bool busy,requested;
        internal DatabaseMaintenance(DatabaseMaintenanceSettings p){policy=p;}
        internal void Start(){worker=new Thread(Loop){IsBackground=true,Name="LinkScope database maintenance"};worker.Start();}
        internal void Update(DatabaseMaintenanceSettings p){lock(gate){if(policy.Enabled==p.Enabled&&policy.Age==p.Age&&policy.Unit==p.Unit&&policy.KeepLatestMonth==p.KeepLatestMonth)return;policy=p;status=p.Enabled?"Pending":"Disabled";}wake.Set();}
        internal bool Request(){lock(gate){if(!policy.Enabled||busy||requested)return false;requested=true;status="Pending";}wake.Set();return true;}
        internal object State(){lock(gate)return new {status=status,busy=busy||requested,lastSuccessUtc=lastSuccess,historyDeleted=historyDeleted,alertsDeleted=alertsDeleted,logsDeleted=logsDeleted,cutoffUtc=policy.Enabled?Telemetry.Utc(policy.Cutoff(History.Now())):""};}
        // Each transaction is limited to a small batch; no user-supplied identifiers or SQL.
        bool Batch(DatabaseMaintenanceSettings p,string file,string sql,long cutoff,ref long total,bool alertIndex=false){
            while(!stop.WaitOne(0)){
                lock(gate){
                    if(!ReferenceEquals(p,policy))return false;
                    using(var db=new Sqlite(file,false)){
                        db.Exec("BEGIN IMMEDIATE");
                        try{
                            if(alertIndex)db.Exec("DELETE FROM alert_search_index WHERE seq IN ("+sql+")",cutoff);
                            if(alertIndex)db.Exec("DELETE FROM alert_events WHERE seq IN ("+sql+")",cutoff);
                            else db.Exec(sql,cutoff);
                            long n=(long)db.Rows("SELECT changes()")[0][0];
                            db.Exec("COMMIT");total+=n;
                            if(n<2000)return true;
                        }catch{db.Exec("ROLLBACK");throw;}
                    }
                }
                if(stop.WaitOne(25))return false;
            }
            return false;
        }
        void Loop(){while(!stop.WaitOne(0)){
            DatabaseMaintenanceSettings p;
            lock(gate){p=policy;requested=false;busy=p.Enabled;status=p.Enabled?"Running":"Disabled";}
            if(!p.Enabled){WaitHandle.WaitAny(new WaitHandle[]{stop,wake});continue;}
            long h=0,a=0,l=0;bool complete=false;
            try{
                long cutoff=p.Cutoff(History.Now());
                complete=Batch(p,Config.Db,"DELETE FROM raw WHERE rowid IN (SELECT rowid FROM raw WHERE t<? ORDER BY t LIMIT 2000)",cutoff,ref h);
                foreach(string table in new[]{"ping_roll","traffic_roll","resource_roll"}){
                    string key=table=="ping_roll"?"target":table=="traffic_roll"?"nic":"metric";
                    // Preserve buckets that overlap the retention boundary.
                    if(complete)complete=Batch(p,Config.Db,"DELETE FROM "+table+" WHERE ("+key+",res,t) IN (SELECT "+key+",res,t FROM "+table+" WHERE t+res<=? LIMIT 2000)",cutoff,ref h);
                }
                if(complete)complete=Batch(p,Config.Db,"SELECT seq FROM alert_events WHERE resolved=1 AND COALESCE(ended,since)<? AND NOT EXISTS(SELECT 1 FROM alert_mail_queue q WHERE q.alert_id=alert_events.id) ORDER BY seq LIMIT 2000",cutoff,ref a,true);
                if(complete)complete=Batch(p,AppJournal.Filename,"DELETE FROM app_log WHERE id IN (SELECT id FROM app_log WHERE t<? ORDER BY t LIMIT 2000)",cutoff,ref l);
                lock(gate){if(ReferenceEquals(p,policy)){historyDeleted=h;alertsDeleted=a;logsDeleted=l;if(complete){lastSuccess=DateTime.UtcNow.ToString("o");status="Completed";}}busy=false;}
                if(complete)AppJournal.Event(LogLevel.Info,"Maintenance","database-cleanup","Deleted "+h+" history rows, "+a+" resolved alerts and "+l+" application logs.");
            }catch(Exception ex){lock(gate){busy=false;if(ReferenceEquals(p,policy)){status="Failed (some batches may have committed): "+ex.GetType().Name;historyDeleted=h;alertsDeleted=a;logsDeleted=l;}}AppJournal.Fault("Maintenance","database-cleanup",ex);}
            WaitHandle.WaitAny(new WaitHandle[]{stop,wake},3600000);
        }}
        public void Dispose(){stop.Set();if(worker!=null)worker.Join();stop.Dispose();wake.Dispose();}
    }
}
