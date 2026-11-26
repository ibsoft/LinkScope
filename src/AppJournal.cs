using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace LinkScope {
    internal sealed class LogEntry {
        internal long Time;
        internal LogLevel Level;
        internal string Module, Operation, Message, Peer, Destination;
        internal int? Status;
        internal long? Elapsed;
        internal SiemPlan Siem;
    }
    internal sealed class AppJournal:IDisposable {
        internal static readonly string Filename=Path.Combine(Config.Data,"application-logs.sqlite");
        internal static volatile AppJournal Current;
        readonly string database;
        readonly BlockingCollection<LogEntry> buffer=new BlockingCollection<LogEntry>(8192);
        readonly object configGate=new object();
        readonly AutoResetEvent forwardWake=new AutoResetEvent(false);
        readonly CancellationTokenSource stop=new CancellationTokenSource();
        Thread writer,forwarder;
        readonly bool readWindows;
        readonly SiemForwarder siem;
        internal sealed class Policy {
            internal SiemPlan Siem; internal DatabaseMaintenanceSettings Maintenance; internal LogSettings Options; internal LogLevel Local,Remote; internal string Destination;
        }
        volatile Policy policy;
        long dropped;int maintenance=1;
        volatile string forwardStatus="Disabled.",localStatus="Ready.";
        internal AppJournal(string path,LogSettings options,bool importCommands=true,SiemSettings receivers=null,DatabaseMaintenanceSettings maintenancePolicy=null){
            database=path;readWindows=importCommands;
            using(var db=new Sqlite(path,false)){db.Exec("PRAGMA journal_mode=WAL");
                db.Exec("CREATE TABLE IF NOT EXISTS app_log(id INTEGER PRIMARY KEY AUTOINCREMENT,t INTEGER NOT NULL,level INTEGER NOT NULL,module TEXT NOT NULL,operation TEXT NOT NULL,message TEXT NOT NULL,peer TEXT NOT NULL,status INTEGER,elapsed INTEGER,words TEXT NOT NULL,destination TEXT NOT NULL)");
                db.Exec("CREATE TABLE IF NOT EXISTS app_log_commands(singleton INTEGER PRIMARY KEY,last_id INTEGER NOT NULL,last_stamp INTEGER NOT NULL)");
                db.Exec("INSERT OR IGNORE INTO app_log_commands VALUES(1,0,0)");
                db.Exec("CREATE INDEX IF NOT EXISTS log_time ON app_log(t,id)");
                db.Exec("CREATE INDEX IF NOT EXISTS log_level ON app_log(level,id)");
                db.Exec("CREATE INDEX IF NOT EXISTS log_module ON app_log(module,id)");
                db.Exec("CREATE INDEX IF NOT EXISTS log_pending ON app_log(destination,id) WHERE destination<>''");
            }
            siem=new SiemForwarder(database,stop.Token,LocalWarning);
            Configure(options,receivers??new SiemSettings(),maintenancePolicy);
        }
        internal void Configure(LogSettings options,SiemSettings receivers,DatabaseMaintenanceSettings maintenancePolicy=null){
            var next=new Policy{Siem=new SiemPlan(receivers,options.RetentionDays,maintenancePolicy),Maintenance=maintenancePolicy,Options=options,Local=LogSettings.Level(options.MinimumLevel),Remote=LogSettings.Level(options.SyslogMinimumLevel),Destination=options.Destination()};
            lock(configGate){
                var old=policy;
                if(old==null||old.Destination!=next.Destination){
                    using(var db=new Sqlite(database,false))db.Exec("UPDATE app_log SET destination='' WHERE destination<>'' AND destination<>?",next.Destination);
                    forwardStatus=options.SyslogEnabled?"Waiting for events.":"Disabled.";
                }
                siem.Configure(next.Siem);policy=next;Interlocked.Exchange(ref maintenance,1);
            }
            forwardWake.Set();
        }
        internal void Start(){
            writer=new Thread(WriteLoop){IsBackground=true,Name="LinkScope application log"};
            forwarder=new Thread(ForwardLoop){IsBackground=true,Name="LinkScope syslog"};
            writer.Start();forwarder.Start();siem.Start();
        }
        // Call sites supply fixed operation names, approved metadata, and no arbitrary payloads.
        internal static void Event(LogLevel level,string module,string operation,string message,string peer="",int? status=null,long? elapsed=null){
            var log=Current;if(log!=null)log.Add(level,module,operation,message,peer,status,elapsed);
        }
        internal static void Fault(string module,string operation,Exception ex){
            Event(LogLevel.Error,module,operation,"Operation failed ("+ex.GetBaseException().GetType().Name+").");
        }
        internal void Add(LogLevel level,string module,string operation,string message,string peer="",int? status=null,long? elapsed=null){
            var p=policy;if(p==null||level<p.Local)return;
            var e=new LogEntry{Time=History.Now(),Level=level,Module=module,Operation=operation,Message=message,Peer=peer??"",
                Status=status,Elapsed=elapsed,Siem=p.Siem,Destination=level>=p.Remote?p.Destination:""};
            try{if(!buffer.TryAdd(e))Interlocked.Increment(ref dropped);}catch(InvalidOperationException){}
        }
        static void Insert(Sqlite db,LogEntry e,string destination){
            string words=AlertSearch.Fold(string.Join(" ",e.Module,e.Operation,e.Message,e.Peer,e.Level.ToString(),e.Status.ToString()));
            db.Exec("INSERT INTO app_log(t,level,module,operation,message,peer,status,elapsed,words,destination) VALUES(?,?,?,?,?,?,?,?,?,?)",
                e.Time,(int)e.Level,e.Module,e.Operation,e.Message,e.Peer,e.Status,e.Elapsed,words,destination);
        }
        internal static void Prune(Sqlite db,int days,long now){
            db.Exec("DELETE FROM app_log WHERE t < ?",now-days*86400L);
        }
        static long Cutoff(Policy p,long now){return p.Maintenance==null?now-p.Options.RetentionDays*History.Day:p.Maintenance.LogCutoff(now,p.Options.RetentionDays);}
        bool ImportCommands(){
            var p=policy;
            long id,stamp;object[] cursor;
            using(var db=new Sqlite(database,true))cursor=db.Rows("SELECT last_id,last_stamp FROM app_log_commands WHERE singleton=1")[0];
            var list=MaintenanceEvents.Read((long)cursor[0],(long)cursor[1],Cutoff(p,History.Now()),out id,out stamp);
            if(list.Count==0)return false;
            lock(configGate)using(var db=new Sqlite(database,false)){
                p=policy;db.Exec("BEGIN IMMEDIATE");
                foreach(var e in list)if(e.Level>=p.Local){
                    Insert(db,e,e.Level>=p.Remote?p.Destination:"");
                    SiemForwarder.Queue(db,e.Level,p.Siem,p.Siem);
                }
                db.Exec("UPDATE app_log_commands SET last_id=?,last_stamp=? WHERE singleton=1",id,stamp);db.Exec("COMMIT");
            }
            forwardWake.Set();siem.Wake();return list.Count==256;
        }
        void WriteLoop(){
            var batch=new List<LogEntry>();long next=0,nextImport=0;bool importFailed=false;
            while(!buffer.IsCompleted||batch.Count>0){
                try{
                    LogEntry e;
                    if(batch.Count==0&&buffer.TryTake(out e,500))batch.Add(e);
                    while(batch.Count<256&&buffer.TryTake(out e))batch.Add(e);
                    long lost=Interlocked.Exchange(ref dropped,0);
                    if(lost>0&&policy.Local<=LogLevel.Warning)batch.Add(new LogEntry{Time=History.Now(),Level=LogLevel.Warning,Module="Logging",Operation="queue",Message=lost+" records dropped while the local log queue was full.",Peer="",Destination=""});
                    long now=History.Now();
                    if(readWindows&&now>=nextImport&&!buffer.IsAddingCompleted){
                        nextImport=now+60;
                        try{if(ImportCommands())nextImport=0;importFailed=false;}
                        catch(Exception ex){
                            if(!importFailed)LocalWarning("maintenance-import","Windows command log unavailable ("+ex.GetBaseException().GetType().Name+").");
                            importFailed=true;
                        }
                    }
                    bool prune=now>=next||Interlocked.CompareExchange(ref maintenance,0,0)!=0;
                    if(batch.Count==0&&!prune)continue;
                    bool pending=false,siemPending=false;
                    lock(configGate){
                        var p=policy;
                        using(var db=new Sqlite(database,false)){
                            db.Exec("BEGIN IMMEDIATE");
                            foreach(var item in batch){
                                string route=item.Destination==p.Destination?p.Destination:"";
                                Insert(db,item,route);pending|=route.Length!=0;
                                siemPending|=SiemForwarder.Queue(db,item.Level,item.Siem,p.Siem);
                            }
                            if(prune&&(p.Maintenance==null||!p.Maintenance.Enabled))db.Exec("DELETE FROM app_log WHERE t<?",Cutoff(p,now));
                            db.Exec("COMMIT");
                        }
                        if(prune){next=now+3600;Interlocked.Exchange(ref maintenance,0);}
                    }
                    batch.Clear();localStatus="Ready.";if(pending)forwardWake.Set();if(siemPending)siem.Wake();
                }catch(Exception ex){
                    localStatus="Local log write failed ("+ex.GetBaseException().GetType().Name+").";
                    if(buffer.IsAddingCompleted){Program.BootstrapError(localStatus);return;}
                    Thread.Sleep(1000);
                }
            }
        }
        void ForwardLoop(){
            int retry=1;
            while(!stop.IsCancellationRequested){
                var p=policy;
                try{
                    if(p.Destination!=""){
                        List<object[]> rows;
                        using(var db=new Sqlite(database,true))rows=db.Rows("SELECT id,t,level,module,operation,message,peer,status,elapsed FROM app_log WHERE destination=? AND t>=? ORDER BY id LIMIT 64",p.Destination,Cutoff(p,History.Now()));
                        if(rows.Count>0&&p.Destination==policy.Destination){
                            SyslogSender.Send(p.Options,rows,stop.Token);
                            using(var db=new Sqlite(database,false))db.Exec("UPDATE app_log SET destination='' WHERE destination=? AND id<=?",p.Destination,(long)rows.Last()[0]);
                            if(p.Destination==policy.Destination)forwardStatus=(p.Options.SyslogTransport=="udp"?"Last datagram sent":"Last batch written")+" at "+Telemetry.Utc(History.Now());
                            retry=1;continue;
                        }
                    }
                    WaitHandle.WaitAny(new WaitHandle[]{stop.Token.WaitHandle,forwardWake},30000);
                }catch(Exception ex){
                    if(stop.IsCancellationRequested)break;
                    if(p.Destination!=policy.Destination){retry=1;continue;}
                    string failure="Forwarding failed ("+ex.GetBaseException().GetType().Name+"). Retrying.";
                    if(forwardStatus!=failure)LocalWarning("syslog",failure);
                    forwardStatus=failure;
                    // Ordinary log traffic must not shorten a failed receiver's backoff.
                    for(int i=0;i<retry&&p.Destination==policy.Destination&&!stop.IsCancellationRequested;i++)stop.Token.WaitHandle.WaitOne(1000);
                    retry=Math.Min(60,retry*2);
                }
            }
        }
        void LocalWarning(string operation,string message){
            if(policy.Local>LogLevel.Warning)return;
            var e=new LogEntry{Time=History.Now(),Level=LogLevel.Warning,Module="Logging",Operation=operation,Message=message,Peer="",Destination=""};
            try{if(!buffer.TryAdd(e))Interlocked.Increment(ref dropped);}catch(InvalidOperationException){}
        }
        internal object TestSiem(string receiver){
            lock(configGate)using(var db=new Sqlite(database,false)){
                db.Exec("BEGIN IMMEDIATE");
                Insert(db,new LogEntry{Time=History.Now(),Level=LogLevel.Info,Module="SIEM",Operation="delivery-test",Message="LinkScope SIEM delivery test.",Peer=""},"");
                string id=siem.QueueTest(db,receiver);
                db.Exec("COMMIT");siem.Wake();return new {queued=true,eventId=id};
            }
        }
        internal object State(){return new {local=localStatus,syslog=forwardStatus,siem=siem.State()};}
        public void Dispose(){
            if(ReferenceEquals(Current,this))Current=null;
            buffer.CompleteAdding();stop.Cancel();forwardWake.Set();
            if(writer!=null)writer.Join();if(forwarder!=null)forwarder.Join();
            // In-flight producer references can still observe a completed collection.
            siem.Dispose();forwardWake.Dispose();stop.Dispose();
        }
    }
}
