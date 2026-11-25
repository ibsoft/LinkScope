using System;
using System.IO;
using System.Linq;
using System.Threading;

namespace LinkScope {
    internal sealed class AlertDelivery:IDisposable {
        readonly string database;
        readonly AlertFiles files;
        readonly Alerts alerts;
        readonly AutoResetEvent mailWake=new AutoResetEvent(false),fileWake=new AutoResetEvent(false);
        readonly CancellationTokenSource stop=new CancellationTokenSource();
        readonly object gate=new object();
        volatile DeliverySettings settings;
        Thread mailWorker,fileWorker,testWorker;
        string mailStatus="Idle",fileStatus="Idle",testState="idle",testMessage="";
        internal AlertDelivery(Alerts alerts,string database,DeliverySettings d){
            this.alerts=alerts;this.database=database;files=new AlertFiles(database);
            Set(d);alerts.OutputChanged+=Wake;
        }
        internal static void Init(Sqlite db){
            db.Exec("CREATE TABLE IF NOT EXISTS alert_mail_queue(job TEXT NOT NULL UNIQUE,alert_id TEXT NOT NULL,kind TEXT NOT NULL,subject TEXT NOT NULL,body TEXT NOT NULL,tries INTEGER NOT NULL DEFAULT 0,due INTEGER NOT NULL DEFAULT 0,UNIQUE(alert_id,kind))");
        }
        internal static void Queue(Sqlite db,HealthAlert a,bool recovery,long now){
            string state=recovery?"RESOLVED":"OPEN";
            string body="Monitoring host: "+Environment.MachineName+"\r\nState: "+state+"\r\nSeverity: "+a.Severity+
                "\r\nCategory: "+a.Category+"\r\nAlert ID: "+a.Id+"\r\nOpened UTC: "+Telemetry.Utc(a.Since)+
                (recovery?"\r\nResolved UTC: "+Telemetry.Utc(now):"")+"\r\n\r\n"+a.Title+"\r\n"+a.Message;
            db.Exec("INSERT OR IGNORE INTO alert_mail_queue(job,alert_id,kind,subject,body) VALUES(?,?,?,?,?)",
                Guid.NewGuid().ToString("N"),a.Id,state,state+" · "+Environment.MachineName+" · "+a.Title,body);
        }
        internal void Start(){
            mailWorker=new Thread(MailLoop){IsBackground=true,Name="LinkScope SMTP"};
            fileWorker=new Thread(FileLoop){IsBackground=true,Name="LinkScope alert files"};
            mailWorker.Start();fileWorker.Start();
        }
        internal void Set(DeliverySettings d,Action persist=null){
            lock(alerts){
                bool mailChanged=!d.SameMailSettings(settings);
                if(mailChanged){
                    using(var db=new Sqlite(database,false)){
                        db.Exec("BEGIN IMMEDIATE");
                        try{
                            if(!d.EmailEnabled)db.Exec("DELETE FROM alert_mail_queue");
                            else if(settings!=null)db.Exec("UPDATE alert_mail_queue SET tries=0,due=0");
                            if(persist!=null)persist();
                            db.Exec("COMMIT");
                        }catch{db.Exec("ROLLBACK");throw;}
                    }
                    Status(true,d.EmailEnabled?"Ready.":"Disabled.",false);
                }else if(persist!=null)persist();
                alerts.Policy=d;settings=d;
            }
            Wake();
        }
        void Wake(){mailWake.Set();fileWake.Set();}
        void Status(bool mail,string text,bool error){
            lock(gate){
                if(error&&text!=(mail?mailStatus:fileStatus))AppJournal.Event(LogLevel.Warning,mail?"SMTP":"AlertFiles",mail?"deliver":"synchronize",mail?"Mail delivery failed. See delivery status.":"Alert file synchronization failed. See delivery status.");
                if(mail)mailStatus=text;else fileStatus=text;
            }
        }
        internal object State(){
            long count=0;using(var db=new Sqlite(database,true))count=(long)db.Rows("SELECT COUNT(*) FROM alert_mail_queue")[0][0];
            lock(gate)return new {queued=count,email=mailStatus,files=fileStatus,testState=testState,testMessage=testMessage,logStatus=AppJournal.Current==null?null:AppJournal.Current.State()};
        }
        internal void Test(DeliverySettings d){
            lock(gate){
                if(testWorker!=null&&testWorker.IsAlive)throw new HttpError(409,"A test email is already in progress.");
                testState="running";testMessage="Connecting to the SMTP relay…";
                testWorker=new Thread(delegate(){
                    try{
                        var mail=new AlertMail{Id=Guid.NewGuid().ToString("N"),Subject="SMTP test · "+Environment.MachineName,
                            Body="This is a LinkScope SMTP test from "+Environment.MachineName+".\r\nUTC: "+DateTime.UtcNow.ToString("o")};
                        string result=SmtpTransport.Send(d,mail,stop.Token);AppJournal.Event(LogLevel.Info,"SMTP","test","Test message accepted by relay.");lock(gate){testState="accepted";testMessage=result;}
                    }catch(Exception ex){AppJournal.Fault("SMTP","test",ex);lock(gate){testState="failed";testMessage=ex.Message;}}
                }){IsBackground=true,Name="LinkScope SMTP test"};testWorker.Start();
            }
        }
        bool Wait(AutoResetEvent wake,int millis){return WaitHandle.WaitAny(new WaitHandle[]{stop.Token.WaitHandle,wake},millis)==0;}
        void FileLoop(){
            bool clean=false;
            while(!stop.IsCancellationRequested){
                var d=settings;
                try{
                    if(d.JsonEnabled||!clean){files.Reconcile(d);AppJournal.Event(LogLevel.Debug,"AlertFiles","synchronize","Managed alert files synchronized.");clean=!d.JsonEnabled;}
                    Status(false,d.JsonEnabled?"Active files synchronized.":"Disabled.",false);
                }catch(Exception ex){clean=false;Status(false,ex.Message,true);}
                if(Wait(fileWake,60000))break;
                if(stop.Token.WaitHandle.WaitOne(350))break;
            }
        }
        void MailLoop(){
            while(!stop.IsCancellationRequested){
                int delay=60000;
                try{
                    var d=settings;
                    if(!d.EmailEnabled)Status(true,"Disabled.",false);
                    else using(var db=new Sqlite(database,false)){
                        var row=db.Rows("SELECT job,subject,body,tries,due FROM alert_mail_queue ORDER BY rowid LIMIT 1").FirstOrDefault();
                        if(row!=null){
                            long wait=(long)row[4]-History.Now();
                            if(wait>0)delay=(int)(Math.Min(wait,60)*1000);
                            else if(d.SameMailSettings(settings)){
                                string job=(string)row[0];
                                try{
                                    var mail=new AlertMail{Id=job,Subject=(string)row[1],Body=(string)row[2]};
                                    string ack=SmtpTransport.Send(d,mail,stop.Token);
                                    AppJournal.Event(LogLevel.Info,"SMTP","deliver","Monitoring email accepted by relay.");
                                    db.Exec("DELETE FROM alert_mail_queue WHERE job=?",job);
                                    Status(true,Telemetry.Utc(History.Now())+" · "+ack,false);delay=0;
                                }catch(OperationCanceledException){if(stop.IsCancellationRequested)break;throw;}
                                catch(Exception ex){
                                    if(!d.SameMailSettings(settings))continue;
                                    long seconds=Math.Min(3600,30L<<((int)Math.Min(7,(long)row[3])));
                                    db.Exec("UPDATE alert_mail_queue SET tries=tries+1,due=? WHERE job=?",History.Now()+seconds,job);
                                    Status(true,ex.Message+" Retry in "+seconds+" s.",true);delay=(int)Math.Min(60000,seconds*1000);
                                }
                            }
                        }
                    }
                }catch(Exception ex){Status(true,ex.Message,true);}
                if(Wait(mailWake,delay))break;
            }
        }
        public void Dispose(){
            alerts.OutputChanged-=Wake;stop.Cancel();Wake();
            if(mailWorker!=null)mailWorker.Join();if(fileWorker!=null)fileWorker.Join();
            if(testWorker!=null)testWorker.Join();
            mailWake.Dispose();fileWake.Dispose();stop.Dispose();
        }
    }
}
