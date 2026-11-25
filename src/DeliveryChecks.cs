using System;
using System.IO;
using System.Collections.Generic;
using System.Web;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace LinkScope {
    internal static class DeliveryChecks {
        static void Check(bool condition,string description){
            if(!condition)throw new InvalidOperationException("Alert delivery self-test failed: "+description);
        }
        internal static void Run(string dir){
            string database=Path.Combine(dir,"outputs.sqlite"),legacy=Path.Combine(dir,"no-legacy.json");
            var alerts=new Alerts(database,legacy);
            var d=new DeliverySettings{EmailEnabled=true,EmailRecovery=true,JsonEnabled=true,MaxJsonFiles=1,
                JsonDirectory=Path.Combine(dir,"active")};
            alerts.Policy=d;var files=new AlertFiles(database);
            Config c=new Config();
            alerts.Sample("ram",new {status="ok",usedPercent=95},c);files.Reconcile(d);
            string first=Directory.GetFiles(d.JsonDirectory,"*.json").Single();
            string foreign=Path.Combine(d.JsonDirectory,"operator.json");File.WriteAllText(foreign,"{}");
            alerts.Sample("cpu",new {status="ok",usedPercent=98},c);files.Reconcile(d);
            Check(!File.Exists(first)&&File.Exists(foreign),"retain newest managed active file");
            string cpuFile=Directory.GetFiles(d.JsonDirectory,"LinkScope-*.json").Single();
            alerts.Sample("cpu",new {status="ok",usedPercent=12},c);files.Reconcile(d);
            Check(!File.Exists(cpuFile)&&File.Exists(first),"delete resolved file and restore eligible active file");
            using(var db=new Sqlite(database,true)){
                Check((long)db.Rows("SELECT COUNT(*) FROM alert_mail_queue")[0][0]==3,"two opening emails and one recovery");
                Check((long)db.Rows("SELECT COUNT(*) FROM alert_events")[0][0]==2,"retention preserves SQLite history");
            }
            alerts.Sample("ram",new {status="ok",usedPercent=96},c);
            string next=Path.Combine(dir,"active-two");d.JsonDirectory=next;files=new AlertFiles(database);files.Reconcile(d);
            Check(!File.Exists(first)&&File.Exists(foreign)&&Directory.GetFiles(next,"*.json").Length==1,"move owned files after restart");
            d.JsonEnabled=false;files.Reconcile(d);
            Check(Directory.GetFiles(next,"*.json").Length==0,"disable removes managed files");
            var safe=new DeliverySettings{SmtpHost="localhost",Username="unit",Authentication="auto",From="from@example.test",To="to@example.test"};
            safe.ApplySecret(new DeliverySettings(),"test-password",false);safe.Validate(true);
            Check(safe.PublicCopy().ProtectedPassword==""&&Encoding.UTF8.GetString(safe.PasswordBytes())=="test-password","SMTP password storage and redaction");
            var reuse=safe.PublicCopy();reuse.ApplySecret(safe,"",false);Check(reuse.ProtectedPassword==safe.ProtectedPassword,"blank retains password");
            reuse.SmtpHost="other.example.test";bool blocked=false;
            try{reuse.ApplySecret(safe,"",false);}catch(InvalidDataException){blocked=true;}
            Check(blocked,"saved credential scoped to server");
            SearchHistory(dir);
            LoopbackSmtp();
        }
        static Dictionary<string,object> Search(string database,string query){
            var json=Config.Json();
            return json.Deserialize<Dictionary<string,object>>(json.Serialize(new AlertSearch(query).Run(database)));
        }
        static void SearchHistory(string dir){
            string database=Path.Combine(dir,"search.sqlite"),legacy=Path.Combine(dir,"none.json");
            new Alerts(database,legacy);
            using(var db=new Sqlite(database,false)){
                db.Exec("BEGIN");
                // Simulate an existing release database without indexed search text.
                db.Exec("DELETE FROM alert_migrations WHERE name='search-text-v1'");
                for(int i=1;i<=32;i++){
                    string id="sample-"+i;
                    db.Exec("INSERT INTO alert_events(id,alert_key,category,severity,title,message,since,is_read,resolved) VALUES(?,?,?,?,?,?,?,?,?)",
                        id,"network/"+id,"network","warning","Πύλη Δικτύου","192.0.2.10 %_ link",1000+i,i%2==0,i%3==0);
                }
                db.Exec("COMMIT");
            }
            new Alerts(database,legacy);
            string filters="q="+HttpUtility.UrlEncode("πυλη δικτυου %_")+"&category=network&severity=warning&state=resolved&read=read&from=1006&until=1018";
            var matches=Search(database,filters);
            Check(Convert.ToInt64(matches["total"])==2,"old history indexed, folded words, literal punctuation and overlapping filters");
            var first=Search(database,"size=10&page=1");
            Check(Convert.ToInt64(first["pages"])==4&&Convert.ToInt64(first["through"])==32,"initial search pages");
            var monitor=new Alerts(database,legacy);
            monitor.Sample("cpu",new {status="ok",usedPercent=98},new Config());
            var last=Search(database,"size=10&page=999&through=32");
            Check(Convert.ToInt64(last["page"])==4&&Convert.ToInt64(last["total"])==32,"paging remains anchored during new alerts");
            Check(Convert.ToInt64(Search(database,"")["total"])==33&&Convert.ToInt64(Search(database,"q=absent")["total"])==0,"fresh and empty searches");
            bool rejected=false;try{new AlertSearch("from=100&until=99");}catch(HttpError){rejected=true;}
            Check(rejected,"invalid opening-date range");
        }
        // Exercise the same wire implementation as the Settings test and alert worker, entirely on loopback.
        static void LoopbackSmtp(){
            var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();
            var d=new DeliverySettings{SmtpHost="127.0.0.1",SmtpPort=((IPEndPoint)listener.LocalEndpoint).Port,Encryption="plain",
                From="from@example.test",To="to@example.test",Cc="copy@example.test",Bcc="blind@example.test",ReplyTo="reply@example.test",
                SenderName="Δοκιμή",TimeoutSeconds=5};
            d.Validate(true);
            Exception serverError=null;string payload="";int recipients=0;
            var server=new Thread(delegate(){
                try{using(var socket=listener.AcceptTcpClient()){
                    socket.ReceiveTimeout=5000;socket.SendTimeout=5000;
                    using(var stream=socket.GetStream())using(var read=new StreamReader(stream,Encoding.ASCII))
                    using(var write=new StreamWriter(stream,Encoding.ASCII){NewLine="\r\n",AutoFlush=true}){
                        write.WriteLine("220 test");string line;
                        while((line=read.ReadLine())!=null){
                            if(line.StartsWith("EHLO "))write.WriteLine("250 test");
                            else if(line.StartsWith("MAIL FROM:"))write.WriteLine("250 ok");
                            else if(line.StartsWith("RCPT TO:")){recipients++;write.WriteLine("250 ok");}
                            else if(line=="DATA"){
                                write.WriteLine("354 go");var buf=new StringBuilder();
                                while((line=read.ReadLine())!=null&&line!=".")buf.AppendLine(line);
                                payload=buf.ToString();write.WriteLine("250 queued");break;
                            }else throw new IOException("Unexpected SMTP command.");
                        }
                    }
                }}catch(Exception ex){serverError=ex;}
            }){IsBackground=true};
            try{
                server.Start();
                var mail=new AlertMail{Id=Guid.NewGuid().ToString("N"),Subject="Δοκιμή",Body="Test body"};
                string result=SmtpTransport.Send(d,mail,CancellationToken.None);
                Check(server.Join(7000)&&serverError==null,"loopback relay completed");
                Check(recipients==3&&result.Contains("3 recipient")&&payload.Contains("reply@example.test")&&
                    !payload.Contains("blind@example.test")&&payload.Contains("=?UTF-8?B?")&&payload.Contains("VGVzdCBib2R5"),"MIME and blind recipient handling");
            }finally{listener.Stop();}
        }
    }
}
