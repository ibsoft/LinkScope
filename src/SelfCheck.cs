using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace LinkScope {
    internal static class SelfCheck {
        static void Check(bool ok,string message){if(!ok)throw new InvalidOperationException("Self-check failed: "+message);}
        static Dictionary<string,object> AsMap(object o){return (Dictionary<string,object>)Config.Json().DeserializeObject(Config.Json().Serialize(o));}
        static void CheckPasswords(string dir){
            foreach(string invalid in new[]{"admin","Short1","abcdef123456","ABCDEF123456","Abcdefghijkl",new string('A',127)+"a1"}){
                bool rejected=false;
                try{AdminPasswords.CheckRules(invalid);}catch(InvalidDataException){rejected=true;}
                Check(rejected,"minimum password rules");
            }
            AdminPasswords.CheckRules("Abcdef123456");
            AdminPasswords.CheckRules(new string('A',126)+"a1");
            var passwords=new AdminPasswords(dir,dir);
            var access=new Access(Path.Combine(dir,"check-tokens.json"),passwords);
            passwords.Initialize();
            bool change;
            string starter=AdminPasswords.Starter;
            Check(access.Login("admin",starter,null,false,out change)==null&&!change,"starter restricted to localhost");
            Check(access.Login("admin",starter,null,true,out change)==null&&change,"no admin session before first-use change");
            string replacement="T1"+Guid.NewGuid().ToString("N")+"a";
            string cookie=access.Login("admin",starter,replacement,true,out change);
            Check(cookie!=null&&!change&&access.Find(cookie)!=null,"local password change opens the session");
            passwords.Initialize();
            Check(access.Login("admin",starter,null,true,out change)==null&&!change,"reinstall keeps the starter retired");
            Check(access.Login("admin",replacement,null,false,out change)!=null&&!change,"permanent credential survives reinstall");
            passwords.Reset("T2"+Guid.NewGuid().ToString("N")+"b");
            Check(access.Find(cookie)==null,"administrator reset expires the session");
            string original=File.ReadAllText(Path.Combine(dir,"admin.json"));
            passwords.Initialize();
            Check(File.ReadAllText(Path.Combine(dir,"admin.json"))==original,"preserve administrator verifier");
        }
        static void CheckManagedAccounts(string parent){
            string dir=Path.Combine(parent,"accounts-check");Directory.CreateDirectory(dir);
            var legacy=new AdminPasswords(dir,dir);legacy.Initialize();
            var access=new Access(Path.Combine(dir,"tokens.json"),legacy);bool change,mfa;
            string adminPass="AdminTest-"+Guid.NewGuid().ToString("N")+"7";
            var adminCookie=access.Login("admin",AdminPasswords.Starter,adminPass,null,true,out change,out mfa);
            var admin=access.Find(adminCookie);Check(admin!=null&&admin.IsAdmin&&!admin.MfaEnabled&&admin.Username=="admin","legacy administrator migration");
            string initial="ViewerInitial-"+Guid.NewGuid().ToString("N")+"5";
            string permanent="ViewerPermanent-"+Guid.NewGuid().ToString("N")+"6";
            access.Users.Manage(admin,new UserInput{action="create",username="ViewerTest",role="Viewer",displayName="Viewer Test",password=initial});
            Check(access.Login("viewertest",initial,null,null,true,out change,out mfa)==null&&change,"temporary user password requires replacement");
            var viewerCookie=access.Login("viewertest",initial,permanent,null,true,out change,out mfa);
            var viewer=access.Find(viewerCookie);Check(viewer!=null&&!viewer.IsAdmin&&!viewer.MfaEnabled&&viewer.Username=="viewertest","viewer login");
            Check(Web.ViewerAllowed("/ui/report",false)&&!Web.ViewerAllowed("/ui/settings",false)&&!Web.ViewerAllowed("/ui/users",true)&&!Web.ViewerAllowed("/ui/alerts/read",true)&&!Web.ViewerAllowed("/ui/endpoint-scan",true)&&Web.ViewerAllowed("/ui/account",true),"viewer route permissions");
            bool blocked=false;try{access.Users.Manage(viewer,new UserInput{action="delete",username="admin"});}catch(HttpError e){blocked=e.Status==403;}Check(blocked,"viewer cannot manage users");
            blocked=false;try{access.Users.Manage(admin,new UserInput{action="delete",username="admin"});}catch(HttpError e){blocked=e.Status==403;}Check(blocked,"built-in administrator cannot be deleted");
            byte[] known=Encoding.ASCII.GetBytes("12345678901234567890");Check(Totp.Code(known,1)=="287082"&&Totp.Base32(known)=="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","RFC TOTP reference vector");
            Check(Totp.Match(known,"287082",59,-1)==1&&Totp.Match(known,"287082",59,1)==-1,"TOTP replay rejection");
            Check(Totp.Unprotect(Totp.Protect(known)).SequenceEqual(known),"DPAPI MFA secret round trip");
            access.Users.Reauthenticate(viewer,permanent,null);var enrollment=AsMap(access.Users.BeginMfa(viewer));
            string secret=(string)enrollment["secret"];const string alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            var bytes=new List<byte>();int bits=0,buffer=0;foreach(char ch in secret){buffer=(buffer<<5)|alphabet.IndexOf(ch);bits+=5;if(bits>=8){bits-=8;bytes.Add((byte)(buffer>>bits));}}
            long step=History.Now()/30;string code=Totp.Code(bytes.ToArray(),step);
            access.Users.FinishMfa(viewer,code);Check(access.Find(viewerCookie)==null,"MFA enrollment invalidates existing session");
            Check(access.Login("viewertest",permanent,null,null,true,out change,out mfa)==null&&mfa,"MFA requires second factor");
            Check(access.Login("viewertest",permanent,null,code,true,out change,out mfa)==null,"enrollment code cannot be replayed");
            // A later step is permitted within the usual one-step clock-skew window.
            string nextCode=Totp.Code(bytes.ToArray(),step+1);viewerCookie=access.Login("viewertest",permanent,null,nextCode,true,out change,out mfa);
            Check(viewerCookie!=null&&access.Find(viewerCookie)!=null&&access.Find(viewerCookie).MfaEnabled,"MFA sign-in with unused code and enrolled session state");
            Check(access.Login("viewertest",permanent,null,nextCode,true,out change,out mfa)==null,"MFA login replay rejected");
            string publicJson=Config.Json().Serialize(access.Users.List());Check(!publicJson.Contains(secret)&&!publicJson.Contains("MfaProtected")&&!publicJson.Contains("Salt")&&!publicJson.Contains(permanent),"account listing excludes credential material");
            access.Users.Manage(admin,new UserInput{action="edit",username="viewertest",displayName="Changed",role="Admin"});Check(access.Find(viewerCookie)==null,"role change invalidates session");
            access.Users.Manage(admin,new UserInput{action="delete",username="viewertest"});Check(access.Login("viewertest",permanent,null,null,true,out change,out mfa)==null,"deleted account cannot sign in");
            access.Users.Reauthenticate(admin,adminPass,null);string changed="AdminNew-"+Guid.NewGuid().ToString("N")+"8";
            access.Users.ChangeOwn(admin,new UserInput{action="password",password=changed,currentPassword=adminPass});Check(access.Find(adminCookie)==null,"admin self password change revokes session");
            Check(access.Login("admin",adminPass,null,null,true,out change,out mfa)==null&&access.Login("admin",changed,null,null,true,out change,out mfa)!=null,"admin managed password replaces legacy verifier");
            legacy.Reset(adminPass);Check(access.Login("admin",changed,null,null,true,out change,out mfa)==null&&access.Login("admin",adminPass,null,null,true,out change,out mfa)!=null,"host password reset remains authoritative");
        }
        static void CheckProbeRules(string dir){
            var cfg=Config.Validate(Config.Json().Deserialize<Config>(Encoding.UTF8.GetString(Program.Resource("default.json"))));
            var target=cfg.Targets[0];target.FailureCount=2;target.HighRttMs=50;target.LossPercent=50;target.LossWindowProbes=4;
            var alerts=new Alerts(Path.Combine(dir,"rules.sqlite"),Path.Combine(dir,"no-legacy.json"));
            Action<string,long?> sample=(status,rtt)=>alerts.Probes(new[]{new Probe{Address=target.Address,Status=status,Rtt=rtt,LocalError=status=="Probe error"}},cfg);
            string[] network={"network"};
            sample("Success",12);sample("Success",50);sample("TimedOut",null);
            Check(alerts.List(network,true).Length==3,"Immediate loss and timeout plus RTT during loss warm-up");
            sample("TimedOut",null);
            Check(alerts.List(network,true).Length==5,"Independent network thresholds and immediate incidents");
            sample("Probe error",null);sample("Success",10);
            Check(alerts.List(network,true).Length==1,"successful probe clears RTT and failure alerts");
            sample("Success",10);sample("Success",10);
            Check(alerts.List(network,true).Length==0,"rolling loss recovery");
            target.HighRttMs=null;target.LossPercent=null;target.FailureCount=0;
            sample("TimedOut",null);
            Check(alerts.List(network,true).Length==2,"Immediate timeout and loss without threshold rules");
            long firstSequence=alerts.List(network,true).Select(x=>Convert.ToInt64(AsMap(x)["sequence"])).Max();
            sample("TimedOut",null);
            Check(alerts.List(network,true).Select(x=>Convert.ToInt64(AsMap(x)["sequence"])).Max()==firstSequence,"Continuous timeout is deduplicated");
            sample("Success",10);Check(alerts.List(network,true).Length==0,"Immediate incidents recover");
            sample("TimedOut",null);
            Check(alerts.List(network,true).Select(x=>Convert.ToInt64(AsMap(x)["sequence"])).Min()>firstSequence,"New timeout after recovery creates new history entries");
            target.AlertsEnabled=false;sample("Success",99);Check(alerts.List(network,true).Length==0,"target alert opt-out");
        }
        static void CheckIntegrity(string dir){
            string files=Path.Combine(dir,"fim-files"),store=Path.Combine(dir,"fim-store");Directory.CreateDirectory(files);Directory.CreateDirectory(store);
            string watched=Path.Combine(files,"app.txt");File.WriteAllText(watched,"original");File.WriteAllText(Path.Combine(files,"trace.log"),"excluded");
            var settings=new IntegritySettings{Enabled=true,Paths=new[]{files},ExcludedPatterns=new[]{"*.log"}};settings.Validate();
            var scanner=new FileIntegrity(store);
            using(var stop=new System.Threading.ManualResetEvent(false)){
                var first=AsMap(scanner.Scan(settings,stop));Check(Equals(first["chainValid"],true)&&Convert.ToInt32(first["monitoredFiles"])==1&&Convert.ToInt32(first["violations"])==0,"FIM baseline and exclusion");
                var activity=AsMap(scanner.Activity(settings));Check(Equals(activity["state"],"completed")&&Equals(activity["scanRunning"],false)&&Convert.ToInt32(activity["filesHashed"])==1&&Convert.ToInt32(activity["excludedEntries"])==1&&Convert.ToInt64(activity["bytesRead"])==8,"FIM completed activity counters");
                string firstScanId=(string)activity["scanId"];Check(Equals(AsMap(scanner.Activity(new IntegritySettings()))["state"],"disabled"),"FIM disabled activity isolation");
                File.WriteAllText(watched,"modified");File.WriteAllText(Path.Combine(files,"trace.log"),"changed");
                var second=AsMap(scanner.Scan(settings,stop));Check(Convert.ToInt32(second["violations"])==1,"FIM content change detected");
                Check(!Equals(AsMap(scanner.Activity(settings))["scanId"],firstScanId),"FIM new scan activity identity");
                File.WriteAllText(watched,"original");Check(Convert.ToInt32(AsMap(scanner.Scan(settings,stop))["violations"])==0,"FIM recovery retains baseline");
                File.Delete(watched);Check(Convert.ToInt32(AsMap(scanner.Scan(settings,stop))["violations"])==1,"FIM deletion detected");
                var changed=new IntegritySettings{Enabled=true,Paths=new[]{files},ExcludedPatterns=new[]{"*.log","*.txt"}};changed.Validate();
                Check(Equals(AsMap(scanner.Scan(changed,stop))["chainValid"],false),"FIM unauthorized policy change detected");
                scanner.Authorize(settings,changed);Check(Equals(AsMap(scanner.Scan(changed,stop))["chainValid"],true),"FIM authorized policy change");
                string state=Path.Combine(store,"integrity","chain.json");var chain=Config.Json().Deserialize<IntegrityState>(File.ReadAllText(state));chain.Chain[0].Mac=new string('0',64);Config.Save(state,chain);
                Check(Equals(AsMap(scanner.Scan(changed,stop))["chainValid"],false),"FIM chain tampering detected");
            }
        }
        static void CheckSignatureSchedule(){
            var c=new EndpointSettings();var utc=TimeZoneInfo.Utc;
            Check(!c.SignatureScheduleEnabled,"signature schedule opt-in default");
            var start=new DateTime(2026,11,27,2,59,0,DateTimeKind.Utc);
            Check(c.NextSignatureUpdate(start,utc)==new DateTime(2026,11,27,3,0,0,DateTimeKind.Utc),"daily signature schedule");
            Check(c.NextSignatureUpdate(start.AddMinutes(1),utc)==new DateTime(2026,11,28,3,0,0,DateTimeKind.Utc),"daily schedule advances past current occurrence");
            c.SignatureScheduleFrequency="weekly";c.SignatureScheduleWeekday=1;
            Check(c.NextSignatureUpdate(start,utc)==new DateTime(2026,11,30,3,0,0,DateTimeKind.Utc),"weekly signature schedule");
            c.SignatureScheduleFrequency="monthly";c.SignatureScheduleMonthDay=31;
            Check(c.NextSignatureUpdate(start,utc)==new DateTime(2026,11,30,3,0,0,DateTimeKind.Utc),"monthly last-day fallback");
            Check(c.NextSignatureUpdate(new DateTime(2027,2,1,0,0,0,DateTimeKind.Utc),utc)==new DateTime(2027,2,28,3,0,0,DateTimeKind.Utc),"February signature schedule");
            c.SignatureScheduleTime="99:99";bool rejected=false;try{c.Validate();}catch(InvalidDataException){rejected=true;}Check(rejected,"invalid signature time rejected");
        }
        static void CheckEndpoint(string dir){
            CheckSignatureSchedule();
            var settings=new EndpointSettings{Enabled=true,Paths=new[]{dir},ExcludedPatterns=new[]{"*.tmp"}};settings.Validate();
            Check(settings.Mode=="monitor"&&settings.RealTime,"endpoint safe defaults");
            Check(EndpointProtection.Excluded(settings,Path.Combine(dir,"TRACE.TMP")),"case-insensitive endpoint exclusion");
            Check(!EndpointProtection.Excluded(settings,Path.Combine(dir,"trace.txt")),"endpoint exclusion boundary");
            var flat=new byte[4096];var uniform=Enumerable.Range(0,4096).Select(n=>(byte)(n%256)).ToArray();
            Check(EndpointProtection.Entropy(flat,flat.Length)==0&&Math.Abs(EndpointProtection.Entropy(uniform,uniform.Length)-8)<0.00001,"entropy known vectors");
            Check(EndpointProtection.Malware("stream: Test.Signature FOUND")&&!EndpointProtection.Malware("stream: Heuristics.Limits.Exceeded FOUND")&&!EndpointProtection.Malware("stream: OK"),"clamd classification");
            bool refused=false;settings.Mode="protect";try{settings.Validate();}catch(InvalidDataException){refused=true;}Check(refused,"automatic actions require explicit response scope and verified engine pin");
            var cfg=new Config();cfg.Endpoint.WriteEvents=false;var dbPath=Path.Combine(dir,"ep-alerts.sqlite");var legacy=Path.Combine(dir,"ep-no-legacy.json");var alerts=new Alerts(dbPath,legacy);long now=History.Now();
            var transitions=new List<object[]>{new object[]{1L,now,"test","test.txt","Test detection","critical","Test only","hash",1L},new object[]{2L,now,"test","test.txt","Test detection","critical","Test only","hash",0L}};
            alerts.EndpointTransitions("test-stream",transitions,cfg);Check(alerts.List(new[]{"endpoint_protection"},true).Length==0,"endpoint recovered event closes active incident");
            alerts=new Alerts(dbPath,legacy);alerts.EndpointTransitions("test-stream",transitions,cfg);using(var db=new Sqlite(dbPath,true))Check(Convert.ToInt64(db.Rows("SELECT COUNT(*) FROM alert_events WHERE category='endpoint_protection'")[0][0])==1,"durable endpoint delivery replay is idempotent");
            alerts.EndpointTransitions("test-stream",new List<object[]>{new object[]{3L,now,"old-warning","ClamAV","Engine unavailable","warning","Legacy warning","",1L},new object[]{4L,now,"still-active","test.txt","Malware detected","critical","Test only","hash",1L}},cfg);
            alerts.Sample("endpoint_protection",new {status="partial",items=new object[0]},cfg);
            alerts.ReconcileEndpointFindings(new HashSet<string>{"still-active"});
            var remaining=alerts.List(new[]{"endpoint_protection"},true).Select(AsMap).ToArray();
            Check(remaining.Length==2&&remaining.Any(a=>Equals(a["title"],"Malware detected"))&&remaining.Any(a=>Equals(a["title"],"endpoint_protection coverage is partial")),"reconciliation keeps actual findings and coverage");
            using(var db=new Sqlite(dbPath,true))Check(Convert.ToInt64(db.Rows("SELECT COUNT(*) FROM alert_events WHERE alert_key='endpoint_protection/old-warning' AND resolved=1 AND is_read=0")[0][0])==1,"orphan alert resolved, unread history preserved");
            alerts.Sample("ram",new {status="ok",usedPercent=100.0},cfg);
            long cutoff=Convert.ToInt64(AsMap(alerts.EndpointAcknowledgement())["through"]);
            alerts.EndpointTransitions("test-stream",new List<object[]>{new object[]{5L,now,"new-alert","new.txt","New detection","critical","Test only","hash",1L}},cfg);
            var ack=AsMap(alerts.ReadEndpointThrough(cutoff));
            Check(Convert.ToInt64(ack["unread"])==1&&Convert.ToInt64(ack["activeUnread"])==1,"endpoint acknowledgement retains later unread incident");
            remaining=alerts.List(new[]{"endpoint_protection"},true).Select(AsMap).ToArray();
            Check(remaining.Any(a=>Equals(a["title"],"Malware detected")&&Equals(a["read"],true))&&remaining.Any(a=>Equals(a["title"],"New detection")&&Equals(a["read"],false)),"endpoint acknowledgement preserves active threats");
            using(var db=new Sqlite(dbPath,true))Check(Convert.ToInt64(db.Rows("SELECT COUNT(*) FROM alert_events WHERE category='endpoint_protection' AND seq<=? AND is_read=0",cutoff)[0][0])==0&&Convert.ToInt64(db.Rows("SELECT COUNT(*) FROM alert_events WHERE category='ram' AND is_read=0")[0][0])>0,"endpoint acknowledgement does not mark RAM alerts read");
        }
        internal static void Run(bool testPasswords=false){
            var allowedIPs=ClientFirewall.Validate(new[]{"192.168.1.10","2001:db8::10","::ffff:192.168.1.10"});
            Check(allowedIPs.Length==2 && ClientFirewall.Allows("192.168.1.10",allowedIPs),"IP firewall explicit allow");
            Check(ClientFirewall.Allows("::ffff:127.0.0.1",null)&&ClientFirewall.Allows("::1",null),"IP firewall loopback");
            Check(!ClientFirewall.Allows("192.168.1.11",allowedIPs)&&!ClientFirewall.Allows("192.168.1.10",null),"IP firewall default deny");
            bool invalidIP=false;try{ClientFirewall.Validate(new[]{"0.0.0.0"});}catch(System.IO.InvalidDataException){invalidIP=true;}
            Check(invalidIP,"IP firewall invalid rule rejection");
            var subnets=ClientFirewall.Validate(new[]{"192.168.1.37/24","192.168.1.0/24","2001:db8:1::9/64","::ffff:10.20.30.0/120","172.16.4.1/32"});
            Check(subnets.Length==4&&subnets.Contains("192.168.1.0/24")&&subnets.Contains("10.20.30.0/24"),"CIDR canonical network and mapped IPv4");
            Check(ClientFirewall.Allows("192.168.1.1",subnets)&&ClientFirewall.Allows("192.168.1.254",subnets)&&ClientFirewall.Allows("::ffff:192.168.1.10",subnets)&&!ClientFirewall.Allows("192.168.2.1",subnets),"IPv4 CIDR boundaries");
            Check(ClientFirewall.Allows("2001:db8:1::ffff",subnets)&&!ClientFirewall.Allows("2001:db8:2::1",subnets)&&ClientFirewall.Allows("172.16.4.1",subnets)&&!ClientFirewall.Allows("172.16.4.2",subnets),"IPv6 and single address CIDR");
            foreach(string bad in new[]{"0.0.0.0/0","::/0","192.168.1.0/33","2001:db8::/129","192.168.1.0/-1","192.168.1.0/24/1","192.168.1.0/","192.168.1.0/ 24","192.168.01.0/24","::ffff:192.168.1.0/95","fe80::1%4/64"}){
                bool refused=false;try{ClientFirewall.Validate(new[]{bad});}catch(InvalidDataException){refused=true;}
                Check(refused&&!ClientFirewall.Allows("192.168.1.10",new[]{bad}),"CIDR invalid rule rejected: "+bad);
            }

            var c=Config.Validate(Config.Json().Deserialize<Config>(Encoding.UTF8.GetString(Program.Resource("default.json"))));
            Check(c.BindAddress=="127.0.0.1"&&!c.UseHttps&&c.RequireLogin,"local default");
            c.BindAddress="192.0.2.1";bool rejected=false;try{Config.Validate(c);}catch(InvalidDataException){rejected=true;}
            Check(rejected,"remote cleartext rejection");c.BindAddress="127.0.0.1";
            var req=Request.Read(new MemoryStream(Encoding.ASCII.GetBytes("GET /api/v1/system HTTP/1.1\r\nHost: localhost:9876\r\n\r\n")));
            Check(req.Path=="/api/v1/system"&&req.Method=="GET","HTTP parsing");
            var ata=new byte[512];var limits=new byte[512];ata[2]=limits[2]=177;ata[5]=ata[6]=93;ata[7]=156;
            var attr=AsMap(SmartDisk.Attributes(ata,limits,true).Single());
            Check((string)attr["name"]=="Wear Leveling Count"&&(string)attr["rawHex"]=="00000000-009C"&&(string)attr["state"]=="OK","ATA attribute decoding");
            var unknown=AsMap(SmartDisk.Attributes(ata,null,true).Single());Check((string)unknown["state"]=="UNKNOWN","absent manufacturer threshold");
            string dir=Path.Combine(Path.GetTempPath(),"LinkScope-check-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(dir);
            try{
                CheckProbeRules(dir);CheckIntegrity(dir);CheckEndpoint(dir);
                if(testPasswords){CheckPasswords(dir);CheckManagedAccounts(dir);DeliveryChecks.Run(dir);LogAiChecks.Run(dir);}
                var access=new Access(Path.Combine(dir,"tokens.json"));string token=access.Issue("self-check",new[]{"cpu"},1,c.Categories());
                Check(access.Authorize("Bearer "+token).SequenceEqual(new[]{"cpu"}),"token scope");
                Check(!Config.Allowed(new[]{"ram"},access.Authorize("Bearer "+token)),"scope rejection");
                string id=(string)AsMap(access.List().Single())["id"];Check(access.Revoke(id)&&access.Authorize("Bearer "+token)==null,"token revocation");
                string file=Path.Combine(dir,"alerts.json"),dbPath=Path.Combine(dir,"history.sqlite");
                var legacy=new HealthAlert{Id="legacy",Key="ram/RAM",Category="ram",Severity="warning",Title="Earlier alert",
                    Message="Legacy status",Since=10,Read=true,Resolved=true,Revision=""};
                Config.Save(file,new Dictionary<string,HealthAlert>{{"closed/legacy",legacy}});
                var alerts=new Alerts(dbPath,file);string[] cpu={"cpu"};
                alerts.Sample("cpu",new {status="ok",usedPercent=95},c);
                string first=(string)AsMap(alerts.List(cpu,true).Single())["id"];Check(alerts.List(new[]{"ram"},true).Length==0,"active scope");
                alerts.Read(first);alerts=new Alerts(dbPath,file);alerts.Sample("cpu",new {status="ok",usedPercent=96},c);
                Check((bool)AsMap(alerts.List(cpu,true).Single())["read"],"read state after restart");
                alerts.Sample("cpu",new {status="ok",usedPercent=12},c);
                alerts.Sample("cpu",new {status="ok",usedPercent=96},c);
                var second=AsMap(alerts.List(cpu,true).Single());Check((string)second["id"]!=first&&!(bool)second["read"],"new incident");
                long cutoff=Convert.ToInt64(AsMap(alerts.Page(0))["through"]);
                alerts.Sample("ram",new {status="ok",usedPercent=97},c);
                alerts.ReadAll(cutoff);alerts.Sample("cpu",new {status="ok",usedPercent=10},c);
                alerts=new Alerts(dbPath,file);
                Check(alerts.List(cpu,true).Length==0,"resolved alert removed from active view");
                Check(Convert.ToInt64(AsMap(alerts.Page(0))["unread"])==1,"bulk acknowledgement preserves newer alert");
                using(var db=new Sqlite(dbPath,true)){
                    Check((long)db.Rows("SELECT COUNT(*) FROM alert_events")[0][0]==4,"retained alert occurrences and idempotent migration");
                    Check((long)db.Rows("SELECT COUNT(*) FROM alert_events WHERE is_read=1 AND resolved=1")[0][0]==3,"read and resolved history retained");
                }
            }finally{Directory.Delete(dir,true);}
            Console.WriteLine("LinkScope self-check passed.");
        }
    }
}
