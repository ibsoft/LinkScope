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
            foreach(string invalid in new[]{"admin","Short1","abcdef1","ABCDEF1","Abcdefg",new string('A',127)+"a1"}){
                bool rejected=false;
                try{AdminPasswords.CheckRules(invalid);}catch(InvalidDataException){rejected=true;}
                Check(rejected,"minimum password rules");
            }
            AdminPasswords.CheckRules("Abcdef1");
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
                File.WriteAllText(watched,"modified");File.WriteAllText(Path.Combine(files,"trace.log"),"changed");
                var second=AsMap(scanner.Scan(settings,stop));Check(Convert.ToInt32(second["violations"])==1,"FIM content change detected");
                File.WriteAllText(watched,"original");Check(Convert.ToInt32(AsMap(scanner.Scan(settings,stop))["violations"])==0,"FIM recovery retains baseline");
                File.Delete(watched);Check(Convert.ToInt32(AsMap(scanner.Scan(settings,stop))["violations"])==1,"FIM deletion detected");
                var changed=new IntegritySettings{Enabled=true,Paths=new[]{files},ExcludedPatterns=new[]{"*.log","*.txt"}};changed.Validate();
                Check(Equals(AsMap(scanner.Scan(changed,stop))["chainValid"],false),"FIM unauthorized policy change detected");
                scanner.Authorize(settings,changed);Check(Equals(AsMap(scanner.Scan(changed,stop))["chainValid"],true),"FIM authorized policy change");
                string state=Path.Combine(store,"integrity","chain.json");var chain=Config.Json().Deserialize<IntegrityState>(File.ReadAllText(state));chain.Chain[0].Mac=new string('0',64);Config.Save(state,chain);
                Check(Equals(AsMap(scanner.Scan(changed,stop))["chainValid"],false),"FIM chain tampering detected");
            }
        }
        internal static void Run(bool testPasswords=false){
            var allowedIPs=ClientFirewall.Validate(new[]{"192.168.1.10","2001:db8::10","::ffff:192.168.1.10"});
            Check(allowedIPs.Length==2 && ClientFirewall.Allows("192.168.1.10",allowedIPs),"IP firewall explicit allow");
            Check(ClientFirewall.Allows("::ffff:127.0.0.1",null)&&ClientFirewall.Allows("::1",null),"IP firewall loopback");
            Check(!ClientFirewall.Allows("192.168.1.11",allowedIPs)&&!ClientFirewall.Allows("192.168.1.10",null),"IP firewall default deny");
            bool invalidIP=false;try{ClientFirewall.Validate(new[]{"0.0.0.0"});}catch(System.IO.InvalidDataException){invalidIP=true;}
            Check(invalidIP,"IP firewall invalid rule rejection");
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
                CheckProbeRules(dir);CheckIntegrity(dir);
                if(testPasswords){CheckPasswords(dir);DeliveryChecks.Run(dir);LogAiChecks.Run(dir);}
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
