using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace LinkScope {
    internal static class LogAiChecks {
        static void Check(bool b,string why){if(!b)throw new InvalidOperationException("Logging/AI self-test: "+why);}
        internal static void Run(string dir){
            string path=Path.Combine(dir,"app.sqlite");var opts=new LogSettings{MinimumLevel="Debug"};
            using(var journal=new AppJournal(path,opts,false)){
                journal.Start();
                for(int i=0;i<29;i++)journal.Add(LogLevel.Info,"API","GET /api/v1/system","System snapshot completed.","192.0.2.8",200,i);
                journal.Add(LogLevel.Warning,"Network","ping","Πύλη probe timeout.","192.0.2.3");
                journal.Add(LogLevel.Debug,"Health","cpu","CPU sampled.");
            }
            var json=Config.Json();
            var check=json.Deserialize<Dictionary<string,object>>(json.Serialize(new LogSearch("q="+Uri.EscapeDataString("πυλη timeout")+"&level=Warning&module=network&operation=pin&peer=192.0.2.3&size=10").Run(path)));
            Check(Convert.ToInt64(check["total"])==1,"combined search");
            using(var db=new Sqlite(path,false)){
                db.Exec("UPDATE app_log SET t=0 WHERE level=0");
                AppJournal.Prune(db,1,History.Now());
                Check((long)db.Rows("SELECT COUNT(*) FROM app_log")[0][0]==30,"retention");
            }
            var page=json.Deserialize<Dictionary<string,object>>(json.Serialize(new LogSearch("page=99&size=10&through=30").Run(path)));
            Check(Convert.ToInt32(page["total"])==30&&Convert.ToInt32(page["page"])==3,"anchored paging");
            var profile=new AiSettings();profile.Profiles["openai"]=new AiProfile{Model="example"};
            var ai=AiSettings.Merge(profile,new AiEdit{Ai=profile.PublicCopy(),NewAiKey="fixture-key"});
            ai.Enabled=true;ai.Validate();Check(ai.PublicCopy().Profile("openai").ProtectedKey==""&&ai.Key()=="fixture-key","key protection and masking");
            var hidden=ai.PublicCopy();hidden.Provider="compatible";hidden.Profiles["compatible"]=new AiProfile{Model="test",BaseUrl="https://localhost/v1"};
            var saved=AiSettings.Merge(ai,new AiEdit{Ai=hidden});saved.Provider="openai";saved.Validate();Check(saved.Key()=="fixture-key","per-provider retention");
            object plain=json.DeserializeObject("{\"choices\":[{\"message\":{\"content\":\"fixture answer\"}}]}");
            object native=json.DeserializeObject("{\"content\":[{\"type\":\"text\",\"text\":\"fixture answer\"}]}");
            object gem=json.DeserializeObject("{\"candidates\":[{\"content\":{\"parts\":[{\"thought\":true,\"text\":\"hidden\"},{\"text\":\"fixture answer\"}]}}]}");
            object bedrock=json.DeserializeObject("{\"output\":{\"message\":{\"content\":[{\"text\":\"fixture answer\"}]}}}");
            object cohere=json.DeserializeObject("{\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"fixture answer\"}]}}");
            foreach(string id in AiSettings.Hosts.Keys){
                object response=id=="anthropic"?native:id=="gemini"?gem:id=="bedrock"?bedrock:id=="cohere"?cohere:plain;
                Check(AiProvider.Answer(id,response)=="fixture answer",id+" response");
                string payload=json.Serialize(AiProvider.Payload(id,"example","system","question"));
                Check(payload.Contains("question")&&!payload.Contains("fixture-key"),id+" request");
            }
            var monitors=new Alerts(Path.Combine(dir,"security.sqlite"),Path.Combine(dir,"no-security-legacy.json"));
            var config=new Config();
            monitors.Sample("security",new {status="ok",items=new[]{new {control="UAC",state="disabled",detail="EnableLUA policy"}}},config);
            Check(monitors.List(new[]{"security"},true).Length==1,"confirmed security finding");
            monitors.Sample("security",new {status="partial",items=new[]{new {control="UAC",state="unavailable",detail="No current measurement"}}},config);
            Check(monitors.List(new[]{"security"},true).Length==2,"keep finding while evidence is unavailable");
            monitors.Sample("security",new {status="ok",items=new[]{new {control="UAC",state="enabled",detail="EnableLUA policy"}}},config);
            Check(monitors.List(new[]{"security"},true).Length==0,"confirmed recovery");
            CheckSecurityEvidence();
            TestWire("udp");TestWire("tcp");SiemChecks.Run(dir);
        }
        static void CheckSecurityEvidence(){
            var j=Config.Json();var evidence=new AiEvidence();
            var endpoint=j.DeserializeObject(j.Serialize(new {collectedUtc="2026-01-01T00:00:00Z",stale=false,result=new {
                status="scanning",engineOnline=true,engineVersion="ClamAV fixture",signatureDatabaseVersion="12345",signatureFreshness="Current",infectedChecks=2,cleanChecks=12,failedChecks=1,violations=1,scanRunning=true,
                signatureMaintenance=new {status="Updated",detail="Downloaded https://provider.invalid/credential-fixture/database.hdb"},
                items=Enumerable.Range(0,41).Select(i=>new {path="C:/fixture/"+i,change="Malware signature",severity=i==40?"critical":"warning",detail="Test only",actualHash="fixture-hash"}).ToArray(),
                canaries=new[]{new {path="C:/canary.docx",status="critical",expectedHash="baseline-fixture"}},
                scanActivity=new[]{new {path="C:/test.txt",result="Infected",detail="Fixture.Signature FOUND",durationMs=3}},
                recentIncidents=new[]{new {path="C:/test.txt",severity="critical",change="Malware signature"}},
                quarantineItems=new[]{new {path="C:/test.txt",state="Quarantined",sha256="fixture-hash"}}
            }}));
            evidence.SecuritySnapshot("endpoint_protection",endpoint,true);
            var integrity=j.DeserializeObject(j.Serialize(new {collectedUtc="2026-01-01T00:00:00Z",stale=true,result=new {status="ok",chainValid=true,sequence=7,violations=1,items=new[]{new {path="C:/modified.exe",change="Modified file",severity="critical",expectedHash="old",actualHash="new"}}}}));
            evidence.SecuritySnapshot("data_integrity",integrity,true);
            string exact=evidence.SecurityFacts(),chunks=string.Join("\n",evidence.Chunks());
            Check(exact.Contains("ClamAV fixture")&&exact.Contains("12345")&&exact.Contains("infectedChecks")&&exact.Contains("C:/fixture/40"),"ClamAV exact facts and critical priority");
            Check(exact.Contains("chainValid")&&exact.Contains("C:/modified.exe")&&exact.Contains("canaryStatusCounts")&&exact.Contains("quarantineSampleCounts"),"integrity and endpoint facts");
            Check(chunks.Contains("Fixture.Signature FOUND")&&chunks.Contains("endpoint_protection-recentIncidents")&&chunks.Contains("endpoint_protection-quarantineItems")&&chunks.Contains("\"omitted\":11"),"bounded detailed evidence");
            Check(!exact.Contains("credential-fixture")&&!chunks.Contains("credential-fixture"),"URL credential redaction");
            Check(evidence.Missing.Contains("data_integrity (stale)")&&!evidence.Missing.Contains("endpoint_protection (scanning)"),"stale and scanning distinction");
            var disabled=new AiEvidence();disabled.SecuritySnapshot("endpoint_protection",j.DeserializeObject("{\"status\":\"disabled\"}"),false);
            Check(disabled.SecurityFacts().Contains("disabled")&&disabled.Missing.Count==1,"disabled protection remains explicit");
        }
        static void TestWire(string transport){
            var endpoint=new IPEndPoint(IPAddress.Loopback,0);
            var rows=new List<object[]>{new object[]{3L,History.Now(),2L,"Network","ping","Δοκιμή","192.0.2.8",null,null}};
            var s=new LogSettings{SyslogHost="127.0.0.1",SyslogTransport=transport};
            string message;
            if(transport=="udp")using(var udp=new UdpClient(endpoint)){
                udp.Client.ReceiveTimeout=3000;s.SyslogPort=((IPEndPoint)udp.Client.LocalEndPoint).Port;
                SyslogSender.Send(s,rows,CancellationToken.None);message=Encoding.UTF8.GetString(udp.Receive(ref endpoint));
            }else{
                var server=new TcpListener(endpoint);server.Start();
                try{s.SyslogPort=((IPEndPoint)server.LocalEndpoint).Port;
                    SyslogSender.Send(s,rows,CancellationToken.None);
                    using(var connection=server.AcceptTcpClient())using(var reader=new StreamReader(connection.GetStream(),Encoding.UTF8)){
                        connection.ReceiveTimeout=3000;string wire=reader.ReadToEnd();int sp=wire.IndexOf(' ');
                        Check(int.Parse(wire.Substring(0,sp))==Encoding.UTF8.GetByteCount(wire.Substring(sp+1)),"TCP byte-count framing");message=wire.Substring(sp+1);
                    }
                }finally{server.Stop();}
            }
            Check(message.StartsWith("<132>1 ")&&message.Contains("LinkScope - Network - ")&&message.Contains("Δοκιμή"),transport+" syslog priority, header and Unicode");
        }
    }
}
