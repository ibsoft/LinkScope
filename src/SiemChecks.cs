using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace LinkScope {
    internal static class SiemChecks {
        static void Check(bool ok,string message){if(!ok)throw new InvalidOperationException("SIEM self-test: "+message);}
        internal static void Run(string directory){
            var rows=new List<object[]>{new object[]{12L,1795600000L,1L,"Network","probe","Line one\nΔύο","192.0.2.9",200L,31L}};
            var cfg=new SiemSettings();
            cfg.Elastic.ProtectedKey="ignored-browser-value";cfg=SiemSettings.Merge(new SiemSettings(),new SiemEdit{Siem=cfg,NewElasticKey="test-key"});
            Check(cfg.Elastic.Key()=="test-key"&&cfg.PublicCopy().Elastic.ProtectedKey=="","DPAPI redaction");
            var attempt=cfg.PublicCopy();attempt.Elastic.BaseUrl="https://other.example";
            bool denied=false;try{SiemSettings.Merge(cfg,new SiemEdit{Siem=attempt});}catch(InvalidDataException){denied=true;}Check(denied,"key bound to receiver");
            var two=new List<object[]>(rows){new object[]{13L,1795600000L,1L,"API","GET","OK","",null,null}};
            var partial=SiemSender.ElasticResult("{\"items\":[{\"create\":{\"_id\":\"host-12\",\"status\":409,\"error\":{\"type\":\"version_conflict_engine_exception\"}}},{\"create\":{\"_id\":\"host-13\",\"status\":429}}]}","host",two);
            Check(partial.Accepted.SequenceEqual(new long[]{12})&&partial.Problem.Contains("429"),"partial bulk acknowledgement");
            TestHttp("Seq",rows);TestHttp("Elastic",rows);TestWazuh("tcp",rows);TestWazuh("udp",rows);
            string path=Path.Combine(directory,"siem-check.sqlite");
            var options=new LogSettings();
            var enabled=new SiemSettings();enabled.Seq.Enabled=true;enabled.Seq.BaseUrl="https://seq.example";enabled.Elastic.Enabled=true;enabled.Elastic.BaseUrl="https://elastic.example";
            using(var log=new AppJournal(path,options,false,enabled)){
                string data=Config.Json().Serialize(log.TestSiem("Seq"));Check(data.Contains("eventId"),"queued test receipt");
                using(var db=new Sqlite(path,false)){
                    Check((long)db.Rows("SELECT count(*) FROM siem_queue WHERE receiver='Seq'")[0][0]==1,"targeted queue");
                    Check((long)db.Rows("SELECT count(*) FROM siem_queue WHERE receiver='Elastic'")[0][0]==0,"isolated test");
                }
            }
            using(var log=new AppJournal(path,options,false,enabled)){
                using(var db=new Sqlite(path,false))Check((long)db.Rows("SELECT count(*) FROM siem_queue")[0][0]==1,"pending survives restart");
                var changed=enabled.PublicCopy();changed.Seq.BaseUrl="https://new.example";log.Configure(options,changed);
                using(var db=new Sqlite(path,false)){
                    Check((long)db.Rows("SELECT count(*) FROM siem_queue")[0][0]==0,"old receiver backlog cleared");
                    Check((long)db.Rows("SELECT count(*) FROM app_log")[0][0]==1,"local history retained");
                }
            }
        }
        static string Line(Stream stream){
            var data=new List<byte>();int b;
            while((b=stream.ReadByte())!=-1&&b!=10){if(data.Count>8192)throw new IOException("Test line too long.");if(b!=13)data.Add((byte)b);}
            return Encoding.UTF8.GetString(data.ToArray());
        }
        static void TestHttp(string kind,List<object[]> rows){
            var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();Exception error=null;
            var expected=kind=="Seq"?"/ingest/clef":"/linkscope-logs/_bulk";
            var cfg=new SiemSettings();var receiver=kind=="Seq"?cfg.Seq:cfg.Elastic;
            receiver.Enabled=true;receiver.BaseUrl="http://127.0.0.1:"+((IPEndPoint)listener.LocalEndpoint).Port;cfg.Validate();
            var server=new Thread(delegate(){
                try{using(var client=listener.AcceptTcpClient())using(var stream=client.GetStream()){
                    stream.ReadTimeout=6000;Check(Line(stream).StartsWith("POST "+expected+" "),"ingestion route");
                    var headers=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
                    for(string line;(line=Line(stream)).Length>0;){var colon=line.IndexOf(':');headers.Add(line.Substring(0,colon),line.Substring(colon+1).Trim());}
                    if(headers.ContainsKey("Expect")){var ack=Encoding.ASCII.GetBytes("HTTP/1.1 100 Continue\r\n\r\n");stream.Write(ack,0,ack.Length);}
                    int length=int.Parse(headers["Content-Length"]);var body=new byte[length];
                    for(int n=0;n<length;){int count=stream.Read(body,n,length-n);if(count==0)throw new EndOfStreamException();n+=count;}
                    string payload=Encoding.UTF8.GetString(body);var lines=payload.TrimEnd('\n').Split('\n');
                    Check(payload.EndsWith("\n")&&headers["Content-Type"].Contains(kind=="Seq"?"vnd.serilog.clef":"x-ndjson"),"wire format");
                    var obj=Config.Json().Deserialize<Dictionary<string,object>>(lines.Last());
                    Check(kind=="Seq"?lines.Length==1&&Equals(obj["@l"],"Information")&&Equals(obj["@m"],rows[0][5]):lines.Length==2&&lines[0].Contains("host-12")&&Equals(obj["message"],rows[0][5]),"structured event and escaping");
                    string reply=kind=="Seq"?"{}":"{\"items\":[{\"create\":{\"_id\":\"host-12\",\"status\":201}}]}";
                    var packet=Encoding.ASCII.GetBytes("HTTP/1.1 "+(kind=="Seq"?"201 Created":"200 OK")+"\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "+reply.Length+"\r\n\r\n"+reply);
                    stream.Write(packet,0,packet.Length);
                }}catch(Exception ex){error=ex;}
            }){IsBackground=true};
            server.Start();
            try{var result=SiemSender.Send(kind,cfg,"host",rows,CancellationToken.None);Check(result.Accepted.SequenceEqual(new long[]{12}),"HTTP response handling");}
            finally{listener.Stop();server.Join(7000);}
            if(error!=null)throw error;
        }
        static void TestWazuh(string transport,List<object[]> rows){
            string message;var endpoint=new IPEndPoint(IPAddress.Loopback,0);var cfg=new SiemSettings();
            cfg.Wazuh.Enabled=true;cfg.Wazuh.Host="127.0.0.1";cfg.Wazuh.Transport=transport;
            if(transport=="udp")using(var udp=new UdpClient(endpoint)){
                cfg.Wazuh.Port=((IPEndPoint)udp.Client.LocalEndPoint).Port;udp.Client.ReceiveTimeout=3000;
                SiemSender.Send("Wazuh",cfg,"host",rows,CancellationToken.None);message=Encoding.UTF8.GetString(udp.Receive(ref endpoint));
            }else{
                var tcp=new TcpListener(endpoint);tcp.Start();
                try{cfg.Wazuh.Port=((IPEndPoint)tcp.LocalEndpoint).Port;SiemSender.Send("Wazuh",cfg,"host",rows,CancellationToken.None);
                    using(var client=tcp.AcceptTcpClient())using(var reader=new StreamReader(client.GetStream(),Encoding.UTF8)){
                        message=reader.ReadToEnd();Check(message.EndsWith("\n")&&message.Count(c=>c=='\n')==1,"TCP newline framing");message=message.TrimEnd('\n');
                    }
                }finally{tcp.Stop();}
            }
            Check(message.StartsWith("<134>")&&message.Contains(" LinkScope: "),"syslog envelope");
            var item=Config.Json().Deserialize<Dictionary<string,object>>(message.Substring(message.IndexOf('{')));
            Check(Equals(item["EventId"],"host-12")&&Equals(item["Message"],rows[0][5]),"Wazuh JSON record");
        }
    }
}
