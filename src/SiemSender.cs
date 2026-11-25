using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;

namespace LinkScope {
    internal static class SiemSender {
        internal sealed class Result {
            internal readonly List<long> Accepted=new List<long>();
            internal string Problem="";
        }
        static string Id(string origin,object[] row){return origin+"-"+Convert.ToString(row[0],CultureInfo.InvariantCulture);}
        static Dictionary<string,object> Fields(string origin,object[] row){
            var d=new Dictionary<string,object>{
                {"Application","LinkScope"},{"Host",Environment.MachineName},{"EventId",Id(origin,row)},
                {"Module",row[3]},{"Operation",row[4]}
            };
            if(!string.IsNullOrEmpty(row[6] as string))d["Peer"]=row[6];
            if(row[7]!=null)d["HttpStatus"]=row[7];
            if(row[8]!=null)d["ElapsedMs"]=row[8];
            return d;
        }
        internal static string Payload(string kind,string origin,List<object[]> rows){
            var json=Config.Json();var body=new StringBuilder();
            foreach(var row in rows){
                var level=(LogLevel)Convert.ToInt32(row[2]);string time=Telemetry.Utc((long)row[1]);
                if(kind=="Seq"){
                    var d=Fields(origin,row);d["@t"]=time;d["@m"]=row[5];d["@l"]=level==LogLevel.Info?"Information":level.ToString();
                    body.Append(json.Serialize(d)).Append('\n');
                }else{
                    body.Append(json.Serialize(new {create=new {_id=Id(origin,row)}})).Append('\n');
                    var d=new Dictionary<string,object>{{"@timestamp",time},{"message",row[5]},
                        {"log",new {level=level.ToString().ToLowerInvariant(),logger=row[3]}},
                        {"event",new {id=Id(origin,row),action=row[4],module="linkscope"}},
                        {"host",new {name=Environment.MachineName}},{"service",new {name="LinkScope"}},
                        {"linkscope",Fields(origin,row)}};
                    body.Append(json.Serialize(d)).Append('\n');
                }
            }
            return body.ToString();
        }
        internal static byte[] WazuhPacket(string origin,object[] row){
            int level=Convert.ToInt32(row[2]);
            var d=Fields(origin,row);d["Timestamp"]=Telemetry.Utc((long)row[1]);d["Level"]=((LogLevel)level).ToString();d["Message"]=row[5];
            var date=new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc).AddSeconds((long)row[1]).ToLocalTime();
            var inv=CultureInfo.InvariantCulture;
            string stamp=date.ToString("MMM ",inv)+date.Day.ToString(inv).PadLeft(2)+' '+date.ToString("HH:mm:ss",inv);
            string header="<"+(128+new[]{7,6,4,3}[level]).ToString(inv)+">"+stamp+" "+Environment.MachineName+" LinkScope: ";
            return Encoding.UTF8.GetBytes(header+Config.Json().Serialize(d));
        }
        internal static Result ElasticResult(string response,string origin,List<object[]> rows){
            var root=Config.Json().DeserializeObject(response) as Dictionary<string,object>;
            object items;var array=root!=null&&root.TryGetValue("items",out items)?items as IList:null;
            if(array==null||array.Count!=rows.Count)throw new InvalidDataException("Invalid Elasticsearch bulk receipt.");
            var result=new Result();
            for(int i=0;i<array.Count;i++){
                var item=array[i] as Dictionary<string,object>;object value;
                var receipt=item!=null&&item.TryGetValue("create",out value)?value as Dictionary<string,object>:null;
                object status,id;
                if(receipt==null||!receipt.TryGetValue("status",out status)||!(status is int)||!receipt.TryGetValue("_id",out id)||!Equals(id,Id(origin,rows[i])))
                    throw new InvalidDataException("Invalid Elasticsearch item receipt.");
                int code=(int)status;
                object error,type;
                var detail=receipt.TryGetValue("error",out error)?error as Dictionary<string,object>:null;
                bool alreadyCreated=code==409&&detail!=null&&detail.TryGetValue("type",out type)&&Equals(type,"version_conflict_engine_exception");
                if(code==201||alreadyCreated)result.Accepted.Add((long)rows[i][0]);
                else if(result.Problem=="")result.Problem="Elasticsearch item HTTP "+code+".";
            }
            return result;
        }
        internal static Result Send(string kind,SiemSettings cfg,string origin,List<object[]> rows,CancellationToken stop){
            var result=new Result();
            if(kind=="Wazuh"){
                var w=cfg.Wazuh;
                SyslogSender.SendTo(w.Host,w.Port,w.Transport,rows,r=>WazuhPacket(origin,r),true,stop);
            }else{
                bool seq=kind=="Seq";var receiver=seq?cfg.Seq:cfg.Elastic;
                string url=receiver.BaseUrl+(seq?"/ingest/clef":"/"+receiver.Index+"/_bulk");
                var req=(HttpWebRequest)WebRequest.Create(url);
                req.Method="POST";req.AllowAutoRedirect=false;req.Timeout=12000;req.ReadWriteTimeout=12000;
                req.ContentType=seq?"application/vnd.serilog.clef":"application/x-ndjson";
                var key=receiver.Key();
                if(key!=""){if(seq)req.Headers["X-Seq-ApiKey"]=key;else req.Headers["Authorization"]="ApiKey "+key;}
                var bytes=Encoding.UTF8.GetBytes(Payload(kind,origin,rows));req.ContentLength=bytes.Length;
                using(var deadline=CancellationTokenSource.CreateLinkedTokenSource(stop)){
                    deadline.CancelAfter(15000);
                    using(deadline.Token.Register(req.Abort))try{
                        using(var stream=req.GetRequestStream())stream.Write(bytes,0,bytes.Length);
                        using(var resp=(HttpWebResponse)req.GetResponse()){
                            int code=(int)resp.StatusCode;
                            if(code!=(seq?201:200))throw new InvalidDataException(kind+" returned HTTP "+code+". Check the receiver URL.");
                            if(!seq){
                                using(var reader=new StreamReader(resp.GetResponseStream(),Encoding.UTF8)){
                                    var text=new StringBuilder();var chunk=new char[4096];int n;
                                    while((n=reader.Read(chunk,0,chunk.Length))>0){
                                        if(text.Length+n>1024*1024)throw new InvalidDataException("Elasticsearch response exceeded 1 MiB.");
                                        text.Append(chunk,0,n);
                                    }
                                    return ElasticResult(text.ToString(),origin,rows);
                                }
                            }
                        }
                    }catch(WebException ex){
                        stop.ThrowIfCancellationRequested();
                        using(var resp=ex.Response as HttpWebResponse){
                            throw new InvalidDataException(resp==null?kind+" transport error ("+ex.Status+").":kind+" returned HTTP "+(int)resp.StatusCode+".");
                        }
                    }
                }
            }
            result.Accepted.AddRange(rows.Select(r=>(long)r[0]));
            return result;
        }
    }
}
