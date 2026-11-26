using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

// One bounded request per connection. No forwarding, chunked requests, pipelining or upgrades.
namespace LinkScope {
    internal sealed class HttpError:Exception {
        internal readonly int Status;internal HttpError(int status,string message):base(message){Status=status;}
    }
    internal sealed class Request {
        internal string Method,Path,Query,Body,AuditActor,AuditResult;
        internal readonly Dictionary<string,string> Headers=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        internal string Header(string key){string v;return Headers.TryGetValue(key,out v)?v:null;}
        internal string Cookie(string name){
            string found=null;foreach(string pair in (Header("Cookie")??"").Split(';')){
                var part=pair.Trim().Split(new[]{'='},2);if(part.Length!=2||part[0]!=name)continue;
                if(found!=null)return null;found=part[1];
            }return found;
        }
        static HttpError Bad(){return new HttpError(400,"Invalid HTTP request.");}
        internal static Request Read(Stream stream){
            const int limit=12288;var buffer=new byte[limit];int used=0,end=-1;
            while(used<limit && end<0){
                int n=stream.Read(buffer,used,limit-used);if(n==0)throw Bad();int from=Math.Max(0,used-3);used+=n;
                for(int i=from;i<=used-4;i++)if(buffer[i]==13&&buffer[i+1]==10&&buffer[i+2]==13&&buffer[i+3]==10){end=i;break;}
            }
            if(end<0)throw new HttpError(431,"Headers too large.");
            for(int i=0;i<end;i++)if(buffer[i]>126||(buffer[i]<32&&buffer[i]!=13&&buffer[i]!=10))throw Bad();
            var lines=Encoding.ASCII.GetString(buffer,0,end).Split(new[]{"\r\n"},StringSplitOptions.None);
            if(lines.Length>64)throw Bad();var first=lines[0].Split(' ');
            if(first.Length!=3||first[2]!="HTTP/1.1"||!first[1].StartsWith("/")||first[1].StartsWith("//")||first[1].Contains("#")||first[1].Contains("\\")||first[1].Any(char.IsControl)||first[1].Length>2048)throw Bad();
            if(first[0]!="GET"&&first[0]!="POST")throw new HttpError(405,"Method unavailable.");
            var path=first[1].Split(new[]{'?'},2);var r=new Request{Method=first[0],Path=path[0],Query=path.Length>1?path[1]:""};
            foreach(var line in lines.Skip(1)){
                int split=line.IndexOf(':');if(split<1)throw Bad();var name=line.Substring(0,split);var value=line.Substring(split+1).Trim(' ');
                if(name.Any(c=>!(c>='a'&&c<='z'||c>='A'&&c<='Z'||c>='0'&&c<='9'||c=='-'))||value.Any(char.IsControl)||r.Headers.ContainsKey(name))throw Bad();
                r.Headers.Add(name,value);
            }
            if(r.Header("Host")==null||r.Header("Transfer-Encoding")!=null||r.Header("Content-Encoding")!=null||r.Header("Expect")!=null||r.Header("Upgrade")!=null)throw Bad();
            int length=0;string size=r.Header("Content-Length");
            if(size!=null&&!int.TryParse(size,NumberStyles.None,CultureInfo.InvariantCulture,out length))throw Bad();
            if(length>48*1024)throw new HttpError(413,"Body too large.");
            if(first[0]=="GET"&&length!=0||first[0]=="POST"&&(length<2||!(r.Header("Content-Type")??"").Split(';')[0].Trim().Equals("application/json",StringComparison.OrdinalIgnoreCase)))throw Bad();
            int offset=end+4,count=used-offset;if(count>length)throw Bad();var body=new byte[length];Array.Copy(buffer,offset,body,0,count);
            while(count<length){int n=stream.Read(body,count,length-count);if(n==0)throw Bad();count+=n;}
            try{r.Body=new UTF8Encoding(false,true).GetString(body);}catch(DecoderFallbackException){throw Bad();}return r;
        }
    }
    internal sealed class Reply {
        internal bool RestartAccepted;
        internal int Code=200;internal string Mime="application/json; charset=utf-8",Cookie,Location;internal byte[] Bytes;
        internal static Reply Json(object value){return new Reply{Bytes=Encoding.UTF8.GetBytes(Config.Json().Serialize(value))};}
        internal static Reply Error(int status,string message){var r=Json(new {error=message});r.Code=status;return r;}
        internal void Send(Stream s,bool tls){
            var reason=((HttpStatusCode)Code).ToString();
            var h=new StringBuilder("HTTP/1.1 ").Append(Code).Append(" ").Append(reason).Append("\r\nContent-Type: ").Append(Mime)
                .Append("\r\nContent-Length: ").Append(Bytes.Length).Append("\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\nCross-Origin-Resource-Policy: same-origin\r\nPermissions-Policy: camera=(), microphone=(), geolocation=()\r\n");
            h.Append("Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; manifest-src 'self'; worker-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'\r\n");
            if(tls)h.Append("Strict-Transport-Security: max-age=31536000\r\n");
            if(Location!=null)h.Append("Location: ").Append(Location).Append("\r\n");
            if(Cookie!=null)h.Append("Set-Cookie: ").Append(Cookie).Append("\r\n");
            if(Code==429)h.Append("Retry-After: 300\r\n");
            if(Code==401)h.Append("WWW-Authenticate: Bearer realm=\"LinkScope\"\r\n");
            byte[] headers=Encoding.ASCII.GetBytes(h.Append("\r\n").ToString());s.Write(headers,0,headers.Length);s.Write(Bytes,0,Bytes.Length);
        }
    }
}
