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
        internal string Method,Path,Query,Body,AuditActor,AuditResult,AuditAction;
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
    // Bounded token buckets: per peer and global. Monotonic time avoids wall-clock jumps.
    internal sealed class RequestRateGate {
        sealed class Bucket {internal double Tokens,Updated,Seen;}
        readonly Dictionary<string,Bucket> peers=new Dictionary<string,Bucket>(StringComparer.Ordinal);
        readonly Bucket global=new Bucket{Tokens=240};
        readonly Stopwatch clock=Stopwatch.StartNew();
        readonly object gate=new object();
        internal bool Allow(string peer){return AllowAt(peer,clock.Elapsed.TotalSeconds);}
        internal bool AllowAt(string peer,double now){
            lock(gate){
                Bucket local;
                if(!peers.TryGetValue(peer,out local)){
                    if(peers.Count>=1024){foreach(var key in peers.Where(x=>now-x.Value.Seen>=300).Select(x=>x.Key).ToArray())peers.Remove(key);}
                    if(peers.Count>=1024)return false;
                    peers[peer]=local=new Bucket{Tokens=100,Updated=now,Seen=now};
                }
                Refill(local,now,30,100);Refill(global,now,120,240);local.Seen=now;
                if(local.Tokens<1||global.Tokens<1)return false;
                local.Tokens--;global.Tokens--;return true;
            }
        }
        static void Refill(Bucket b,double now,double rate,double cap){
            if(now>b.Updated){b.Tokens=Math.Min(cap,b.Tokens+(now-b.Updated)*rate);b.Updated=now;}
        }
    }
    // Optional fail-closed deployment policy, loaded only at service startup from the
    // administrator-owned ProgramData root (not the service-writable settings directory).
    public sealed class ProductionTransportPolicy {
        public string[] AllowedDestinations {get;set;}
        static volatile ProductionTransportPolicy current;
        internal static bool Active {get{return current!=null;}}
        internal static string PolicyPath {get{return Path.Combine(Config.Root,"production-transport.json");}}
        static string Key(string host,int port){
            host=host.Trim('[',']').TrimEnd('.').ToLowerInvariant();IPAddress ip;
            if(IPAddress.TryParse(host,out ip)){if(ip.IsIPv4MappedToIPv6)ip=ip.MapToIPv4();host=ip.ToString();}
            return (host.Contains(":")?"["+host+"]":host)+":"+port.ToString(CultureInfo.InvariantCulture);
        }
        internal void Validate(){
            if(AllowedDestinations==null||AllowedDestinations.Length>128)throw new InvalidDataException("Production transport policy must contain an AllowedDestinations array (maximum 128 entries).");
            var keys=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach(string entry in AllowedDestinations){Uri uri;
                if(string.IsNullOrEmpty(entry)||entry.Length>300||!Uri.TryCreate("https://"+entry,UriKind.Absolute,out uri)||
                   uri.UserInfo.Length!=0||uri.AbsolutePath!="/"||uri.Query.Length!=0||uri.Fragment.Length!=0||uri.Port<1||
                   !string.Equals(entry,Key(uri.DnsSafeHost,uri.Port),StringComparison.OrdinalIgnoreCase)||!keys.Add(entry))
                    throw new InvalidDataException("Use unique production destination entries in host:port format (IPv6 in brackets).");
            }
        }
        internal static void Initialize(Config cfg){
            ProductionTransportPolicy next=null;
            try{
                if((File.GetAttributes(PolicyPath)&FileAttributes.ReparsePoint)!=0)throw new InvalidDataException("Production transport policy must not be a reparse point.");
                using(var file=new FileStream(PolicyPath,FileMode.Open,FileAccess.Read,FileShare.Read)){
                    if(file.Length<2||file.Length>16384)throw new InvalidDataException("Invalid production transport policy size.");
                    using(var reader=new StreamReader(file,new UTF8Encoding(false,true)))next=Config.Json().Deserialize<ProductionTransportPolicy>(reader.ReadToEnd());
                }
            }catch(FileNotFoundException){current=null;return;}catch(DirectoryNotFoundException){current=null;return;}
            if(next==null)throw new InvalidDataException("Invalid production transport policy.");
            next.Validate();next.ValidateConfig(cfg);
            if(AdminPasswords.Installed.Revision()==null)throw new InvalidDataException("Set a permanent administrator password before activating the production transport policy.");
            current=next;
        }
        internal void Require(string host,int port,bool encrypted){
            if(!encrypted)throw new InvalidDataException("Production transport policy requires encrypted transport.");
            if(!AllowedDestinations.Contains(Key(host,port),StringComparer.OrdinalIgnoreCase))
                throw new InvalidDataException("Outbound destination is not in the administrator's production allowlist.");
        }
        void RequireUri(string url){var uri=new Uri(url);Require(uri.DnsSafeHost,uri.Port,uri.Scheme=="https");}
        internal void ValidateConfig(Config cfg){
            if(!cfg.UseHttps)throw new InvalidDataException("Production transport policy requires HTTPS for the LinkScope listener.");
            if(cfg.Ai.Enabled)RequireUri(cfg.Ai.Base(cfg.Ai.Provider));
            if(cfg.Delivery.EmailEnabled)Require(cfg.Delivery.SmtpHost,cfg.Delivery.SmtpPort,cfg.Delivery.Encryption!="plain");
            if(cfg.Siem.Seq.Enabled)RequireUri(cfg.Siem.Seq.BaseUrl);
            if(cfg.Siem.Elastic.Enabled)RequireUri(cfg.Siem.Elastic.BaseUrl);
            if(cfg.Siem.Wazuh.Enabled)throw new InvalidDataException("Production transport policy requires TLS. The direct Wazuh TCP/UDP integration is not TLS capable; use a TLS-capable relay instead.");
            if(cfg.Logging.SyslogEnabled)Require(cfg.Logging.SyslogHost,cfg.Logging.SyslogPort,cfg.Logging.SyslogTransport=="tls");
        }
        internal static void ValidateConfiguration(Config cfg){var policy=current;if(policy!=null)policy.ValidateConfig(cfg);}
        internal static bool Check(string host,int port,bool encrypted){var policy=current;if(policy==null)return false;policy.Require(host,port,encrypted);return true;}
    }
    // Administrators may deliberately configure private SMTP/SIEM/local AI destinations.
    // Reject special-use/metadata addresses; validate every result, never just the first.
    // HTTP DNS validation is a preflight, not a connection pin. Enforce egress ACLs too.
    internal static class OutboundGuard {
        internal static bool AllowedAddress(IPAddress address){
            if(address.IsIPv4MappedToIPv6)address=address.MapToIPv4();
            if(address.AddressFamily==AddressFamily.InterNetwork){
                byte[] a=address.GetAddressBytes();
                return a[0]!=0&&a[0]<224&&!(a[0]==169&&a[1]==254)&&
                    !(a[0]==100&&a[1]==100&&a[2]==100&&a[3]==200)&&
                    !(a[0]==168&&a[1]==63&&a[2]==129&&a[3]==16);
            }
            return address.AddressFamily==AddressFamily.InterNetworkV6&&!address.Equals(IPAddress.IPv6Any)&&
                !address.IsIPv6LinkLocal&&!address.IsIPv6Multicast&&!address.IsIPv6SiteLocal&&
                !address.Equals(IPAddress.Parse("fd00:ec2::254"));
        }
        internal static void ValidateAddresses(string host,IPAddress[] addresses){
            IPAddress literal;
            bool explicitLoopback=string.Equals(host,"localhost",StringComparison.OrdinalIgnoreCase)||
                (IPAddress.TryParse(host,out literal)&&IPAddress.IsLoopback(literal));
            if(addresses==null||addresses.Length==0||addresses.Any(a=>!AllowedAddress(a)||
                (IPAddress.IsLoopback(a.IsIPv4MappedToIPv6?a.MapToIPv4():a)&&!explicitLoopback)))
                throw new InvalidDataException("Outbound destination blocked by security policy (special-use address or unexpected loopback).");
        }
        internal static bool ValidateHttp(Uri uri){
            if(uri==null||!uri.IsAbsoluteUri||(uri.Scheme!="https"&&uri.Scheme!="http")||uri.UserInfo.Length!=0)
                throw new InvalidDataException("Invalid outbound HTTP destination.");
            string host=uri.DnsSafeHost.Trim('[',']');
            bool strict=ProductionTransportPolicy.Check(host,uri.Port,uri.Scheme=="https");
            var lookup=Dns.GetHostAddressesAsync(host);
            if(!lookup.Wait(5000))throw new IOException("Outbound destination DNS validation timed out.");
            ValidateAddresses(host,lookup.Result);return strict;
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
                .Append("\r\nContent-Length: ").Append(Bytes.Length).Append("\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\nCross-Origin-Resource-Policy: same-origin\r\nPermissions-Policy: camera=(), microphone=(), geolocation=()\r\nX-Permitted-Cross-Domain-Policies: none\r\n");
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
