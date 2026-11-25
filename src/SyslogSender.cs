using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Threading;

namespace LinkScope {
    internal static class SyslogSender {
        static readonly int[] Severity={7,6,4,3};
        static string Token(string s,int max){
            var chars=s.Take(max).Select(c=>c>=33&&c<=126?c:'_').ToArray();
            return chars.Length==0?"-":new string(chars);
        }
        internal static byte[] Packet(object[] row,int facility){
            int level=Convert.ToInt32(row[2]);string module=(string)row[3],op=(string)row[4],peer=(string)row[6];
            string ts=new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc).AddSeconds((long)row[1]).ToString("yyyy-MM-ddTHH:mm:ssZ",CultureInfo.InvariantCulture);
            string header="<"+(facility*8+Severity[level]).ToString(CultureInfo.InvariantCulture)+">1 "+ts+" "+Token(Environment.MachineName,255)+" LinkScope - "+Token(module,32)+" - ";
            string body="id="+row[0]+" level="+(LogLevel)level+" module="+module+" operation="+op+
                (peer==""?"":" peer="+peer)+(row[7]==null?"":" status="+row[7])+(row[8]==null?"":" elapsedMs="+row[8])+" "+row[5];
            return Encoding.UTF8.GetBytes(header+"\uFEFF"+new string(body.Select(c=>char.IsControl(c)?' ':c).ToArray()));
        }
        internal static void Send(LogSettings settings,List<object[]> rows,CancellationToken stop){
            SendTo(settings.SyslogHost,settings.SyslogPort,settings.SyslogTransport,rows,r=>Packet(r,settings.SyslogFacility),false,stop);
        }
        internal static void SendTo(string hostname,int port,string transport,List<object[]> rows,Func<object[],byte[]> packet,bool newline,CancellationToken stop){
            using(var deadline=CancellationTokenSource.CreateLinkedTokenSource(stop)){
                deadline.CancelAfter(8000);
                var ct=deadline.Token;string host=hostname.Trim('[',']');
                var dns=Dns.GetHostAddressesAsync(host);dns.Wait(ct);
                Exception last=null;
                foreach(var ip in dns.Result){
                    if(ip.AddressFamily==AddressFamily.InterNetworkV6&&!Socket.OSSupportsIPv6)continue;
                    ct.ThrowIfCancellationRequested();
                    bool wrote=false;
                    try{
                        if(transport=="udp"){
                            using(var udp=new UdpClient(ip.AddressFamily))using(ct.Register(udp.Close)){
                                udp.Connect(ip,port);
                                foreach(var row in rows){ct.ThrowIfCancellationRequested();var b=packet(row);udp.Send(b,b.Length);wrote=true;}
                            }
                        }else using(var tcp=new TcpClient(ip.AddressFamily))using(ct.Register(tcp.Close)){
                            tcp.ConnectAsync(ip,port).Wait(ct);
                            using(var raw=tcp.GetStream()){
                                SslStream tls=null;
                                try{
                                    Stream stream=raw;
                                    if(transport=="tls"){
                                        tls=new SslStream(raw,true);
                                        tls.AuthenticateAsClient(host,null,SslProtocols.None,true);stream=tls;
                                    }
                                    foreach(var row in rows){
                                        ct.ThrowIfCancellationRequested();
                                        var b=packet(row);
                                        if(!newline){
                                            var prefix=Encoding.ASCII.GetBytes(b.Length.ToString(CultureInfo.InvariantCulture)+" ");
                                            stream.Write(prefix,0,prefix.Length);
                                        }
                                        stream.Write(b,0,b.Length);if(newline)stream.WriteByte(10);wrote=true;
                                    }stream.Flush();
                                }finally{if(tls!=null)tls.Dispose();}
                            }
                        }
                        return;
                    }catch(Exception ex){ct.ThrowIfCancellationRequested();if(wrote)throw;last=ex.GetBaseException();}
                }
                throw new IOException("No syslog address accepted the connection.",last);
            }
        }
    }
}
