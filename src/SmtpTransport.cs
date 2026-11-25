using System;
using System.Collections.Generic;
using System.Diagnostics;
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
    internal sealed class AlertMail {
        internal string Id, Subject, Body;
    }
    internal sealed class SmtpTransport {
        readonly DeliverySettings options;
        Stream stream;
        StreamReader reader;
        string phase="Connect",transport="plain SMTP",auth="no authentication";
        SmtpTransport(DeliverySettings settings){options=settings;}
        internal static string Send(DeliverySettings settings,AlertMail message,CancellationToken cancel){
            return new SmtpTransport(settings).Submit(message,cancel);
        }
        static TcpClient Connect(string host,int port,CancellationToken cancel){
            var lookup=Dns.GetHostAddressesAsync(host.Trim('[',']'));
            lookup.Wait(cancel);
            Exception last=null;
            foreach(var address in lookup.Result){
                cancel.ThrowIfCancellationRequested();
                if(address.AddressFamily==AddressFamily.InterNetworkV6&&!Socket.OSSupportsIPv6)continue;
                TcpClient candidate=null;
                try{
                    candidate=new TcpClient(address.AddressFamily);
                    using(cancel.Register(candidate.Close)){
                        var opening=candidate.ConnectAsync(address,port);
                        opening.Wait(cancel);
                    }
                    return candidate;
                }catch(Exception ex){
                    if(candidate!=null)candidate.Close();
                    cancel.ThrowIfCancellationRequested();last=ex.GetBaseException();
                }
            }
            throw new IOException(last==null?"No usable IP address for this relay.":last.Message);
        }
        string Submit(AlertMail message,CancellationToken cancel){
            var clock=Stopwatch.StartNew();
            using(var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancel)){
                deadline.CancelAfter(options.TimeoutSeconds*1000);
                try{
                    using(var client=Connect(options.SmtpHost,options.SmtpPort,deadline.Token))
                    using(deadline.Token.Register(client.Close)){
                        stream=client.GetStream();
                        if(options.Encryption=="tls")Upgrade();
                        else SetReader();
                        phase="Server greeting";Expect(Reply(),220);
                        var capabilities=Hello();
                        if(options.Encryption=="starttls"){
                            phase="STARTTLS";if(!capabilities.Contains("STARTTLS"))throw new IOException("The relay did not advertise STARTTLS.");
                            Write("STARTTLS");Expect(Reply(),220);Upgrade();capabilities=Hello();
                        }
                        Authenticate(capabilities);
                        phase="Sender";Write("MAIL FROM:<"+DeliverySettings.Addresses(options.From).Single()+">");Expect(Reply(),250);
                        var recipients=DeliverySettings.Addresses(options.To).Concat(DeliverySettings.Addresses(options.Cc)).Concat(DeliverySettings.Addresses(options.Bcc)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
                        phase="Recipients";
                        foreach(string address in recipients){Write("RCPT TO:<"+address+">");Expect(Reply(),250,251,252);}
                        phase="Message transfer";Write("DATA");Expect(Reply(),354);
                        Write(MessageText(options,message)+"\r\n.");
                        Expect(Reply(),250);
                        // After DATA is accepted, loss of the connection during QUIT cannot undo delivery.
                        try{Write("QUIT");}catch(IOException){}catch(ObjectDisposedException){}
                        return "Relay accepted the message for "+recipients.Length+" recipient(s) using "+transport+", "+auth+" ("+clock.ElapsedMilliseconds+" ms).";
                    }
                }catch(Exception ex){
                    if(cancel.IsCancellationRequested)throw new OperationCanceledException(cancel);
                    if(deadline.IsCancellationRequested)throw new IOException(phase+" timed out after "+options.TimeoutSeconds+" seconds.");
                    throw new IOException(phase+" failed. "+ex.GetBaseException().Message);
                }finally{if(reader!=null)reader.Dispose();if(stream!=null)stream.Dispose();}
            }
        }
        void SetReader(){reader=new StreamReader(stream,Encoding.ASCII,false,1024,true);}
        void Upgrade(){
            phase="TLS handshake";
            if(reader!=null){reader.Dispose();reader=null;}
            var tls=new SslStream(stream,false);stream=tls;
            tls.AuthenticateAsClient(options.SmtpHost.Trim('[',']'),null,SslProtocols.None,true);
            transport=tls.SslProtocol.ToString();SetReader();
        }
        void Write(string text){byte[] bytes=Encoding.ASCII.GetBytes(text+"\r\n");stream.Write(bytes,0,bytes.Length);stream.Flush();}
        sealed class Answer {internal int Code;internal readonly List<string> Lines=new List<string>();}
        Answer Reply(){
            var result=new Answer();int total=0;
            for(int i=0;i<100;i++){
                var b=new StringBuilder();int c;
                while((c=reader.Read())>=0&&c!='\n'){if(++total>32768||b.Length>=2048)throw new IOException("SMTP reply exceeds its limit.");if(c!='\r')b.Append((char)c);}
                if(c<0)throw new IOException("The relay closed the connection.");
                string line=b.ToString();int code;
                if(line.Length<3||!int.TryParse(line.Substring(0,3),out code)||(i>0&&code!=result.Code)||
                    (line.Length>3&&line[3]!='-'&&line[3]!=' '))throw new IOException("Invalid SMTP reply.");
                result.Code=code;result.Lines.Add(line.Length>4?line.Substring(4):"");
                if(line.Length==3||line[3]==' ')return result;
            }
            throw new IOException("Too many SMTP reply lines.");
        }
        static void Expect(Answer reply,params int[] codes){
            if(!codes.Contains(reply.Code))throw new IOException("SMTP "+reply.Code+". "+(reply.Code==535?"Check the username, password and relay authentication policy.":reply.Code==550?"Check the envelope addresses and relay permissions.":"The relay did not accept this step."));
        }
        HashSet<string> Hello(){
            phase="EHLO";Write("EHLO "+Environment.MachineName);var reply=Reply();
            if((reply.Code==500||reply.Code==502||reply.Code==504)&&options.Authentication=="none"&&options.Encryption!="starttls"){
                Write("HELO "+Environment.MachineName);Expect(Reply(),250);return new HashSet<string>();
            }
            Expect(reply,250);
            var capabilities=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach(var line in reply.Lines){
                var parts=line.Replace('=',' ').Split(new[]{' ','\t'},StringSplitOptions.RemoveEmptyEntries);
                if(parts.Length==0)continue;capabilities.Add(parts[0]);
                if(parts[0].Equals("AUTH",StringComparison.OrdinalIgnoreCase))foreach(var mechanism in parts.Skip(1))capabilities.Add("AUTH "+mechanism);
            }
            return capabilities;
        }
        void Authenticate(HashSet<string> features){
            if(options.Authentication=="none")return;
            phase="Authentication";
            string mode=options.Authentication=="auto"?(features.Contains("AUTH PLAIN")?"plain":"login"):options.Authentication;
            if(!features.Contains("AUTH "+mode))throw new IOException("The requested authentication method is unavailable.");
            byte[] secret=options.PasswordBytes(),user=Encoding.UTF8.GetBytes(options.Username);
            try{
                if(mode=="plain"){
                    byte[] token=new byte[user.Length+secret.Length+2];
                    try{Buffer.BlockCopy(user,0,token,1,user.Length);Buffer.BlockCopy(secret,0,token,user.Length+2,secret.Length);
                        string encoded=Convert.ToBase64String(token);
                        Write("AUTH PLAIN "+encoded);var answer=Reply();
                        if(answer.Code==501){Write("AUTH PLAIN");answer=Reply();}
                        if(answer.Code==334){Write(encoded);answer=Reply();}
                        Expect(answer,235);}
                    finally{Array.Clear(token,0,token.Length);}
                }else{
                    Write("AUTH LOGIN");Expect(Reply(),334);Write(Convert.ToBase64String(user));Expect(Reply(),334);Write(Convert.ToBase64String(secret));Expect(Reply(),235);
                }
                auth="AUTH "+mode.ToUpperInvariant();
            }finally{Array.Clear(secret,0,secret.Length);}
        }
        static string Words(string value){
            // Fold encoded words on Unicode scalar boundaries so Greek and other UTF-8 text survives.
            var pieces=new List<string>();var part=new StringBuilder();int count=0;
            for(int i=0;i<value.Length;){
                int n=char.IsSurrogatePair(value,i)?2:1;string glyph=value.Substring(i,n);i+=n;
                if(glyph.Any(char.IsControl))glyph=" ";
                int bytes=Encoding.UTF8.GetByteCount(glyph);
                if(count+bytes>42){pieces.Add(Encoded(part.ToString()));part.Clear();count=0;}
                part.Append(glyph);count+=bytes;
            }
            if(part.Length>0)pieces.Add(Encoded(part.ToString()));
            return string.Join("\r\n ",pieces);
        }
        static string Encoded(string value){return "=?UTF-8?B?"+Convert.ToBase64String(Encoding.UTF8.GetBytes(value))+"?=";}
        internal static string MessageText(DeliverySettings d,AlertMail mail){
            var b=new StringBuilder();
            b.Append("Date: ").Append(DateTime.UtcNow.ToString("ddd, dd MMM yyyy HH:mm:ss +0000",CultureInfo.InvariantCulture)).Append("\r\n");
            b.Append("Message-ID: <").Append(mail.Id).Append("@linkscope.local>\r\n");
            b.Append("From: ").Append(d.SenderName.Length==0?"":Words(d.SenderName)+" ").Append('<').Append(d.From).Append(">\r\n");
            b.Append("To: ").Append(string.Join(",\r\n ",DeliverySettings.Addresses(d.To))).Append("\r\n");
            if(d.Cc.Length>0)b.Append("Cc: ").Append(string.Join(",\r\n ",DeliverySettings.Addresses(d.Cc))).Append("\r\n");
            if(d.ReplyTo.Length>0)b.Append("Reply-To: ").Append(d.ReplyTo).Append("\r\n");
            b.Append("Subject: ").Append(Words((d.SubjectPrefix+" "+mail.Subject).Trim())).Append("\r\n");
            b.Append("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n");
            return b.Append(Convert.ToBase64String(Encoding.UTF8.GetBytes(mail.Body),Base64FormattingOptions.InsertLineBreaks)).ToString();
        }
    }
}
