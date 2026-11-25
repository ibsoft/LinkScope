using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Web;

namespace LinkScope {
    public sealed class LoginInput {public string user{get;set;}public string password{get;set;}public string newPassword{get;set;}}
    public sealed class TokenInput {public string name{get;set;}public int days{get;set;}public string[] categories{get;set;}public string id{get;set;}}
    public sealed class AlertReadBatch { public long through {get;set;} }
    internal sealed class Web:IDisposable {
        readonly Config running;
        readonly string instanceId=Guid.NewGuid().ToString("N");
        readonly ManualResetEventSlim restartReplySent=new ManualResetEventSlim(true);
        long lastRestartRequest;
        bool RestartNeeded(Config next){
            return next.Origin()!=running.Origin()||next.BindAddress!=running.BindAddress||next.CertificateThumbprint!=running.CertificateThumbprint||
                next.IntervalSeconds!=running.IntervalSeconds||next.TimeoutMs!=running.TimeoutMs||next.InterfaceName!=running.InterfaceName||
                !next.Targets.Select(t=>t.Address+" "+t.Name).SequenceEqual(running.Targets.Select(t=>t.Address+" "+t.Name));
        }
        Reply RequestRestart(){
            if(!Program.ServiceMode)throw new HttpError(409,"Restart the console process on the monitoring host.");
            if(!RestartNeeded(settings))throw new HttpError(409,"No saved changes require a restart.");
            if(History.Now()-lastRestartRequest<120)throw new HttpError(409,"A restart has already been requested.");
            restartReplySent.Reset();
            try{
                Program.QueueServiceRestart();lastRestartRequest=History.Now();
                var reply=Reply.Json(new {accepted=true,instanceId=instanceId,activeOrigin=running.Origin(),nextOrigin=settings.Origin()});
                reply.Code=202;reply.RestartAccepted=true;return reply;
            }catch{restartReplySent.Set();throw;}
        }
        Config settings;
        readonly Collector collector;
        readonly Alerts alerts;
        readonly AlertDelivery outputs;
        readonly Telemetry monitor;
        readonly AiAssist ai=new AiAssist();
        readonly Access access=new Access();
        readonly object mutation=new object();
        readonly TcpListener listener;
        readonly Dictionary<string,Reply> assets=new Dictionary<string,Reply>();
        readonly HashSet<TcpClient> active=new HashSet<TcpClient>();
        readonly SemaphoreSlim passwordWorkers=new SemaphoreSlim(2), historyWorkers=new SemaphoreSlim(4);
        X509Certificate2 cert;
        Thread thread;volatile bool stopping;
        internal Web(Config c,Collector collector,Alerts alerts,AlertDelivery outputs){
            this.outputs=outputs;
            this.collector=collector;settings=running=c;listener=new TcpListener(IPAddress.Parse(c.BindAddress),c.Port);this.alerts=alerts;alerts.Trim(c.Categories().Concat(new[]{"network"}).ToArray());monitor=new Telemetry(c,alerts);
            Asset("/","dashboard.html","text/html");Asset("/login","login.html","text/html");Asset("/system","system.html","text/html");Asset("/settings","settings.html","text/html");Asset("/alerts","alerts.html","text/html");Asset("/logs","logs.html","text/html");Asset("/ai","ai.html","text/html");
            foreach(var file in new[]{"loading.js","loading.css","ai.js","ai.css","logs.js","paging.js","charts.js","dashboard.js","report.js","app.js","pdf-lib.min.js","app.css","dashboard.css","toast.js","toast.css"}){
                string url=file=="pdf-lib.min.js"?"pdf-lib.js":file;Asset("/assets/"+url,file,file.EndsWith(".js")?"application/javascript":"text/css");}
        }
        void Asset(string url,string file,string mime){assets[url]=new Reply{Mime=mime+"; charset=utf-8",Bytes=Program.Resource(file)};}
        Reply PageAsset(string path){
            var template=assets[path];
            string title=(settings.BrandLabel.Length==0?"":settings.BrandLabel+" ")+"LinkScope";
            string html=System.Text.Encoding.UTF8.GetString(template.Bytes).Replace("{{brand}}",WebUtility.HtmlEncode(title));
            return new Reply{Mime=template.Mime,Bytes=System.Text.Encoding.UTF8.GetBytes(html)};
        }
        static long? Cursor(Request r,string field){
            if(r.Query.Length==0)return null;
            var q=HttpUtility.ParseQueryString(r.Query);
            long value;
            if(q.Count!=1||q.AllKeys[0]!=field||!long.TryParse(q[field],System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,out value))throw new HttpError(400,"Invalid notification cursor.");
            return value;
        }
        static X509Certificate2 Certificate(Config c){
            string thumb=c.CertificateThumbprint.Length>0?c.CertificateThumbprint:File.ReadAllText(Path.Combine(Config.Root,"self-signed.thumbprint")).Trim();
            using(var store=new X509Store(StoreName.My,StoreLocation.LocalMachine)){
                store.Open(OpenFlags.ReadOnly);var list=store.Certificates.Find(X509FindType.FindByThumbprint,thumb,false);
                if(list.Count!=1||!list[0].HasPrivateKey||DateTime.Now<list[0].NotBefore||DateTime.Now>=list[0].NotAfter)
                    throw new InvalidDataException("Choose a current server certificate with a private key in Local Machine / Personal.");
                // Fail before binding if the service identity cannot open the selected private key.
                using(var key=System.Security.Cryptography.X509Certificates.RSACertificateExtensions.GetRSAPrivateKey(list[0])){
                    if(key==null){
                        using(var ec=ECDsaCertificateExtensions.GetECDsaPrivateKey(list[0])){if(ec==null)throw new InvalidDataException("Select an RSA or ECDSA TLS server certificate.");ec.SignData(new byte[32],System.Security.Cryptography.HashAlgorithmName.SHA256);}
                    }else key.SignData(new byte[32],System.Security.Cryptography.HashAlgorithmName.SHA256,System.Security.Cryptography.RSASignaturePadding.Pkcs1);
                }
                return list[0];
            }
        }
        internal void Start(){if(running.UseHttps)cert=Certificate(running);listener.Server.ExclusiveAddressUse=true;listener.Start(32);
            monitor.Start();thread=new Thread(Accept){IsBackground=true,Name="LinkScope web"};thread.Start();}
        void Accept(){
            while(!stopping)try{var client=listener.AcceptTcpClient();
                lock(active){if(stopping||active.Count>=24){client.Close();continue;}active.Add(client);}
                ThreadPool.QueueUserWorkItem(delegate{try{Serve(client);}catch(IOException){}catch(SocketException){}catch(AuthenticationException){}catch(ObjectDisposedException){}catch(Exception ex){Program.Log(ex);}
                    finally{client.Close();lock(active){active.Remove(client);Monitor.PulseAll(active);}}});
            }catch(SocketException){if(!stopping)Thread.Sleep(50);}catch(ObjectDisposedException){break;}
        }
        void Serve(TcpClient client){
            string ip=((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString();
            client.ReceiveTimeout=6000;client.SendTimeout=8000;
            using(var deadline=new Timer(delegate{client.Close();},null,15000,Timeout.Infinite))
            using(var raw=client.GetStream()){
                SslStream tls=null;Stream stream=raw;
                try{
                    if(cert!=null){tls=new SslStream(raw,true);tls.AuthenticateAsServer(cert,false,SslProtocols.Tls12,false);stream=tls;}
                    Reply reply;Request req=null;var timer=System.Diagnostics.Stopwatch.StartNew();
                    try{req=Request.Read(stream);
                        if(!HostAllowed(req.Header("Host")))throw new HttpError(400,"Unexpected host.");
                        reply=Route(req,ip);
                    }catch(HttpError ex){reply=Reply.Error(ex.Status,ex.Message);}
                    catch(InvalidDataException ex){reply=Reply.Error(400,ex.Message);}
                    catch(Exception ex){Program.Log(ex);reply=Reply.Error(503,"LinkScope could not complete this request.");}
                    try{AuditRequest(req,reply.Code,ip,timer.ElapsedMilliseconds);reply.Send(stream,cert!=null);}
                    finally{if(reply.RestartAccepted)restartReplySent.Set();}
                }finally{if(tls!=null)tls.Dispose();}
            }
        }
        static readonly HashSet<string> knownRoutes=new HashSet<string>{"/ui/connections","/ui/restart","/ui/siem-test","/ui/ai","/ui/ai/ask","/ui/ai/result","/ui/ai/clear","/ui/ai/cancel","/ai","/ui/logs/summary","/","/alerts","/api/history","/api/v1/system","/auth/login","/auth/logout","/login","/logs","/settings","/system","/ui/alert-delivery","/ui/alerts","/ui/alerts/history","/ui/alerts/read","/ui/alerts/read-all","/ui/alerts/search","/ui/logs/search","/ui/report","/ui/report-system","/ui/resource-history","/ui/session","/ui/settings","/ui/smtp-test","/ui/system","/ui/tokens","/ui/tokens/revoke"};
        void AuditRequest(Request req,int code,string ip,long elapsed){
            string route=req==null?"malformed":knownRoutes.Contains(req.Path)?req.Path:assets.ContainsKey(req.Path)?"asset":"unknown";
            string method=req==null?"HTTP":req.Method;
            string module=route.StartsWith("/ui/ai")?"AI":route.StartsWith("/auth/")?"Auth":route.StartsWith("/ui/tokens")?"Tokens":route=="/ui/settings"?"Settings":
                route=="/api/v1/system"?"API":route.StartsWith("/ui/report")?"Reports":route=="/api/history"||route=="/ui/resource-history"?"History":
                route.StartsWith("/ui/alerts")?"Alerts":route=="/ui/smtp-test"?"SMTP":route=="/ui/logs/search"?"Logging":"Web";
            LogLevel level=code>=500?LogLevel.Error:code>=400?LogLevel.Warning:method=="POST"||module=="API"||route=="/ui/report"?LogLevel.Info:LogLevel.Debug;
            AppJournal.Event(level,module,method+" "+route,"HTTP "+code+".",ip,code,elapsed);
        }
        bool HostAllowed(string host){
            if(string.Equals(host,new Uri(running.Origin()).Authority,StringComparison.OrdinalIgnoreCase))return true;
            return !running.UseHttps && string.Equals(host,new UriBuilder("http","localhost",running.Port).Uri.Authority,StringComparison.OrdinalIgnoreCase);
        }
        string CookieName(){return running.UseHttps?"__Host-LinkScope":"LinkScopeLocal";}
        string Cookie(string value,bool clear){return CookieName()+"="+value+"; Path=/; HttpOnly; SameSite=Strict"+(running.UseHttps?"; Secure":"")+(clear?"; Max-Age=0":"");}
        static T Decode<T>(Request r) where T:class{try{var o=Config.Json().Deserialize<T>(r.Body);if(o==null)throw new FormatException();return o;}
            catch(Exception){throw new HttpError(400,"Invalid JSON request.");}}
        DeliverySettings SubmittedDelivery(Request request,bool test){
            var edit=Decode<DeliveryInput>(request);
            if(edit.Delivery==null){if(test)throw new HttpError(400,"Supply SMTP settings.");return settings.Delivery;}
            var d=edit.Delivery;d.ApplySecret(settings.Delivery,edit.NewSmtpPassword,edit.ClearSmtpPassword);d.Validate(test);return d;
        }
        static void Deny(){throw new HttpError(403,"Access denied.");}
        static Reply SignIn(){return new Reply{Code=303,Location="/login",Bytes=new byte[0]};}
        Reply Route(Request r,string ip){
            if(r.Path.StartsWith("/api/v1/",StringComparison.Ordinal)){
                if(r.Method!="GET"||r.Path!="/api/v1/system")throw new HttpError(404,"Unknown API endpoint.");
                lock(mutation){var scope=access.Authorize(r.Header("Authorization"));if(scope==null)throw new HttpError(401,"Valid bearer token required.");
                var q=HttpUtility.ParseQueryString(r.Query);if(q.AllKeys.Any(k=>k!="categories"))throw new HttpError(400,"Unknown parameter.");
                    var allowed=settings.Categories().Intersect(scope).ToArray();var selected=q["categories"]==null?allowed:q["categories"].Split(',');
                    if(!Config.Allowed(selected,allowed))Deny();return Reply.Json(monitor.Snapshot(selected));}
            }
            if(r.Header("Authorization")!=null)Deny();
            if(r.Path!="/api/history"&&r.Path!="/ui/resource-history"&&r.Path!="/ui/alerts"&&r.Path!="/ui/alerts/history"&&r.Path!="/ui/alerts/search"&&r.Path!="/ui/logs/search"&&r.Query.Length>0)throw new HttpError(400,"Unexpected query string.");
            bool post=r.Method=="POST";
            if(post&&!string.Equals(r.Header("Origin"),(running.UseHttps?"https://":"http://")+r.Header("Host"),StringComparison.OrdinalIgnoreCase))Deny();
            if(post&&r.Path=="/auth/login"){
                if(!access.LoginAllowed(ip)||!passwordWorkers.Wait(0))throw new HttpError(429,"Too many sign-in attempts. Try again in five minutes.");
                try{var input=Decode<LoginInput>(r);bool changeRequired;
                    bool local=IPAddress.IsLoopback(IPAddress.Parse(ip))&&IPAddress.IsLoopback(IPAddress.Parse(running.BindAddress));
                    string value=access.Login(input.user,input.password,input.newPassword,local,out changeRequired);
                    if(changeRequired)return Reply.Json(new {changeRequired=true});
                    if(value==null)throw new HttpError(401,"Sign-in failed. Check the username and password.");
                    var response=Reply.Json(new {ok=true});response.Cookie=Cookie(value,false);return response;
                }finally{passwordWorkers.Release();}
            }
            Reply asset;
            if(!post&&r.Path.StartsWith("/assets/",StringComparison.Ordinal)&&assets.TryGetValue(r.Path,out asset))return asset;
            if(!post&&r.Path=="/login"){lock(mutation)return PageAsset("/login");}
            string rawCookie=r.Cookie(CookieName());var session=access.Find(rawCookie);
            if(post&&(session==null||!Access.Equal(session.Csrf,r.Header("X-CSRF-Token"))))Deny();
            lock(mutation){
                bool view=session!=null||(!settings.RequireLogin&&IPAddress.IsLoopback(IPAddress.Parse(ip)));
                if(!post&&(r.Path=="/"||r.Path=="/system"||r.Path=="/settings"||r.Path=="/alerts"||r.Path=="/logs"||r.Path=="/ai")){
                    if(r.Path=="/ai"&&session==null)return new Reply{Code=303,Location="/login#ai",Bytes=new byte[0]};
                    if(r.Path=="/logs"&&session==null)return new Reply{Code=303,Location="/login#logs",Bytes=new byte[0]};
                    if(r.Path=="/alerts"&&session==null)return new Reply{Code=303,Location="/login#alerts",Bytes=new byte[0]};
                    return (r.Path=="/settings"?session!=null:view)?PageAsset(r.Path):SignIn();
                }
                if(!post&&r.Path=="/ui/session")return Reply.Json(new {instanceId=instanceId,admin=session!=null,csrf=session==null?null:session.Csrf,brandLabel=settings.BrandLabel});
                if(!post&&r.Path=="/ui/alerts"&&view){
                    var after=Cursor(r,"after");
                    object feed=session!=null?alerts.Feed(after):
                        (object)new {alerts=alerts.List(Config.Core.Concat(new[]{"network"}),false),cursor=0,more=false,unread=0};
                    return Reply.Json(new {admin=session!=null,csrf=session==null?null:session.Csrf,brandLabel=settings.BrandLabel,feed=feed});
                }
                if(!post&&r.Path=="/ui/alerts/history"&&session!=null)return Reply.Json(alerts.Page(Cursor(r,"before")??0));
                if(post&&r.Path=="/ui/alerts/read"){alerts.Read(Decode<TokenInput>(r).id);return Reply.Json(new {ok=true});}
                if(post&&r.Path=="/ui/alerts/read-all"){
                    long through=Decode<AlertReadBatch>(r).through;
                    if(through<0)throw new HttpError(400,"Invalid notification cursor.");
                    alerts.ReadAll(through);return Reply.Json(new {ok=true});
                }
                if(!post&&r.Path=="/ui/report-system"&&view){
                    if(session==null&&settings.ExtraCategories.Length>0)throw new HttpError(403,"Sign in to export the complete configured inventory.");
                    return Reply.Json(monitor.ReportSnapshot(settings.Categories()));
                }
                if(!post&&r.Path=="/ui/system"&&view)return Reply.Json(monitor.Snapshot(session!=null?settings.Categories():Config.Core));
                if(!post&&((r.Path=="/api/history"||r.Path=="/ui/resource-history")&&view||(r.Path=="/ui/alerts/search"||r.Path=="/ui/logs/search"||r.Path=="/ui/logs/summary")&&session!=null)){} // History reads run outside the settings lock.
                else if(session==null)throw new HttpError(401,"Sign in required.");
                else if(post&&r.Path=="/auth/logout"){ai.Clear(session);access.Logout(rawCookie);var res=Reply.Json(new {ok=true});res.Cookie=Cookie("",true);return res;}
                else if(!post&&r.Path=="/ui/report")return Reply.Json(new {now=History.Now(),targets=running.Targets.Select(t=>settings.Targets.FirstOrDefault(x=>x.Address==t.Address)??t).ToArray(),probeAlertCount=settings.ProbeAlertCount,windows=monitor.ReportSnapshot(settings.Categories())});
                else if(!post&&r.Path=="/ui/connections")return Reply.Json(NativeConnections.Snapshot());
                else if(!post&&r.Path=="/ui/ai")return Reply.Json(ai.Info(settings.Ai));
                else if(!post&&r.Path=="/ui/ai/result")return Reply.Json(ai.Result(session));
                else if(post&&r.Path=="/ui/ai/ask"){var cfg=settings;return Reply.Json(ai.Start(session,Decode<AiQuestion>(r),cfg.Ai,()=>AiEvidence.Collect(monitor,running,cfg)));}
                else if(post&&r.Path=="/ui/ai/cancel"){ai.Cancel(session);return Reply.Json(new {ok=true});}
                else if(post&&r.Path=="/ui/ai/clear"){ai.Clear(session);return Reply.Json(new {ok=true});}
                else if(!post&&r.Path=="/ui/settings")return Reply.Json(new {config=settings.PublicCopy(),restartRequired=RestartNeeded(settings),canRestart=Program.ServiceMode,nextOrigin=settings.Origin(),seqKeyStored=!string.IsNullOrEmpty(settings.Siem.Seq.ProtectedKey),elasticKeyStored=!string.IsNullOrEmpty(settings.Siem.Elastic.ProtectedKey),aiKeyStored=settings.Ai.Profiles.ToDictionary(x=>x.Key,x=>!string.IsNullOrEmpty(x.Value.ProtectedKey)),smtpPasswordStored=!string.IsNullOrEmpty(settings.Delivery.ProtectedPassword),defaultJsonDirectory=Path.Combine(Config.Data,"active-alerts"),outputStatus=outputs.State(),logStatus=AppJournal.Current.State(),core=Config.Core,extras=Config.Extras,channels=Config.Channels,tokens=access.List(),activeOrigin=running.Origin()});
                else if(post&&r.Path=="/ui/settings"){
                    var next=Decode<Config>(r);
                    next.Delivery=SubmittedDelivery(r,false);
                    next.Ai=AiSettings.Merge(settings.Ai,Decode<AiEdit>(r));
                    next.Logging=Decode<LogSettingsInput>(r).Logging??settings.Logging;
                    next.Siem=SiemSettings.Merge(settings.Siem,Decode<SiemEdit>(r));
                    Config.Validate(next);
                    if(next.UseHttps)using(Certificate(next)){}
                    outputs.Set(next.Delivery,delegate{Config.Save(Config.FilePath,next);});if(Config.Json().Serialize(settings.Ai)!=Config.Json().Serialize(next.Ai))ai.Reset();settings=next;AppJournal.Current.Configure(next.Logging,next.Siem);
                    collector.AlertRules=next;monitor.Update(next);alerts.Trim(next.Categories().Concat(new[]{"network"}).ToArray());
                    bool restart=RestartNeeded(next);
                    return Reply.Json(new {ok=true,restartRequired=restart,nextOrigin=next.Origin()});
                }
                else if(!post&&r.Path=="/ui/alert-delivery")return Reply.Json(outputs.State());
                else if(post&&r.Path=="/ui/restart")return RequestRestart();
                else if(post&&r.Path=="/ui/siem-test")return Reply.Json(AppJournal.Current.TestSiem(Decode<SiemTestInput>(r).Receiver));
                else if(post&&r.Path=="/ui/smtp-test"){outputs.Test(SubmittedDelivery(r,true));return Reply.Json(new {started=true});}
                else if(post&&r.Path=="/ui/tokens"){var t=Decode<TokenInput>(r);return Reply.Json(new {token=access.Issue(t.name,t.categories,t.days,settings.Categories())});}
                else if(post&&r.Path=="/ui/tokens/revoke"){if(!access.Revoke(Decode<TokenInput>(r).id))throw new HttpError(404,"Token not found.");return Reply.Json(new {ok=true});}
                else throw new HttpError(404,"Unknown route.");
            }
            if(r.Path=="/ui/logs/summary"){
                if(!historyWorkers.Wait(0))throw new HttpError(503,"History is busy.");
                try{using(var db=new Sqlite(AppJournal.Filename,true))return Reply.Json(new {rows=db.Rows("SELECT module,level,COUNT(*) FROM app_log GROUP BY module,level ORDER BY module,level").Select(row=>new {module=row[0],level=((LogLevel)Convert.ToInt32(row[1])).ToString(),count=row[2]}).ToArray()});}
                finally{historyWorkers.Release();}
            }
            if(r.Path=="/ui/logs/search"){
                var search=new LogSearch(r.Query);
                if(!historyWorkers.Wait(0))throw new HttpError(503,"History is busy.");
                try{return Reply.Json(search.Run(AppJournal.Filename));}finally{historyWorkers.Release();}
            }
            if(r.Path=="/ui/alerts/search"){
                var search=new AlertSearch(r.Query);
                if(!historyWorkers.Wait(0))throw new HttpError(503,"History is busy.");
                try{return Reply.Json(search.Run(Config.Db));}finally{historyWorkers.Release();}
            }
            var query=HttpUtility.ParseQueryString(r.Query);string target=query["target"]??running.Targets[0].Address,period=query["range"]??"day";
            bool resource=r.Path=="/ui/resource-history";
            if(query.AllKeys.Any(k=>k!="range"&&k!="at"&&(resource||k!="target"))||!running.Targets.Any(t=>t.Address==target)||
                !new[]{"day","week","month","year","all"}.Contains(period)||(resource&&period=="all"))throw new HttpError(400,"Invalid history selection.");
            long now=History.Now(),at=now;
            if(query["at"]!=null&&(!long.TryParse(query["at"],out at)||at<now-86400||at>now+2))throw new HttpError(400,"Invalid report time.");
            if(!historyWorkers.Wait(0))throw new HttpError(503,"History is busy.");
            try{return Reply.Json(resource?History.ResourceTrend(period,at):collector.Report(target,period,at));}finally{historyWorkers.Release();}
        }
        public void Dispose(){stopping=true;listener.Stop();if(thread!=null)thread.Join();restartReplySent.Wait(9000);lock(active){foreach(var c in active)c.Close();while(active.Count>0)Monitor.Wait(active);}
            ai.Dispose();monitor.Dispose();if(cert!=null)cert.Dispose();passwordWorkers.Dispose();historyWorkers.Dispose();}
    }
}
