using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace LinkScope {
    internal sealed class Telemetry : IDisposable {
        readonly object gate=new object();
        Config cfg;
        readonly ManualResetEvent stop=new ManualResetEvent(false);
        readonly AutoResetEvent refresh=new AutoResetEvent(false),refreshExtra=new AutoResetEvent(false),refreshFast=new AutoResetEvent(false);
        Thread fast,slow,extra,integrityThread,endpointThread;
        readonly EndpointProtection endpoint=new EndpointProtection();
        readonly AutoResetEvent endpointWake=new AutoResetEvent(false);
        internal void ScanEndpointNow(){endpointWake.Set();}
        internal void ResetEndpointScan(){endpoint.RequestReset();endpointWake.Set();}
        internal object ResetEndpointHistory(){var result=endpoint.RequestHistoryReset();endpointWake.Set();return result;}
        internal object EndpointHistoryResetStatus(){return endpoint.HistoryResetStatus();}

        internal object QuarantineStatus(){return endpoint.QuarantineStatus();}
        internal object DeleteQuarantine(string[] ids,string actor,string ip){var result=endpoint.DeleteQuarantine(ids,actor,ip);endpointWake.Set();return result;}
        internal void CreateEndpointCanaries(EndpointSettings policy,string directory){endpoint.CreateManagedCanaries(policy,directory);}
        internal object RunEndpointProtectionLab(EndpointSettings policy,string directory,Func<bool> authorized){return endpoint.RunProtectionLab(policy,directory,stop,()=>endpointWake.Set(),authorized);}
        void EndpointLoop(){bool force=true;while(!stop.WaitOne(0)){Config c;lock(gate)c=cfg;object result;bool successfulTick=true,resetReady=false;try{endpoint.WorkerPhase("Processing scan requests");endpoint.ProcessHistoryReset(alerts);resetReady=true;result=endpoint.Tick(c.Endpoint,stop,force,delegate{lock(gate)return ReferenceEquals(cfg,c)&&c.Endpoint.Enabled;});}catch(OperationCanceledException){return;}catch(Exception ex){AppJournal.Fault("Endpoint","scan",ex);successfulTick=false;result=Unavailable();}lock(gate){if(ReferenceEquals(c,cfg)){values["endpoint_protection"]=result;times["endpoint_protection"]=History.Now();try{if(resetReady){endpoint.Publish(alerts,c,successfulTick);alerts.Sample("endpoint_protection",result,c);}}catch(Exception ex){AppJournal.Fault("Endpoint","alerts",ex);}}}endpoint.WorkerPhase(successfulTick?"Waiting for next cycle":"Scan cycle failed; retry pending");force=WaitHandle.WaitAny(new WaitHandle[]{stop,endpointWake},c.Endpoint.Enabled?1000:30000)==1;}}
        readonly FileIntegrity integrity=new FileIntegrity();
        readonly AutoResetEvent integrityWake=new AutoResetEvent(false);
        internal void ScanIntegrityNow(){integrityWake.Set();}
        internal void AuthorizeIntegrity(IntegritySettings old,IntegritySettings next){integrity.Authorize(old,next);}
        void IntegrityLoop(){while(!stop.WaitOne(0)){Config c;lock(gate)c=cfg;object result;try{result=integrity.Scan(c.Integrity,stop);}catch(OperationCanceledException){return;}lock(gate){if(ReferenceEquals(cfg,c)){values["data_integrity"]=result;times["data_integrity"]=History.Now();try{alerts.Sample("data_integrity",result,c);}catch(Exception ex){AppJournal.Fault("Integrity","alerts",ex);}}}WaitHandle.WaitAny(new WaitHandle[]{stop,integrityWake},c.Integrity.IntervalSeconds*1000);}}
        readonly Dictionary<string,object> values=new Dictionary<string,object>();
        readonly Dictionary<string,long> times=new Dictionary<string,long>();
        readonly string smartScript=Encoding.UTF8.GetString(Program.Resource("smart.ps1"));
        readonly string script=Encoding.UTF8.GetString(Program.Resource("health.ps1"));
        ulong idle,kernel,user;
        [StructLayout(LayoutKind.Sequential)] struct Memory {public uint Size,Load;public ulong Total,Available,PageTotal,PageAvailable,VirtualTotal,VirtualAvailable,Extended;}
        [DllImport("kernel32.dll")] static extern bool GlobalMemoryStatusEx(ref Memory value);
        [DllImport("kernel32.dll")] static extern bool GetSystemTimes(out ulong idle,out ulong kernel,out ulong user);
        readonly Alerts alerts;
        internal Telemetry(Config c,Alerts alerts){cfg=c;this.alerts=alerts;}
        internal void Start(){
            fast=new Thread(Fast){IsBackground=true,Name="LinkScope resource sampler"};
            slow=new Thread(delegate(){Slow(false);}){IsBackground=true,Name="LinkScope Windows health"};
            extra=new Thread(delegate(){Slow(true);}){IsBackground=true,Name="LinkScope optional inventory"};
            fast.Start();slow.Start();extra.Start();integrityThread=new Thread(IntegrityLoop){IsBackground=true,Name="LinkScope integrity scanner"};integrityThread.Start();endpointThread=new Thread(EndpointLoop){IsBackground=true};endpointThread.Start();
        }
        internal void Update(Config c){lock(gate){cfg=c; foreach(var key in values.Keys.Except(c.CollectedCategories()).Concat(new[]{"smart","events","event_details"}).Distinct().ToArray()){values.Remove(key);times.Remove(key);}}refresh.Set();refreshExtra.Set();refreshFast.Set();integrityWake.Set();endpointWake.Set();}
        internal object Snapshot(IEnumerable<string> names){return Snapshot(names,false);}
        internal object ReportSnapshot(IEnumerable<string> names){return Snapshot(names,true);}
        internal object EndpointSnapshot(){return Snapshot(new[]{"endpoint_protection"},false,true);}
        object Snapshot(IEnumerable<string> names,bool includeNetwork,bool showRead=false){lock(gate){
            var data=new Dictionary<string,object>();long now=History.Now();
            foreach(var n in names){if((n=="endpoint_protection"&&!cfg.Endpoint.Enabled)||(n=="data_integrity"&&!cfg.Integrity.Enabled)){data[n]=new {status="disabled",result=new {status="disabled",items=new object[0]}};continue;}object value;if(!values.TryGetValue(n,out value)){data[n]=n=="data_integrity"?(object)new {status="collecting",activity=integrity.Activity(cfg.Integrity)}:n=="endpoint_protection"?(object)new {status="collecting",activity=endpoint.WorkerActivity()}:new {status="collecting"};continue;}
                long age=now-times[n];long expected=n=="endpoint_protection"?30:n=="data_integrity"?cfg.Integrity.IntervalSeconds:(n=="cpu"||n=="ram"||n=="disk_usage")?cfg.ResourceSeconds:cfg.InventoryMinutes*60;
                data[n]=n=="data_integrity"?(object)new {collectedUtc=Utc(times[n]),ageSeconds=age,stale=age>expected*2+60,result=value,activity=integrity.Activity(cfg.Integrity)}:n=="endpoint_protection"?(object)new {collectedUtc=Utc(times[n]),ageSeconds=age,stale=age>expected*2+60,result=value,activity=endpoint.WorkerActivity()}:new {collectedUtc=Utc(times[n]),ageSeconds=age,stale=age>expected*2+60,result=value};}
            return new {schemaVersion=1,monitorHost=Environment.MachineName,generatedUtc=Utc(now),categories=data,alerts=alerts.List(includeNetwork?names.Concat(new[]{"network"}):names,showRead)};}}
        internal static string Utc(long seconds){return new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc).AddSeconds(seconds).ToString("o");}
        static object Unavailable(){return new {status="unavailable",items=new object[0]};}
        void ReadFast(string name,Func<object> read){object result;try{result=read();}catch(Exception ex){AppJournal.Fault("Health",name,ex);result=Unavailable();}
            lock(gate){values[name]=result;times[name]=History.Now();try{alerts.Sample(name,result,cfg);}catch(Exception ex){AppJournal.Fault("Alerts","evaluate",ex);}}}
        void Fast(){while(!stop.WaitOne(0)){var usage=new Dictionary<string,double>();
            ReadFast("ram",delegate{var m=new Memory();m.Size=(uint)Marshal.SizeOf(typeof(Memory));if(!GlobalMemoryStatusEx(ref m))return Unavailable();
                usage["RAM"]=m.Load;return new {status="ok",totalBytes=m.Total,availableBytes=m.Available,usedBytes=m.Total-m.Available,usedPercent=m.Load};});
            ReadFast("cpu",delegate{ulong i,k,u;if(!GetSystemTimes(out i,out k,out u))return Unavailable();
                ulong delta=k+u-kernel-user;bool valid=kernel!=0&&k>=kernel&&u>=user&&i>=idle&&delta>0&&i-idle<=delta;
                double? pct=valid?(double?)Math.Round(100.0*(delta-(i-idle))/delta,1):null;idle=i;kernel=k;user=u;
                if(pct.HasValue)usage["CPU"]=pct.Value;return new {status=valid?"ok":"warming_up",usedPercent=pct};});
            ReadFast("disk_usage",delegate{var result=new List<object>();
                foreach(var d in DriveInfo.GetDrives().Where(x=>x.DriveType==DriveType.Fixed))try{long total=d.TotalSize,free=d.TotalFreeSpace;
                    if(total>0)usage["Disk "+d.Name]=100.0*(total-free)/total;
                    result.Add(new {volume=d.Name,status="ok",totalBytes=total,freeBytes=free,usedBytes=total-free,usedPercent=total>0?(double?)Math.Round(100.0*(total-free)/total,1):null});}
                    catch(IOException){result.Add(new {volume=d.Name,status="unavailable"});}catch(UnauthorizedAccessException){result.Add(new {volume=d.Name,status="unavailable"});}
                return new {status="ok",items=result};});
            try{History.SaveResources(usage);AppJournal.Event(LogLevel.Debug,"History","save-resources","Resource samples processed.");}catch(Exception ex){AppJournal.Fault("History","save-resources",ex);}
            int interval;lock(gate)interval=cfg.ResourceSeconds;WaitHandle.WaitAny(new WaitHandle[]{stop,refreshFast},interval*1000);
        }}
        internal static ProcessStartInfo PowerShell(string code){
            string system=Environment.SystemDirectory;
            var p=new ProcessStartInfo(Path.Combine(system,@"WindowsPowerShell\v1.0\powershell.exe"),"-NoLogo -NoProfile -NonInteractive -EncodedCommand "+Convert.ToBase64String(Encoding.Unicode.GetBytes(code))){
                WorkingDirectory=system,UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardOutputEncoding=Encoding.UTF8};
            p.EnvironmentVariables["PSModulePath"]=Path.Combine(system,@"WindowsPowerShell\v1.0\Modules")+";"+Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),@"WindowsPowerShell\Modules");
            return p;
        }
        [DllImport("wscapi.dll")] static extern int WscGetSecurityProviderHealth(uint provider,out int status);
        static string AntivirusHealth(){
            try{int status;int hr=WscGetSecurityProviderHealth(4,out status); // WSC_SECURITY_PROVIDER_ANTIVIRUS
                return hr==0 && status>=0&&status<4?new[]{"good","not_monitored","poor","snoozed"}[status]:"unavailable";}
            catch(DllNotFoundException){return "unavailable";}catch(EntryPointNotFoundException){return "unavailable";}
        }
        object Run(string category,Config c){
            var info=PowerShell(category=="smart"?smartScript:script);
            info.EnvironmentVariables["LINKSCOPE_CATEGORY"]=category;info.EnvironmentVariables["LINKSCOPE_LIMIT"]=c.EventsPerChannel.ToString();
            info.EnvironmentVariables["LINKSCOPE_CHANNELS"]=string.Join("|",c.EventChannels);info.EnvironmentVariables["LINKSCOPE_LIFE"]=c.LowLifePercent.ToString();
            using(var p=new Process{StartInfo=info}){
                p.Start();var output=p.StandardOutput.ReadToEndAsync();var errors=p.StandardError.ReadToEndAsync();var timer=Stopwatch.StartNew();
                while(!p.WaitForExit(200))if(stop.WaitOne(0)||timer.ElapsedMilliseconds>30000){try{p.Kill();}catch(InvalidOperationException){}return Unavailable();}
                if(p.ExitCode!=0||!output.Wait(1500)||!errors.Wait(1500)||output.Result.Length>2000000)return Unavailable();
                var result=(Dictionary<string,object>)Config.Json().DeserializeObject(output.Result);
                if(category=="antivirus"){
                    var wsc=AntivirusHealth();result["windowsSecurityCenter"]=wsc;
                    if(wsc!="unavailable" && Convert.ToString(result["status"])=="unavailable")result["status"]="partial";
                }
                return result;
            }
        }
        readonly string notices=Path.Combine(Config.Data,"disk-alerts.json");
        void Notify(object result,Config c){
            if(!c.WriteDiskEvents)return;
            var report=result as Dictionary<string,object>;if(report==null||!report.ContainsKey("items"))return;
            var rows=report["items"] as System.Collections.IEnumerable;if(rows==null)return;
            var state=File.Exists(notices)?Config.Json().Deserialize<Dictionary<string,bool>>(File.ReadAllText(notices)):new Dictionary<string,bool>();bool changed=false;
            foreach(var item in rows){var row=item as Dictionary<string,object>;if(row==null)continue;
                var id=(string)row["diskId"];string verdict=(string)row["recommendation"];
                if(verdict=="replace"&&!state.ContainsKey(id)){
                    EventLog.WriteEntry("LinkScope","Plan disk replacement. Model: "+row["model"]+"; disk: "+row["device"]+"; health: "+row["health"]+"; estimated remaining life (%): "+(row["estimatedLifeRemainingPercent"]??"unknown")+".",EventLogEntryType.Warning,4101);
                    state[id]=true;changed=true;
                }else if(verdict=="normal")changed|=state.Remove(id);
            }if(changed)Config.Save(notices,state);
        }
        void Slow(bool optional){var wake=optional?refreshExtra:refresh;while(!stop.WaitOne(0)){Config c;lock(gate)c=cfg;
            foreach(var key in (optional?c.CollectedCategories().Intersect(Config.Extras).ToArray():Config.Core.Skip(3).Where(x=>x!="data_integrity"&&x!="endpoint_protection").ToArray())){if(stop.WaitOne(0))return;lock(gate)if(!ReferenceEquals(cfg,c))break;
                object value;try{value=key=="security"?SecurityPosture.Read():Run(key,c);}catch(Exception ex){AppJournal.Fault("Health",key,ex);value=Unavailable();}
                lock(gate){if(!ReferenceEquals(cfg,c))break;values[key]=value;times[key]=History.Now();try{alerts.Sample(key,value,cfg);}catch(Exception ex){AppJournal.Fault("Alerts","evaluate",ex);}
                    if(key=="smart")try{Notify(value,c);}catch(Exception ex){AppJournal.Fault("SMART","notify",ex);}}
            }
            WaitHandle.WaitAny(new WaitHandle[]{stop,wake},c.InventoryMinutes*60000);
        }}
        public void Dispose(){stop.Set();if(endpointThread!=null)endpointThread.Join();endpoint.Dispose();endpointWake.Dispose();if(integrityThread!=null)integrityThread.Join();integrityWake.Dispose();if(fast!=null)fast.Join();if(slow!=null)slow.Join();if(extra!=null)extra.Join();stop.Dispose();refresh.Dispose();refreshExtra.Dispose();refreshFast.Dispose();}
    }
}
