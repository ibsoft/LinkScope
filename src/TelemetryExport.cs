using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Threading;
using System.Diagnostics;

namespace LinkScope {
    public sealed class TelemetryExportSettings {
        public bool Enabled {get;set;}
        public int IntervalSeconds {get;set;}
        public string Directory {get;set;}
        public bool Full {get;set;}
        public string[] Categories {get;set;}
        internal static readonly string[] Additional={"network","connections","ai_verdict"};
        internal static string[] All(){return Config.Core.Concat(Config.Extras).Concat(Additional).ToArray();}
        public TelemetryExportSettings(){IntervalSeconds=300;Directory="";Categories=Config.Core.Concat(new[]{"network"}).ToArray();}
        internal string[] Selected(){return Full?All():Categories;}
        internal string Folder(){return Directory.Length==0?Path.Combine(Config.Data,"telemetry"):Directory;}
        internal void Validate(){
            if(IntervalSeconds<1||IntervalSeconds>86400||!Config.Allowed(Categories,All())||(Enabled&&!Full&&Categories.Length==0))throw new InvalidDataException("Select telemetry categories and an interval of 1–86400 seconds.");
            Directory=(Directory??"").Trim();
            if(Directory.Length==0)return;
            if(Directory.Length>220||Directory.Any(char.IsControl)||Directory.Length<4||!char.IsLetter(Directory[0])||Directory[1]!=':'||Directory[2]!='\\'||Directory.Substring(2).Contains(":"))throw new InvalidDataException("Use an absolute local Windows folder, e.g. D:\\Telemetry.");
            try{Directory=Path.GetFullPath(Directory).TrimEnd('\\');if(Directory.Length<=3)throw new ArgumentException();}catch(ArgumentException){throw new InvalidDataException("Invalid telemetry folder.");}catch(NotSupportedException){throw new InvalidDataException("Invalid telemetry folder.");}
        }
    }
    internal sealed class TelemetryExport:IDisposable {
        readonly object gate=new object();
        readonly ManualResetEvent stop=new ManualResetEvent(false);
        readonly AutoResetEvent wake=new AutoResetEvent(false);
        readonly Telemetry monitor;readonly Collector collector;readonly AiAssist ai;readonly Config running;
        Config cfg;Thread worker;string status="Not started",lastSuccess="";
        internal TelemetryExport(Config c,Telemetry monitor,Collector collector,AiAssist ai){cfg=running=c;this.monitor=monitor;this.collector=collector;this.ai=ai;}
        internal void Start(){worker=new Thread(Loop){IsBackground=true,Name="LinkScope telemetry export"};worker.Start();}
        internal void Update(Config c){lock(gate){cfg=c;status=c.TelemetryExport.Enabled?"Pending":"Disabled";}wake.Set();}
        internal object State(){lock(gate)return new {status=status,lastSuccessUtc=lastSuccess,path=Path.Combine(cfg.TelemetryExport.Folder(),"telemetry.json")};}
        static void CheckFolder(string folder){for(var d=new DirectoryInfo(folder);d!=null;d=d.Parent)if(d.Exists&&(d.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Telemetry folder contains a link or junction.");}
        static void Publish(string folder,object payload){
            CheckFolder(folder);System.IO.Directory.CreateDirectory(folder);CheckFolder(folder);
            string path=Path.Combine(folder,"telemetry.json");
            if(File.Exists(path)){
                var info=new FileInfo(path);if((info.Attributes&FileAttributes.ReparsePoint)!=0||info.Length>64L*1024*1024*4)throw new IOException("Unexpected telemetry destination.");
                var previous=Config.Json().DeserializeObject(File.ReadAllText(path)) as Dictionary<string,object>;object source;
                if(previous==null||!previous.TryGetValue("source",out source)||!Equals(source,"LinkScope telemetry export"))throw new IOException("Existing telemetry.json is not a LinkScope telemetry export.");
            }
            Config.Save(path,payload);
        }
        void Loop(){while(!stop.WaitOne(0)){
            Config c;lock(gate)c=cfg;var e=c.TelemetryExport;
            if(!e.Enabled){lock(gate)if(ReferenceEquals(cfg,c))status="Disabled";WaitHandle.WaitAny(new WaitHandle[]{stop,wake});continue;}
            var timer=Stopwatch.StartNew();
            try{
                var selected=e.Selected();var names=selected.Intersect(Config.Core.Concat(Config.Extras)).ToArray();
                var snapshot=Config.Json().Deserialize<Dictionary<string,object>>(Config.Json().Serialize(selected.Contains("network")?monitor.ReportSnapshot(names):monitor.Snapshot(names)));
                var data=(Dictionary<string,object>)snapshot["categories"];
                if(selected.Contains("network"))data["network"]=Read(()=>running.Targets.Select(t=>collector.Report(t.Address,"day")).ToArray());
                if(selected.Contains("connections"))data["connections"]=Read(()=>NativeConnections.Snapshot());
                if(selected.Contains("ai_verdict"))data["ai_verdict"]=Read(()=>ai.ReportVerdict(c.Ai));
                snapshot["source"]="LinkScope telemetry export";snapshot["full"]=e.Full;snapshot["selectedCategories"]=selected;
                lock(gate)if(!ReferenceEquals(cfg,c))continue;
                if(stop.WaitOne(0))return;
                Publish(e.Folder(),snapshot);
                lock(gate)if(ReferenceEquals(cfg,c)){status="Export successful";lastSuccess=DateTime.UtcNow.ToString("o");}
            }catch(Exception ex){lock(gate)if(ReferenceEquals(cfg,c))status="Export failed: "+ex.GetType().Name;AppJournal.Fault("TelemetryExport","write",ex);}
            WaitHandle.WaitAny(new WaitHandle[]{stop,wake},(int)Math.Max(1,e.IntervalSeconds*1000L-timer.ElapsedMilliseconds));
        }}
        static object Read(Func<object> read){try{return new {status="ok",result=read()};}catch(Exception ex){AppJournal.Fault("TelemetryExport","collect",ex);return new {status="unavailable"};}}
        public void Dispose(){stop.Set();if(worker!=null)worker.Join();stop.Dispose();wake.Dispose();}
    }
}
