using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;

namespace LinkScope {
    internal sealed class Collector : IDisposable {
        static readonly HashSet<string> LocalFailures = new HashSet<string>(StringComparer.Ordinal) {
            "Unknown", "NoResources", "BadOption", "HardwareError", "BadDestination"
        };
        readonly Config cfg;
        readonly CancellationTokenSource stop = new CancellationTokenSource();
        Sqlite writer;
        Task worker;
        readonly object gate = new object();
        string nicId="", nicName="", error="";
        NetworkInterface adapter;
        long prevRx,prevTx,prevTicks;
        readonly Alerts alerts; internal volatile Config AlertRules;
        internal Collector(Config c,Alerts alerts) { cfg=c;this.alerts=alerts;AlertRules=c; }

        internal void Start() {
            writer = new Sqlite(false);
            History.Init(writer);
            alerts.RestoreProbeWindows(writer,cfg.Targets);
            worker = Task.Run((Func<Task>)Loop);
        }
        internal object Report(string ip,string period,long? at=null) {
            string id,name,err;
            lock(gate) { id=nicId; name=nicName; err=error; }
            return History.Report(cfg,ip,period,id,name,err,at);
        }
        async Task<Probe> Sample(Target target) {
            var p=new Probe {Address=target.Address};
            try {
                using (var ping=new Ping()) {
                    int timeout=Math.Min(cfg.TimeoutMs,cfg.IntervalSeconds*1000);
                    var reply=await ping.SendPingAsync(IPAddress.Parse(target.Address),timeout).ConfigureAwait(false);
                    p.Status=reply.Status.ToString();
                    if(reply.Status==IPStatus.Success) p.Rtt=reply.RoundtripTime;
                    else if(LocalFailures.Contains(p.Status) || !Enum.IsDefined(typeof(IPStatus),reply.Status)) {
                        p.LocalError=true;
                        p.Status="Probe error: "+p.Status;
                    }
                }
            } catch(Exception ex) {
                p.LocalError=true;
                var cause=ex.GetBaseException();
                p.Status="Probe error: "+cause.Message;
            }
            AppJournal.Event(p.Rtt.HasValue?LogLevel.Debug:LogLevel.Warning,"Network","ping",
                p.Rtt.HasValue?"ICMP reply in "+p.Rtt+" ms.":p.LocalError?"Local probe error.":"ICMP "+p.Status+".",p.Address);
            return p;
        }
        NetworkInterface ChooseAdapter() {
            var all=NetworkInterface.GetAllNetworkInterfaces();
            if(cfg.InterfaceName.Length!=0)
                return all.FirstOrDefault(n=>string.Equals(n.Name,cfg.InterfaceName,StringComparison.OrdinalIgnoreCase)
                    || string.Equals(n.Id,cfg.InterfaceName,StringComparison.OrdinalIgnoreCase));
            return all.Where(n=>n.OperationalStatus==OperationalStatus.Up && n.NetworkInterfaceType!=NetworkInterfaceType.Loopback &&
                        n.NetworkInterfaceType!=NetworkInterfaceType.Tunnel)
                .OrderByDescending(n=>n.GetIPProperties().GatewayAddresses.Count>0)
                .ThenByDescending(n=>n.Speed).ThenBy(n=>n.Id).FirstOrDefault();
        }
        Traffic ReadTraffic() {
            try {
                if(adapter==null) adapter=ChooseAdapter();
                if(adapter==null) {
                    lock(gate) nicName=cfg.InterfaceName.Length==0 ? "No active adapter" : cfg.InterfaceName+" (unavailable)";
                    return null;
                }
                lock(gate) { nicId=adapter.Id; nicName=adapter.Name; }
                if(adapter.OperationalStatus!=OperationalStatus.Up) {
                    prevTicks=0;
                    adapter=null;
                    return null;
                }
                var stats=adapter.GetIPStatistics();
                long rx=stats.BytesReceived,tx=stats.BytesSent,ticks=Stopwatch.GetTimestamp();
                double seconds=(ticks-prevTicks)/(double)Stopwatch.Frequency;
                Traffic result=null;
                if(prevTicks!=0 && rx>=prevRx && tx>=prevTx && seconds>0 && seconds<=Math.Max(15,3*cfg.IntervalSeconds))
                    result=new Traffic {Id=adapter.Id,Name=adapter.Name,RxBytes=rx-prevRx,TxBytes=tx-prevTx,Seconds=seconds};
                prevRx=rx; prevTx=tx; prevTicks=ticks;
                return result;
            } catch(NetworkInformationException) { }
              catch(PlatformNotSupportedException) { }
              catch(InvalidOperationException) { }
              catch(UnauthorizedAccessException) { }
            lock(gate) nicName=(adapter==null ? cfg.InterfaceName : adapter.Name)+" (counters unavailable)";
            prevTicks=0; adapter=null;
            return null;
        }
        async Task Loop() {
            long lastCleanup=0, nextDue=0;
            long cadence=cfg.IntervalSeconds*1000L;
            var schedule=Stopwatch.StartNew();
            while(!stop.IsCancellationRequested) {
                try {
                    long t=History.Now();
                    var traffic=ReadTraffic();
                    Probe[] results=await Task.WhenAll(cfg.Targets.Select(Sample)).ConfigureAwait(false);
                    bool cleanup=t-lastCleanup>=3600 || t<lastCleanup;
                    AppJournal.Event(LogLevel.Debug,"Network","interface","Adapter counters "+(traffic==null?"unavailable or warming up.":"collected."));
                    History.Save(writer,t,results,traffic,cleanup,AlertRules.DatabaseMaintenance);
                    AppJournal.Event(LogLevel.Debug,"History","save-probes","Saved "+results.Length+" probe observations.");
                    if(cleanup&&!AlertRules.DatabaseMaintenance.Enabled)AppJournal.Event(LogLevel.Debug,"History","prune","Network history retention ran.");
                    alerts.Probes(results,AlertRules);
                    if(cleanup) lastCleanup=t;
                    lock(gate) error="";
                } catch(Exception ex) {
                    lock(gate) error=ex.GetBaseException().Message;
                    AppJournal.Fault("Network","collect",ex);
                }
                try {
                    // Keep the original cadence across timer jitter; never replay missed rounds.
                    nextDue+=cadence;
                    long elapsed=schedule.ElapsedMilliseconds;
                    if(elapsed-nextDue>=cadence) nextDue+=((elapsed-nextDue)/cadence)*cadence;
                    await Task.Delay((int)Math.Max(1,nextDue-elapsed),stop.Token).ConfigureAwait(false);
                } catch(OperationCanceledException) { break; }
            }
        }
        public void Dispose() {
            stop.Cancel();
            if(worker!=null) worker.GetAwaiter().GetResult();
            if(writer!=null) writer.Dispose();
            stop.Dispose();
        }
    }
}
