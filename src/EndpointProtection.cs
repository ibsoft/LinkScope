// Endpoint source layout: split-response-v2
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using System.Xml;
using Microsoft.Win32.SafeHandles;
using Microsoft.Win32;
namespace LinkScope {
 public sealed class EndpointSettings {
  public bool WebProtectionEnabled {get;set;} public bool WebProcessAuditEnabled {get;set;} public string[] WebPaths {get;set;}
  public bool Enabled {get;set;} public bool WriteEvents {get;set;} public bool RealTime {get;set;} public bool ProcessCorrelation {get;set;}
  public bool SignatureScheduleEnabled {get;set;} public string SignatureScheduleFrequency {get;set;} public string SignatureScheduleTime {get;set;} public int SignatureScheduleWeekday {get;set;} public int SignatureScheduleMonthDay {get;set;}
  public bool MetadataFastCache {get;set;} public bool BackgroundPauseOnBattery {get;set;} public bool BackgroundPauseOnBusyDisk {get;set;} public int BackgroundReadMiB {get;set;} public int IntervalSeconds {get;set;} public int ChangeThreshold {get;set;} public int Port {get;set;} public int MaxFileMiB {get;set;} public int BehaviorWindowSeconds {get;set;} public bool BackgroundPauseOnLowMemory {get;set;} public int MemoryMinimumAvailableMiB {get;set;} public int MemoryMinimumAvailablePercent {get;set;} public int BackgroundBatchSize {get;set;} public int SignatureMemoryDeferralMinutes {get;set;} public int ExtendedEntropyWindowSeconds {get;set;} public int ExtendedEntropyThreshold {get;set;} public int EntropyMinimumSampleBytes {get;set;} public double EntropyMinimumCurrent {get;set;} public double EntropyMinimumIncrease {get;set;}
  public string Mode {get;set;} public string TrustedEnginePath {get;set;} public string TrustedEngineSha256 {get;set;} public string[] Paths {get;set;} public string[] ExcludedPaths {get;set;} public string[] BackgroundExcludedPaths {get;set;} public bool ProfileDefaultsApplied {get;set;} public string[] ExcludedPatterns {get;set;} public string[] CanaryPaths {get;set;} public string[] ResponsePaths {get;set;} public string[] TestPaths {get;set;} public string[] ContainmentExecutables {get;set;}
  public EndpointSettings(){WebPaths=new string[0];SignatureScheduleFrequency="daily";SignatureScheduleTime="03:00";SignatureScheduleWeekday=1;SignatureScheduleMonthDay=1;MetadataFastCache=true;BackgroundPauseOnBusyDisk=true;BackgroundReadMiB=10;IntervalSeconds=86400;ChangeThreshold=50;Port=3310;MaxFileMiB=25;BehaviorWindowSeconds=60;BackgroundPauseOnLowMemory=true;MemoryMinimumAvailableMiB=512;MemoryMinimumAvailablePercent=10;BackgroundBatchSize=4;SignatureMemoryDeferralMinutes=60;ExtendedEntropyWindowSeconds=300;ExtendedEntropyThreshold=5;EntropyMinimumSampleBytes=4096;EntropyMinimumCurrent=7.5;EntropyMinimumIncrease=1.0;RealTime=true;Mode="monitor";TrustedEnginePath="";TrustedEngineSha256="";Paths=new string[0];ExcludedPaths=new string[0];BackgroundExcludedPaths=new string[0];ExcludedPatterns=new string[0];CanaryPaths=new string[0];ResponsePaths=new string[0];TestPaths=new string[0];ContainmentExecutables=new string[0];}
  internal void Validate(){if(!new[]{"daily","weekly","monthly"}.Contains(SignatureScheduleFrequency)||!Regex.IsMatch(SignatureScheduleTime??"",@"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$")||SignatureScheduleWeekday<0||SignatureScheduleWeekday>6||SignatureScheduleMonthDay<1||SignatureScheduleMonthDay>31)throw new InvalidDataException("Invalid ClamAV signature schedule.");if(SignatureScheduleEnabled&&Port!=3310)throw new InvalidDataException("Scheduled signature maintenance requires the standard ClamD port 3310.");if(MemoryMinimumAvailableMiB<128||MemoryMinimumAvailableMiB>8192||MemoryMinimumAvailablePercent<5||MemoryMinimumAvailablePercent>40||BackgroundBatchSize<1||BackgroundBatchSize>4||SignatureMemoryDeferralMinutes<0||SignatureMemoryDeferralMinutes>120)throw new InvalidDataException("Invalid endpoint resource management settings.");if(BackgroundReadMiB<5||BackgroundReadMiB>50||IntervalSeconds<60||IntervalSeconds>86400||ChangeThreshold<5||ChangeThreshold>10000||Port<1||Port>65535||MaxFileMiB<1||MaxFileMiB>100||BehaviorWindowSeconds<10||BehaviorWindowSeconds>600||ExtendedEntropyWindowSeconds<30||ExtendedEntropyWindowSeconds>3600||ExtendedEntropyThreshold<2||ExtendedEntropyThreshold>1000||EntropyMinimumSampleBytes<512||EntropyMinimumSampleBytes>65536||EntropyMinimumCurrent<0||EntropyMinimumCurrent>8||EntropyMinimumIncrease<0||EntropyMinimumIncrease>8||!new[]{"monitor","protect","contain"}.Contains(Mode))throw new InvalidDataException("Invalid endpoint monitoring settings.");Paths=Normalize(Paths);ExcludedPaths=Normalize(ExcludedPaths);BackgroundExcludedPaths=Normalize(BackgroundExcludedPaths);CanaryPaths=Normalize(CanaryPaths);ResponsePaths=Normalize(ResponsePaths);TestPaths=Normalize(TestPaths);ContainmentExecutables=Normalize(ContainmentExecutables);ExcludedPatterns=ExcludedPatterns??new string[0];WebPaths=Normalize(WebPaths);if(WebProtectionEnabled&&(WebPaths.Length==0||WebPaths.Any(x=>!Paths.Any(p=>EndpointProtection.Under(x,p))||x.TrimEnd('\\').Length<=2||EndpointProtection.Excluded(this,x)||EndpointProtection.BackgroundExcluded(this,x))))throw new InvalidDataException("Web protection requires explicit non-excluded web application roots inside protected paths.");if(WebProcessAuditEnabled&&!WebProtectionEnabled)throw new InvalidDataException("Enable web protection before web process auditing.");if(ExcludedPatterns.Length>100||ExcludedPatterns.Any(x=>string.IsNullOrWhiteSpace(x)||x.Length>200||x.Any(char.IsControl)||x.IndexOfAny(new[]{'\\','/',':'})>=0))throw new InvalidDataException("Use filename wildcard patterns only.");if(Enabled&&Paths.Length==0)throw new InvalidDataException("Configure at least one endpoint scan path.");if(CanaryPaths.Any(x=>!Paths.Any(p=>EndpointProtection.Under(x,p))||EndpointProtection.Excluded(this,x)))throw new InvalidDataException("Canary files must be monitored and not excluded.");if(ResponsePaths.Any(x=>!Paths.Any(p=>EndpointProtection.Under(x,p))||!EndpointResponse.SafeScope(x)))throw new InvalidDataException("Response paths must be monitored non-system directories or files, not drive roots.");if(TestPaths.Any(x=>File.Exists(x)||!ResponsePaths.Contains(x,StringComparer.OrdinalIgnoreCase)||!Paths.Any(p=>EndpointProtection.Under(x,p))||!EndpointResponse.SafeScope(x)||EndpointProtection.Excluded(this,x)||ResponsePaths.Any(p=>!string.Equals(p,x,StringComparison.OrdinalIgnoreCase)&&EndpointProtection.Under(p,x))))throw new InvalidDataException("Test Center directories must be exact, non-excluded leaf response paths within protected scope. Remove obsolete test paths when changing response scope.");TrustedEnginePath=TrustedEnginePath??"";TrustedEngineSha256=(TrustedEngineSha256??"").Trim().ToLowerInvariant();if(Mode!="monitor"&&(!EndpointResponse.TrustedEngineLocation(TrustedEnginePath)||!Regex.IsMatch(TrustedEngineSha256,"^[a-f0-9]{64}$")))throw new InvalidDataException("Automatic response requires an administrator-pinned clamd.exe path under Program Files and SHA-256.");if(Mode!="monitor"&&ResponsePaths.Length==0)throw new InvalidDataException("Specify restricted response paths before enabling automatic actions.");if(ContainmentExecutables.Any(x=>!ResponsePaths.Any(p=>EndpointProtection.Under(x,p))||!x.EndsWith(".exe",StringComparison.OrdinalIgnoreCase)||EndpointProtection.Excluded(this,x)))throw new InvalidDataException("Containment executables must be exact monitored EXE paths inside response scope.");if(Mode=="contain"&&(!RealTime||!ProcessCorrelation||ContainmentExecutables.Length==0))throw new InvalidDataException("Contain mode requires real-time monitoring, process auditing and explicit executable paths.");}
  internal string SignatureScheduleKey(){return string.Join("|",new[]{SignatureScheduleFrequency,SignatureScheduleTime,SignatureScheduleWeekday.ToString(System.Globalization.CultureInfo.InvariantCulture),SignatureScheduleMonthDay.ToString(System.Globalization.CultureInfo.InvariantCulture)});}
  internal DateTime NextSignatureUpdate(DateTime utc,TimeZoneInfo zone){
   if(utc.Kind!=DateTimeKind.Utc)throw new ArgumentException("UTC reference required.");
   var local=TimeZoneInfo.ConvertTimeFromUtc(utc,zone);var date=local.Date;
   var time=TimeSpan.ParseExact(SignatureScheduleTime,@"hh\:mm",System.Globalization.CultureInfo.InvariantCulture);
   for(int i=0;i<=370;i++){
    var day=date.AddDays(i);
    if(SignatureScheduleFrequency=="weekly"&&(int)day.DayOfWeek!=SignatureScheduleWeekday)continue;
    if(SignatureScheduleFrequency=="monthly"&&day.Day!=Math.Min(SignatureScheduleMonthDay,DateTime.DaysInMonth(day.Year,day.Month)))continue;
    var candidate=DateTime.SpecifyKind(day.Add(time),DateTimeKind.Unspecified);
    for(int minutes=0;zone.IsInvalidTime(candidate)&&minutes<180;minutes++)candidate=candidate.AddMinutes(1);
    if(zone.IsInvalidTime(candidate))continue;
    var next=TimeZoneInfo.ConvertTimeToUtc(candidate,zone);
    if(next>utc)return next;
   }
   throw new InvalidOperationException("No valid next signature schedule occurrence.");
  }
  static string[] Normalize(string[] paths){if(paths==null)return new string[0];if(paths.Length>100)throw new InvalidDataException("Maximum 100 endpoint paths.");return paths.Select(p=>{if(string.IsNullOrWhiteSpace(p)||p.Length>1024||p.Any(char.IsControl)||p.Length<3||p[1]!=':'||p[2]!='\\'||p.Substring(2).Contains(":"))throw new InvalidDataException("Use absolute local drive paths.");return Path.GetFullPath(p);}).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();}
 }
 internal sealed class EndpointProtection : IDisposable {
  const int MaxEntries=100000, MaxQueue=8192;
  // Immutable progress frames are published independently of the completed tick.
  sealed class WorkerFrame {internal readonly string Phase;internal readonly long At;internal WorkerFrame(string phase){Phase=phase;At=History.Now();}}
  volatile WorkerFrame workerFrame=new WorkerFrame("Starting");
  internal void WorkerPhase(string phase){workerFrame=new WorkerFrame(phase);}
  internal object WorkerActivity(){var frame=workerFrame;return new {phase=frame.Phase,phaseUtc=Telemetry.Utc(frame.At)};}
  // Runtime-only enrollment; the saved user policy is never modified. The normal
  // scanner consumes the exact registered path and pre-existing trusted baseline.
  sealed class LabCanaryEnrollment {internal string Path,Expected,Policy;internal long Watermark;}
  readonly object labCanaryGate=new object();volatile LabCanaryEnrollment labCanary;
  string watcherInspectionPath;
  LabCanaryEnrollment ActiveLabCanary(EndpointSettings c,string path){var lab=labCanary;return lab!=null&&string.Equals(lab.Path,path,StringComparison.OrdinalIgnoreCase)&&lab.Policy==Config.Json().Serialize(c)?lab:null;}
  readonly string store; readonly string dbPath; readonly object vaultGate=new object(); readonly List<FileSystemWatcher> watchers=new List<FileSystemWatcher>();
  readonly UsnJournalMonitor usn=new UsnJournalMonitor();
  // One bounded, case-insensitive queue for watcher events. New arrivals reserve
  // capacity and can bypass ordinary backlog without creating extra scan workers.
  sealed class WatchWork {internal string Path;internal DateTime First,Last,NotBefore;internal bool Priority,ObservedWatcher;internal int Retries;}
  readonly object watchGate=new object();
  readonly Dictionary<string,WatchWork> watchQueue=new Dictionary<string,WatchWork>(StringComparer.OrdinalIgnoreCase);
  EndpointSettings watchPolicy; int overflow; long seenOverflow; int watcherFailures;
  readonly Dictionary<string,FileSystemWatcher> localWatchers=new Dictionary<string,FileSystemWatcher>(StringComparer.OrdinalIgnoreCase);
  readonly Dictionary<string,FileSystemWatcher> faultedWatchers=new Dictionary<string,FileSystemWatcher>(StringComparer.OrdinalIgnoreCase);
  readonly Dictionary<string,string> failedWatchers=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase); long nextWatcherRetry;
  const int PriorityReserve=1024, MaxLockedRetries=3;
  readonly Dictionary<string,DateTime> changes=new Dictionary<string,DateTime>(StringComparer.OrdinalIgnoreCase);
  readonly Dictionary<string,DateTime> highEntropy=new Dictionary<string,DateTime>(StringComparer.OrdinalIgnoreCase);
  readonly Dictionary<string,DateTime> extendedEntropy=new Dictionary<string,DateTime>(StringComparer.OrdinalIgnoreCase);
  int extendedEntropyPeak;
  readonly Stack<string> pending=new Stack<string>(); readonly HashSet<string> visited=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
  string signatureMaintenanceSeen="",reportedUpdateUtc=null;long lastSignatureLogCheck,lastSignatureComparison;bool signatureLogReadable;
  string responseEngineStatus="Not checked",responseEngineDetail="Waiting for response verification";
  long lastResponseCheck,responseVerifiedEpoch;object[] responsePathsReadiness=new object[0];
  string signatureFreshness="Unknown",signatureComparison="Not checked"; string policy,scope,version="Unavailable",auditStatus="Disabled",signatureVersion="Unknown",signatureTimestamp="Unknown"; long nextScan,scanId,lastScan,lastEngine,lastCanary,lastSignatureCheck; bool running,online,complete,rescan,traversalLimitReached,journalGapDuringScan,reconcilePending=true,scopeReconcilePending=true; int scanned,excluded,limited,errors; long cleanChecks,infectedChecks,heuristicChecks,excludedChecks,failedChecks,quarantinedChecks,deferredChecks,snapshotCleanChecks; long realTimeChecked,lastFileScan,lastRealTimeScan; string latestChanged="",lastScannedPath="";
  int resetRequested; long privilegedFileChecks;
  const long VerdictCacheMaxAge=7*86400;
  bool baselineRestorePending=true,baselineResumed;
  List<string> baselineChildren;
  long cachedChecks,metadataCachedChecks; int baselineCached;
  readonly EndpointResourceMonitor resourceMonitor=new EndpointResourceMonitor(); readonly EndpointDiskPressure diskPressure=new EndpointDiskPressure(); string baselineThrottleReason="";
  sealed class CacheCandidate {internal string Hash,Generation,Stamp;}
  int engineFailures; bool engineNeedsScanProbe; long nextEngineProbe;
  // Independent, bounded download-directory reconciliation. Never use the service account's USERPROFILE.
  sealed class DownloadWork {internal UsnJournalService.DownloadEntry Entry;internal bool Done;internal long Next;}
  readonly Dictionary<string,DownloadWork> downloadWork=new Dictionary<string,DownloadWork>(StringComparer.OrdinalIgnoreCase);
  string[] downloadRoots=new string[0];int downloadRootIndex;long nextDownloadPoll,nextDownloadDiscovery,downloadChecks;string downloadStatus="Waiting",downloadLastPath="",downloadLastResult="";
  string downloadSource;
  void ResetDownloads(){downloadWork.Clear();downloadRoots=new string[0];downloadRootIndex=0;nextDownloadPoll=nextDownloadDiscovery=downloadChecks=0;downloadStatus="Waiting";downloadLastPath=downloadLastResult="";}
  internal static string[] DownloadRoots(EndpointSettings c){
   var roots=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
   Action<string> add=path=>{if(string.IsNullOrWhiteSpace(path))return;try{string p=Path.GetFullPath(path).TrimEnd('\\');if(p.Length>=3&&p[1]==':'&&p[2]=='\\'&&p.Substring(2).IndexOf(':')<0&&string.Equals(Path.GetFileName(p),"Downloads",StringComparison.OrdinalIgnoreCase)&&c.Paths.Any(x=>Under(p,x))&&!Excluded(c,p))roots.Add(p);}catch(ArgumentException){}catch(NotSupportedException){}catch(PathTooLongException){}};
   foreach(var p in c.Paths){if(string.Equals(Path.GetFileName(p.TrimEnd('\\')),"Downloads",StringComparison.OrdinalIgnoreCase))add(p);}
   try{using(var profiles=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList")){
    if(profiles!=null)foreach(string sid in profiles.GetSubKeyNames()){
     if(!sid.StartsWith("S-1-5-21-",StringComparison.OrdinalIgnoreCase)&&!sid.StartsWith("S-1-12-1-",StringComparison.OrdinalIgnoreCase))continue;
     using(var profile=profiles.OpenSubKey(sid)){string path=profile==null?null:profile.GetValue("ProfileImagePath") as string;if(!string.IsNullOrWhiteSpace(path))add(Path.Combine(path,"Downloads"));}
    }
   }}catch(System.Security.SecurityException){if(roots.Count==0)throw;}catch(UnauthorizedAccessException){if(roots.Count==0)throw;}
   return roots.OrderBy(x=>x,StringComparer.OrdinalIgnoreCase).ToArray();
  }
  void PollDownloads(EndpointSettings c,long now){
   if(now>=nextDownloadDiscovery){nextDownloadDiscovery=now+60;try{downloadRoots=DownloadRoots(c);downloadRootIndex=0;}catch(Exception ex){downloadStatus="Profile discovery failed: "+ex.Message;}}
   if(downloadRoots.Length==0){if(!downloadStatus.StartsWith("Profile discovery failed",StringComparison.Ordinal))downloadStatus="No Downloads folder inside configured scan scope";return;}
   if(now<nextDownloadPoll)return;nextDownloadPoll=now+5;
   string root=downloadRoots[downloadRootIndex++%downloadRoots.Length];
   try{
    var list=UsnJournalService.FetchDownloads(root);
    if(list.Kind=="Missing"){downloadStatus="Folder missing: "+root;foreach(var path in downloadWork.Keys.Where(x=>Under(x,root)).ToArray())downloadWork.Remove(path);return;}
    if(list.Kind!="Downloads")throw new IOException(list.Detail??"Unexpected Downloads reply");
    var current=new HashSet<string>(StringComparer.OrdinalIgnoreCase);bool capped=false;
    foreach(var file in list.Downloads.OrderByDescending(x=>Math.Max(x.Created,x.Written))){
     if(!c.Paths.Any(x=>Under(file.Path,x))||Excluded(c,file.Path))continue;current.Add(file.Path);DownloadWork work;
     if(downloadWork.TryGetValue(file.Path,out work)&&work.Entry.Size==file.Size&&work.Entry.Written==file.Written&&work.Entry.Created==file.Created)continue;
     if(!downloadWork.ContainsKey(file.Path)&&downloadWork.Count>=32768){capped=true;continue;}
     downloadWork[file.Path]=new DownloadWork{Entry=file};
    }
    if(string.IsNullOrEmpty(list.Detail))foreach(var path in downloadWork.Keys.Where(x=>Under(x,root)&&!current.Contains(x)).ToArray())downloadWork.Remove(path);
    downloadStatus=capped?"Downloads tracking capacity reached; coverage incomplete":list.Detail??("Listing verified: "+root);
   }catch(Exception ex){downloadStatus="Downloads check failed: "+root+" · "+ex.Message;}
  }
  void ScanDownload(Sqlite db,EndpointSettings c,WaitHandle stop,Func<bool> authorized,long now){
   if(!online||!authorized()||stop.WaitOne(0))return;
   var work=downloadWork.Values.Where(x=>!x.Done&&x.Next<=now).OrderByDescending(x=>Math.Max(x.Entry.Created,x.Entry.Written)).FirstOrDefault(x=>!usn.RetryWaiting(db,x.Entry.Path));if(work==null)return;
   string p=work.Entry.Path;if(!c.Paths.Any(x=>Under(p,x))||Excluded(c,p)){work.Done=true;return;}
   long before=Convert.ToInt64(db.Rows("SELECT COALESCE(MAX(seq),0) FROM scan_activity")[0][0]);
   downloadSource="Downloads reconciliation";
   try{
    if(Program.ServiceMode&&c.Port==3310)CheckPrivileged(db,c,p,stop,authorized,false,c.CanaryPaths.Contains(p,StringComparer.OrdinalIgnoreCase),MaxLockedRetries,Stopwatch.StartNew(),"Dedicated Downloads scan");
    else CheckFile(db,c,p,stop,authorized,false,MaxLockedRetries);
   }finally{downloadSource=null;}
   var row=db.Rows("SELECT result,detail FROM scan_activity WHERE seq>? AND path=? COLLATE NOCASE ORDER BY seq DESC LIMIT 1",before,p).FirstOrDefault();
   downloadLastPath=p;downloadLastResult=row==null?"No verdict":(string)row[0]+" · "+(string)row[1];downloadChecks++;
   // A missing file is retried until the next complete listing confirms disappearance.
   work.Done=row!=null&&new[]{"Clean","Infected","Heuristic","Quarantined","Limited","Excluded","Reparse boundary"}.Contains((string)row[0]);work.Next=now+15;
  }

  internal void RequestReset(){Interlocked.Exchange(ref resetRequested,1);}
  readonly object historyResetGate=new object();
  string historyResetId="",historyResetState="Idle";long historyResetCutoff;bool historyResetRecoveryChecked;
  internal object HistoryResetStatus(){lock(historyResetGate)return new {id=historyResetId,state=historyResetState,through=historyResetCutoff};}
  internal object RequestHistoryReset(){lock(historyResetGate){
   if(historyResetState=="Queued"||historyResetState=="Running")throw new HttpError(409,"An endpoint history reset is already in progress.");
   historyResetId=Guid.NewGuid().ToString("N");historyResetState="Queued";historyResetCutoff=0;return HistoryResetStatus();
  }}
  // Called exclusively by the endpoint worker, before scans or outbox publication.
  // A local transaction records a restart-safe marker before the central alert purge.
  internal void ProcessHistoryReset(Alerts alerts){
   string requested;lock(historyResetGate)requested=historyResetState=="Queued"?historyResetId:null;
   if(requested==null&&(historyResetRecoveryChecked||!File.Exists(dbPath)))return;
   historyResetRecoveryChecked=false;
   using(var db=Open()){
    var marker=db.Rows("SELECT value FROM endpoint_metadata WHERE name='history-reset-pending'").FirstOrDefault();
    if(marker==null&&requested==null){historyResetRecoveryChecked=true;return;}
    string id=marker==null?requested:(string)marker[0];
    lock(historyResetGate){historyResetId=id;historyResetState="Running";}
    try{
     if(marker==null){
      db.Exec("BEGIN IMMEDIATE");try{
       db.Exec("DELETE FROM scan_activity");db.Exec("DELETE FROM clean_verdict_cache");ClearBaselineRows(db);db.Exec("DELETE FROM incidents");db.Exec("DELETE FROM files WHERE NOT EXISTS (SELECT 1 FROM findings f WHERE f.path=files.path COLLATE NOCASE AND f.active=1 AND f.change IN ('Malware signature detected','Heuristic signature finding','Quarantine withheld or failed','Canary integrity violation'))");db.Exec("DELETE FROM endpoint_probe WHERE finished IS NOT NULL");
       db.Exec("DELETE FROM findings WHERE active=0 OR severity='coverage' OR change IN ('File scan error','File scan limited','Engine scan incomplete','Protected path unavailable','Scan incomplete','File scan coverage incomplete','Watcher coverage incomplete','Scan traversal limit reached')");
       // Retain active malware, canary, response and unresolved journal/overflow findings.
       // Replace old pending transitions with a fresh publication of the retained findings.
       db.Exec("DELETE FROM endpoint_outbox");
       db.Exec("INSERT INTO endpoint_outbox (utc,id,path,change,severity,detail,hash,active) SELECT ?,id,path,change,severity,detail,hash,1 FROM findings WHERE active=1",History.Now());
       db.Exec("INSERT OR REPLACE INTO endpoint_metadata(name,value) VALUES('history-reset-pending',?)",id);
       db.Exec("COMMIT");
      }catch{db.Exec("ROLLBACK");throw;}
     }
     long cutoff=alerts.ResetEndpointHistory();
     // Do not discard live watcher arrivals, durable USN work, canary baselines or vault receipts.
     changes.Clear();highEntropy.Clear();extendedEntropy.Clear();extendedEntropyPeak=0;pending.Clear();visited.Clear();running=false;complete=false;rescan=false;reconcilePending=true;scanId=lastScan=nextScan=lastCanary=0;
     baselineRestorePending=false;baselineResumed=false;scanned=excluded=limited=errors=baselineCached=0;cachedChecks=metadataCachedChecks=0;cleanChecks=infectedChecks=heuristicChecks=excludedChecks=failedChecks=quarantinedChecks=deferredChecks=snapshotCleanChecks=realTimeChecked=privilegedFileChecks=lastFileScan=lastRealTimeScan=0;
     lastScannedPath="";ResetDownloads();Interlocked.Exchange(ref resetRequested,0);
     db.Exec("DELETE FROM endpoint_metadata WHERE name='history-reset-pending'");historyResetRecoveryChecked=true;
     lock(historyResetGate){historyResetCutoff=cutoff;historyResetState="Completed";}
     AppJournal.Event(LogLevel.Info,"Endpoint","history-reset","Endpoint history reset "+id+"; active security findings, canary baselines, quarantine evidence and journal work retained; new baseline scheduled.");
    }catch{lock(historyResetGate)historyResetState="Failed";throw;}
   }
  }

  internal EndpointProtection():this(Path.Combine(Config.Data,"endpoint")){} internal EndpointProtection(string directory){store=directory;dbPath=Path.Combine(store,"endpoint.sqlite");}
  internal static string Hash(byte[] b){using(var h=SHA256.Create())return BitConverter.ToString(h.ComputeHash(b)).Replace("-","").ToLowerInvariant();}
  internal static string Id(string p){return Hash(Encoding.UTF8.GetBytes(p.ToUpperInvariant()));}
  internal static bool Under(string p,string root){return string.Equals(p.TrimEnd('\\'),root.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase)||p.StartsWith(root.TrimEnd('\\')+"\\",StringComparison.OrdinalIgnoreCase);}
  internal static bool Excluded(EndpointSettings c,string p){return Under(p,Config.Root)||c.ExcludedPaths.Any(x=>Under(p,x))||c.ExcludedPatterns.Any(x=>Regex.IsMatch(Path.GetFileName(p),"^"+Regex.Escape(x).Replace("\\*",".*").Replace("\\?",".")+"$",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant,TimeSpan.FromMilliseconds(50)));}
  // Scheduled traversal only. Never apply this to watcher, USN, download or manual file probes.
  internal static bool BackgroundExcluded(EndpointSettings c,string p){return (c.BackgroundExcludedPaths??new string[0]).Any(x=>Under(p,x))&&!c.CanaryPaths.Any(x=>Under(x,p));}
  // Do not follow junctions, symbolic links or cloud reparse points, even in SYSTEM mode.
  internal sealed class ScanReparseException : IOException {internal ScanReparseException(string path):base("Reparse point skipped: "+path){} }
  internal static void SafePath(string p){for(string q=p;!string.IsNullOrEmpty(q);q=Path.GetDirectoryName(q)){if((File.GetAttributes(q)&FileAttributes.ReparsePoint)!=0)throw new ScanReparseException(q);}}
  internal static double Entropy(byte[] b,int n){if(n==0)return 0;var counts=new int[256];for(int i=0;i<n;i++)counts[b[i]]++;double h=0;foreach(int count in counts)if(count>0){double f=(double)count/n;h-=f*Math.Log(f,2);}return h;}
  internal static string FileHash(Stream s,EndpointReadBudget budget=null){using(var h=SHA256.Create()){
   if(budget==null)return BitConverter.ToString(h.ComputeHash(s)).Replace("-","").ToLowerInvariant();
   var b=new byte[65536];int n;while((n=budget.Read(s,b,0,b.Length))>0)h.TransformBlock(b,0,n,b,0);h.TransformFinalBlock(new byte[0],0,0);return BitConverter.ToString(h.Hash).Replace("-","").ToLowerInvariant();
  }}
  // ClamD may queue an INSTREAM request before returning its verdict. Use one
  // bounded budget for connect, send and response, not a five-second read cap.
  const int ClamScanDeadlineMs=30000,ClamControlDeadlineMs=5000;
  static void AwaitClam(Task operation,Stopwatch deadline,int budget,WaitHandle stop,string stage){
   while(!operation.IsCompleted){
    int remaining=budget-(int)deadline.ElapsedMilliseconds;
    if(stop.WaitOne(0)||remaining<=0){
     operation.ContinueWith(t=>{var ignored=t.Exception;},CancellationToken.None,TaskContinuationOptions.OnlyOnFaulted|TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);
     if(stop.WaitOne(0))throw new OperationCanceledException();
     throw new IOException("ClamAV "+stage+" timed out after "+budget+" ms; no signature verdict");
    }
    Task.WhenAny(operation,Task.Delay(Math.Min(remaining,200))).GetAwaiter().GetResult();
   }
   if(stop.WaitOne(0))throw new OperationCanceledException();
   operation.GetAwaiter().GetResult();
   if(deadline.ElapsedMilliseconds>budget)throw new IOException("ClamAV "+stage+" exceeded deadline; no signature verdict");
  }
  internal static string Command(int port,string cmd,Stream file,WaitHandle stop,Action<TcpClient> verifyPeer=null,EndpointReadBudget readBudget=null){
   int budget=file==null?ClamControlDeadlineMs:ClamScanDeadlineMs+(readBudget==null?0:20000);var deadline=Stopwatch.StartNew();string stage="connect";
   using(var c=new TcpClient(AddressFamily.InterNetwork))try{
    AwaitClam(c.ConnectAsync(IPAddress.Loopback,port),deadline,2000,stop,stage);
    stage="peer verification";if(verifyPeer!=null)verifyPeer(c);
    using(var stream=c.GetStream()){
     Action<byte[],int> send=(bytes,count)=>AwaitClam(stream.WriteAsync(bytes,0,count),deadline,budget,stop,stage);
     stage="send command";var command=Encoding.ASCII.GetBytes("z"+cmd+"\0");send(command,command.Length);
     if(file!=null){stage="send file";byte[] b=new byte[65536];int n;while((n=readBudget==null?file.Read(b,0,b.Length):readBudget.Read(file,b,0,b.Length))>0){if(stop.WaitOne(0))throw new OperationCanceledException();if(deadline.ElapsedMilliseconds>=budget)throw new IOException("Scan deadline exceeded");var size=BitConverter.GetBytes(IPAddress.HostToNetworkOrder(n));send(size,4);send(b,n);}send(new byte[4],4);}
     stage="await verdict";var reply=new List<byte>();var buf=new byte[512];
     while(reply.Count<4096){var read=stream.ReadAsync(buf,0,Math.Min(buf.Length,4096-reply.Count));AwaitClam(read,deadline,budget,stop,stage);int n=read.GetAwaiter().GetResult();if(n==0)throw new IOException("Incomplete engine reply");for(int i=0;i<n;i++){int x=buf[i];if(x==0||x==10)return Encoding.UTF8.GetString(reply.ToArray());reply.Add((byte)x);}}
     throw new IOException("Oversized engine reply");
    }
   }catch(OperationCanceledException){throw;}catch(Exception ex){throw new IOException("ClamAV "+stage+" ("+deadline.ElapsedMilliseconds+" ms): "+ex.Message,ex);}
  }
  internal static bool CleanVerdict(string reply){return string.Equals(reply,"stream: OK",StringComparison.Ordinal);}
  internal static bool Malware(string reply){return reply!=null&&reply.StartsWith("stream: ",StringComparison.Ordinal)&&reply.EndsWith(" FOUND",StringComparison.Ordinal)&&reply.Length>14&&!reply.StartsWith("stream: Heuristics.Limits.Exceeded",StringComparison.OrdinalIgnoreCase);}
  // Match a directory segment, not a filename or a substring of a folder name.
  internal static bool DownloadPriority(string path){return path!=null&&path.IndexOf(@"\Downloads\",StringComparison.OrdinalIgnoreCase)>=0;}
  void Enqueue(EndpointSettings c,string path,bool priority=false){
   // Filter before allocating queue space; LinkScope's own writes must not feed back into scanning.
   try{if(!c.Paths.Any(root=>Under(path,root))||Excluded(c,path))return;}catch(Exception){Interlocked.Exchange(ref overflow,1);return;}
   lock(watchGate){if(!ReferenceEquals(watchPolicy,c))return;
    var now=DateTime.UtcNow;priority=priority||DownloadPriority(path);WatchWork existing;
    if(watchQueue.TryGetValue(path,out existing)){existing.Last=now;existing.Priority|=priority;existing.ObservedWatcher=true;return;}
    if(watchQueue.Count>=(priority?MaxQueue:MaxQueue-PriorityReserve)){Interlocked.Exchange(ref overflow,1);return;}
    watchQueue.Add(path,new WatchWork{Path=path,First=now,Last=now,NotBefore=now,Priority=priority,ObservedWatcher=true});
   }
  }
  bool RetryLocked(EndpointSettings c,string path,int retries){
   if(!c.RealTime||retries>=MaxLockedRetries)return false;
   lock(watchGate){if(watchPolicy==null)return false;
    // A newer event already queued while scanning must not be overwritten.
    if(watchQueue.ContainsKey(path))return true;
    if(watchQueue.Count>=MaxQueue){Interlocked.Exchange(ref overflow,1);return false;}
    var now=DateTime.UtcNow;watchQueue.Add(path,new WatchWork{Path=path,First=now,Last=now,NotBefore=now.AddSeconds(2<<retries),Priority=true,Retries=retries+1,ObservedWatcher=string.Equals(watcherInspectionPath,path,StringComparison.OrdinalIgnoreCase)});return true;
   }
  }
  internal static bool LockedFile(Exception error){var io=error as IOException;return io!=null&&((io.HResult&65535)==32||(io.HResult&65535)==33);}
  bool HasWatcher(string path){lock(watchGate)return watchQueue.ContainsKey(path);}
  void RemoveWatcher(string path){lock(watchGate)watchQueue.Remove(path);}
  int[] WatchCounts(){lock(watchGate)return new[]{watchQueue.Count,watchQueue.Values.Count(x=>x.Priority)};}
  // 0: urgent creation/rename/download, 1: oldest eligible, 2: newest eligible (e.g. overwritten copy).
  WatchWork TakeWatcher(int lane){lock(watchGate){var now=DateTime.UtcNow;WatchWork best=null;
   foreach(var item in watchQueue.Values){
    if(now<item.NotBefore||((now-item.Last).TotalMilliseconds<750&&(now-item.First).TotalSeconds<5)|| (lane==0&&!item.Priority))continue;
    if(best==null){best=item;continue;}
    if(lane==0){bool download=DownloadPriority(item.Path),bestDownload=DownloadPriority(best.Path);if(download!=bestDownload?download:item.First<best.First)best=item;}
    else if(lane==2?item.Last>best.Last:item.First<best.First)best=item;
   }
   if(best!=null)watchQueue.Remove(best.Path);return best;
  }}
  // Optional native self-test: no watcher, filesystem or antivirus access is needed.
  internal static void PrioritySelfTest(){
   string root=Path.Combine(Path.GetTempPath(),"LinkScope-priority-fixture-"+Guid.NewGuid().ToString("N"));
   using(var ep=new EndpointProtection(root)){
    var settings=new EndpointSettings{Enabled=true,Paths=new[]{root},ExcludedPatterns=new[]{"*.tmp"}};ep.watchPolicy=settings;
    string old=Path.Combine(root,"old.txt"),copy=Path.Combine(root,"copy.exe"),download=Path.Combine(root,"Downloads","test.com");
    ep.Enqueue(settings,old);ep.Enqueue(settings,copy);ep.Enqueue(settings,copy.ToUpperInvariant(),true);ep.Enqueue(settings,download);ep.Enqueue(settings,Path.Combine(root,"skip.tmp"),true);
    if(ep.watchQueue.Count!=3||ep.watchQueue.Values.Count(x=>x.Priority)!=2)throw new IOException("Priority queue enqueue fixture failed");
    foreach(var work in ep.watchQueue.Values)work.NotBefore=DateTime.UtcNow.AddMinutes(1);
    if(ep.TakeWatcher(0)!=null)throw new IOException("Priority queue debounce fixture failed");
    DateTime now=DateTime.UtcNow;foreach(var work in ep.watchQueue.Values){work.First=work.Last=work.NotBefore=now.AddSeconds(-2);}
    ep.watchQueue[old].First=now.AddSeconds(-10);
    if(ep.TakeWatcher(0).Path!=download||ep.TakeWatcher(1).Path!=old||!string.Equals(ep.TakeWatcher(0).Path,copy,StringComparison.OrdinalIgnoreCase))throw new IOException("Priority queue selection fixture failed");
    if(!ep.RetryLocked(settings,copy,0)||ep.RetryLocked(settings,old,MaxLockedRetries))throw new IOException("Priority queue bounded retry fixture failed");
    ep.watchQueue[copy].First=ep.watchQueue[copy].Last=ep.watchQueue[copy].NotBefore=now.AddSeconds(-10);
    if(ep.TakeWatcher(0).Retries!=1)throw new IOException("Priority queue retry count fixture failed");
   }
  }
  // Keep the metadata heartbeat independent of slow ClamAV scans and SQLite work.
  // Only the scanner thread owns failedWatchers and the database. The pump owns
  // its scoped requests; results are published under a lock and events use Enqueue.
  const int PrivilegedWatcherFreshSeconds=30, PrivilegedWatcherStartupSeconds=15;
  sealed class PrivilegedWatcherState {internal long Verified,Next,Created;internal bool Failed;internal string Detail="Awaiting first privileged watcher request";}
  readonly object privilegedWatcherGate=new object();
  readonly Dictionary<string,PrivilegedWatcherState> privilegedWatcherStates=new Dictionary<string,PrivilegedWatcherState>(StringComparer.OrdinalIgnoreCase);
  EndpointSettings privilegedWatcherPolicy;Thread privilegedWatcherThread;bool privilegedWatcherStopping;int privilegedWatcherReconcile;
  static bool PrivilegedWatcherCovers(PrivilegedWatcherState state,long now){return state!=null&&state.Verified>0&&now>=state.Verified&&now-state.Verified<=PrivilegedWatcherFreshSeconds;}
  static bool PrivilegedWatcherInitializing(PrivilegedWatcherState state,long now){return state!=null&&!state.Failed&&state.Verified==0&&now>=state.Created&&now-state.Created<PrivilegedWatcherStartupSeconds;}
  void ResetPrivilegedWatchers(){lock(privilegedWatcherGate){privilegedWatcherStates.Clear();privilegedWatcherPolicy=null;Interlocked.Exchange(ref privilegedWatcherReconcile,0);}}
  void SyncPrivilegedWatchers(EndpointSettings c){lock(privilegedWatcherGate){
   if(privilegedWatcherStopping||!Program.ServiceMode||!c.RealTime||watchPolicy==null)return;
   privilegedWatcherPolicy=watchPolicy;
   foreach(var root in privilegedWatcherStates.Keys.Where(x=>!failedWatchers.ContainsKey(x)).ToArray())privilegedWatcherStates.Remove(root);
   foreach(var root in failedWatchers.Keys){if(c.CanaryPaths.Contains(root,StringComparer.OrdinalIgnoreCase))continue;if(!privilegedWatcherStates.ContainsKey(root))privilegedWatcherStates[root]=new PrivilegedWatcherState{Created=History.Now()};}
   if(privilegedWatcherThread==null&&privilegedWatcherStates.Count>0){privilegedWatcherThread=new Thread(PrivilegedWatcherLoop){IsBackground=true,Name="LinkScope privileged watcher heartbeat"};privilegedWatcherThread.Start();}
  }}
  void PrivilegedWatcherLoop(){while(true){
   string root=null;PrivilegedWatcherState state=null;EndpointSettings saved=null;
   lock(privilegedWatcherGate){
    if(privilegedWatcherStopping)return;
    if(privilegedWatcherPolicy!=null){long now=History.Now();var next=privilegedWatcherStates.Where(x=>x.Value.Next<=now).OrderBy(x=>x.Value.Next).FirstOrDefault();
     if(next.Key!=null){root=next.Key;state=next.Value;saved=privilegedWatcherPolicy;if(state.Verified==0)state.Detail="Contacting LinkScopeUsn privileged watcher";}}
   }
   if(root==null){Thread.Sleep(250);continue;}
   UsnJournalService.ScanBatch batch=null;string error=null;
   try{batch=UsnJournalService.FetchWatcher(root);if(batch.Kind!="Watcher")throw new IOException(batch.Detail??batch.Kind);}
   catch(Exception ex){error=ex.GetType().Name+": "+ex.Message;}
   long completed=History.Now();
   lock(privilegedWatcherGate){
    if(privilegedWatcherStopping)return;
    PrivilegedWatcherState current;
    // Never consume an old generation's results after a scope change or reset.
    if(!ReferenceEquals(saved,privilegedWatcherPolicy)||!privilegedWatcherStates.TryGetValue(root,out current)||!ReferenceEquals(current,state))continue;
    if(error==null){
     foreach(var path in batch.Children)Enqueue(saved,path,batch.WatchArrivals.Contains(path,StringComparer.OrdinalIgnoreCase));
     state.Verified=batch.WatchGap?0:completed;state.Failed=batch.WatchGap;
     state.Detail=batch.WatchGap?"Privileged watcher lost events; reconciliation requested":"Privileged recursive watcher active";state.Next=completed+2;
     if(batch.WatchStarted)Interlocked.Exchange(ref privilegedWatcherReconcile,1);if(batch.WatchGap)Interlocked.Exchange(ref overflow,1);
    }else{
     if(state.Verified>0||!state.Failed)Interlocked.Exchange(ref privilegedWatcherReconcile,1);
     state.Verified=0;state.Failed=true;state.Detail=error;state.Next=completed+10;
    }
   }
  }}
  Dictionary<string,PrivilegedWatcherState> PrivilegedWatcherSnapshot(){lock(privilegedWatcherGate){return privilegedWatcherStates.ToDictionary(x=>x.Key,x=>new PrivilegedWatcherState{Verified=x.Value.Verified,Next=x.Value.Next,Created=x.Value.Created,Failed=x.Value.Failed,Detail=x.Value.Detail},StringComparer.OrdinalIgnoreCase);}}
  void CloseWatchers(){ResetPrivilegedWatchers();lock(watchGate){watchPolicy=null;watchQueue.Clear();faultedWatchers.Clear();}foreach(var w in watchers)w.Dispose();watchers.Clear();localWatchers.Clear();failedWatchers.Clear();watcherFailures=0;}
  // Failed watcher roots are retried independently; do not reset successful watchers or queued arrivals.
  bool TryStartWatcher(EndpointSettings c,string p){FileSystemWatcher w=null;try{
   SafePath(p);bool dir=(File.GetAttributes(p)&FileAttributes.Directory)!=0;
   w=new FileSystemWatcher(dir?p:Path.GetDirectoryName(p),dir?"*":Path.GetFileName(p));w.IncludeSubdirectories=dir;w.InternalBufferSize=32768;w.NotifyFilter=NotifyFilters.FileName|NotifyFilters.DirectoryName|NotifyFilters.LastWrite|NotifyFilters.Size;
   w.Changed+=(s,e)=>Enqueue(c,e.FullPath);w.Created+=(s,e)=>Enqueue(c,e.FullPath,true);w.Deleted+=(s,e)=>Enqueue(c,e.FullPath);w.Renamed+=(s,e)=>{Enqueue(c,e.OldFullPath);Enqueue(c,e.FullPath,true);};var instance=w;w.Error+=(sender,e)=>{lock(watchGate){if(ReferenceEquals(watchPolicy,c))faultedWatchers[p]=instance;}Interlocked.Exchange(ref overflow,1);};
   w.EnableRaisingEvents=true;watchers.Add(w);localWatchers[p]=w;failedWatchers.Remove(p);return true;
  }catch(Exception ex){if(w!=null)w.Dispose();failedWatchers[p]=ex.GetType().Name+": "+ex.Message;return false;}}
  // Only a continuously registered recursive local watcher qualifies as redundant
  // evidence. A privileged watcher heartbeat or USN itself is not independent proof.
  bool IndependentLocalCoverage(EndpointSettings c,string volume){
   if(!c.RealTime||Interlocked.CompareExchange(ref overflow,0,0)!=0)return false;
   var roots=c.Paths.Where(p=>string.Equals(Path.GetPathRoot(p),volume,StringComparison.OrdinalIgnoreCase)).ToArray();
   if(roots.Length==0)return false;
   lock(watchGate){foreach(var root in roots){FileSystemWatcher w;if(faultedWatchers.ContainsKey(root)||!localWatchers.TryGetValue(root,out w)||!w.EnableRaisingEvents||!w.IncludeSubdirectories||!Directory.Exists(root))return false;}}
   return true;
  }
  void ConsumeCoverageOverflow(Sqlite db){if(Interlocked.Exchange(ref overflow,0)!=0){usn.InvalidateIndependentCoverage();seenOverflow++;nextScan=0;rescan=true;Issue(db,"Protected paths","Real-time queue overflow","warning","Events may have been missed; full reconciliation requested.");}}
  void ConsumeWatcherFaults(){
   KeyValuePair<string,FileSystemWatcher>[] faults;lock(watchGate){faults=faultedWatchers.ToArray();faultedWatchers.Clear();}
   foreach(var fault in faults){FileSystemWatcher current;if(!localWatchers.TryGetValue(fault.Key,out current)||!ReferenceEquals(current,fault.Value))continue;
    localWatchers.Remove(fault.Key);watchers.Remove(current);current.Dispose();failedWatchers[fault.Key]="Local watcher reported an error; registration must be renewed";nextWatcherRetry=0;}
   watcherFailures=failedWatchers.Count;
  }
  void RetryFailedWatchers(long now){
   // Use the original watcher policy object, not the freshly deserialized equivalent.
   var c=watchPolicy;if(c==null||failedWatchers.Count==0||now<nextWatcherRetry)return;
   nextWatcherRetry=now+60;bool recovered=false;foreach(var p in failedWatchers.Keys.ToArray())if(TryStartWatcher(c,p))recovered=true;
   watcherFailures=failedWatchers.Count;SyncPrivilegedWatchers(c);
   if(recovered){usn.InvalidateIndependentCoverage();nextScan=0;if(running)rescan=true;AppJournal.Event(LogLevel.Info,"Endpoint","watcher-recovery","Previously unavailable watcher restored; reconciliation scheduled.");}
  }
  void Configure(EndpointSettings c){nextWebAudit=0;webAuditState="Not checked";baselineRestorePending=true;baselineResumed=false;cachedChecks=metadataCachedChecks=0;baselineCached=0;CloseWatchers();ResetDownloads();changes.Clear();highEntropy.Clear();extendedEntropy.Clear();extendedEntropyPeak=0;pending.Clear();visited.Clear();running=false;complete=false;rescan=false;journalGapDuringScan=false;reconcilePending=true;scopeReconcilePending=true;scanId=lastScan=0;nextScan=0;lastEngine=0;lastSignatureComparison=0;engineFailures=0;engineNeedsScanProbe=false;nextEngineProbe=0;lastCanary=0;lastResponseCheck=0;responseVerifiedEpoch=0;responseEngineStatus="Not checked";responseEngineDetail="Waiting for response verification";responsePathsReadiness=new object[0];watcherFailures=0;nextWatcherRetry=0;realTimeChecked=lastFileScan=lastRealTimeScan=privilegedFileChecks=0;cleanChecks=infectedChecks=heuristicChecks=excludedChecks=failedChecks=deferredChecks=quarantinedChecks=snapshotCleanChecks=0;lastScannedPath="";auditStatus=c.ProcessCorrelation?"Awaiting matching audit evidence":"Disabled";scope=Id(Config.Json().Serialize(new {c.Paths,c.ExcludedPaths,c.ExcludedPatterns}));usn.Configure(c,scope);if(!c.Enabled||!c.RealTime)return;lock(watchGate)watchPolicy=c;foreach(var p in c.Paths)TryStartWatcher(c,p);watcherFailures=failedWatchers.Count;SyncPrivilegedWatchers(c);nextWatcherRetry=History.Now()+60;}
  Sqlite Open(){Directory.CreateDirectory(store);SafePath(store);var db=new Sqlite(dbPath,false);try{db.Exec("PRAGMA journal_mode=WAL");db.Exec("PRAGMA synchronous=FULL");db.Exec("CREATE TABLE IF NOT EXISTS files(scope TEXT,path TEXT COLLATE NOCASE,hash TEXT,entropy REAL,seen INTEGER,PRIMARY KEY(scope,path))");db.Exec("CREATE TABLE IF NOT EXISTS clean_verdict_cache(policy TEXT NOT NULL,path TEXT COLLATE NOCASE NOT NULL,hash TEXT NOT NULL,generation TEXT NOT NULL,verified INTEGER NOT NULL,PRIMARY KEY(policy,path))");if(!db.Rows("PRAGMA table_info(clean_verdict_cache)").Any(x=>Equals(x[1],"stamp")))db.Exec("ALTER TABLE clean_verdict_cache ADD COLUMN stamp TEXT");db.Exec("CREATE INDEX IF NOT EXISTS ep_cache_verified ON clean_verdict_cache(verified)");db.Exec("CREATE INDEX IF NOT EXISTS ep_cache_path ON clean_verdict_cache(path)");db.Exec("CREATE TABLE IF NOT EXISTS canaries(path TEXT COLLATE NOCASE PRIMARY KEY,hash TEXT NOT NULL)");db.Exec("CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY,path TEXT,change TEXT,severity TEXT,detail TEXT,hash TEXT,first INTEGER,last INTEGER,active INTEGER)");db.Exec("CREATE INDEX IF NOT EXISTS ep_findings_active_severity ON findings(active,severity,last)");db.Exec("CREATE INDEX IF NOT EXISTS ep_findings_path_active ON findings(path COLLATE NOCASE,active)");db.Exec("CREATE TABLE IF NOT EXISTS baseline_state(id INTEGER PRIMARY KEY CHECK(id=1),policy TEXT NOT NULL,scan INTEGER NOT NULL,scanned INTEGER NOT NULL,excluded INTEGER NOT NULL,limited INTEGER NOT NULL,errors INTEGER NOT NULL,cached INTEGER NOT NULL,capped INTEGER NOT NULL)");db.Exec("CREATE TABLE IF NOT EXISTS baseline_frontier(seq INTEGER PRIMARY KEY AUTOINCREMENT,path TEXT NOT NULL)");db.Exec("CREATE TABLE IF NOT EXISTS baseline_visited(path TEXT COLLATE NOCASE PRIMARY KEY)");db.Exec("CREATE TABLE IF NOT EXISTS incidents(seq INTEGER PRIMARY KEY AUTOINCREMENT,utc INTEGER,id TEXT,path TEXT,change TEXT,severity TEXT,detail TEXT,hash TEXT)");db.Exec("CREATE INDEX IF NOT EXISTS ep_incidents_utc ON incidents(utc)");db.Exec("CREATE TABLE IF NOT EXISTS quarantine_deletions(id TEXT PRIMARY KEY,path TEXT NOT NULL,hash TEXT NOT NULL,actor TEXT NOT NULL,requested INTEGER NOT NULL,completed INTEGER)");db.Exec("CREATE TABLE IF NOT EXISTS scan_activity(seq INTEGER PRIMARY KEY AUTOINCREMENT,utc INTEGER,path TEXT,source TEXT,result TEXT,durationMs INTEGER,detail TEXT)");db.Exec("CREATE TABLE IF NOT EXISTS endpoint_metadata(name TEXT PRIMARY KEY,value TEXT NOT NULL)");db.Exec("CREATE TABLE IF NOT EXISTS endpoint_stream(id TEXT NOT NULL)");db.Exec("INSERT INTO endpoint_stream SELECT ? WHERE NOT EXISTS (SELECT 1 FROM endpoint_stream)",Guid.NewGuid().ToString("N"));db.Exec("CREATE TABLE IF NOT EXISTS endpoint_outbox(seq INTEGER PRIMARY KEY AUTOINCREMENT,utc INTEGER,id TEXT,path TEXT,change TEXT,severity TEXT,detail TEXT,hash TEXT,active INTEGER)");UsnJournalMonitor.Schema(db);ProbeSchema(db);return db;}catch{db.Dispose();throw;}}
  // Installer supplies a known original hash, never a first-observed potentially altered file.
  internal void SeedSetupCanaries(string folder){using(var db=Open()){
   db.Exec("BEGIN IMMEDIATE");try{foreach(string name in CanaryTemplates.Names){string path=Path.Combine(folder,name),expected=CanaryTemplates.ExpectedHash(name);var existing=db.Rows("SELECT hash FROM canaries WHERE path=?",path).FirstOrDefault();if(existing!=null&&!Equals(existing[0],expected))throw new IOException("Existing canary baseline differs; no replacement permitted.");db.Exec("INSERT OR IGNORE INTO canaries(path,hash) VALUES(?,?)",path,expected);}db.Exec("COMMIT");}catch{db.Exec("ROLLBACK");throw;}
  }}
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)] static extern bool CreateDirectoryW(string name,IntPtr security);
  internal void CreateManagedCanaries(EndpointSettings policy,string directory){
   // No elevated helper: writes occur under the existing LinkScope service account.
   if(!policy.Enabled||!policy.Paths.Contains(directory,StringComparer.OrdinalIgnoreCase)||!EndpointResponse.SafeScope(directory)||!Directory.Exists(directory))throw new IOException("Select a saved, existing non-system monitored directory.");
   SafePath(directory);string folder=Path.Combine(directory,CanaryTemplates.FolderName);var paths=CanaryTemplates.Names.Select(n=>Path.Combine(folder,n)).ToArray();
   if(Excluded(policy,folder)||paths.Any(p=>Excluded(policy,p)))throw new IOException("The canary folder or files are excluded by the current policy.");
   using(var db=Open()){
    db.Exec("BEGIN IMMEDIATE");try{
     if(paths.Any(p=>db.Rows("SELECT hash FROM canaries WHERE path=?",p).Count>0)||Directory.Exists(folder)||File.Exists(folder))throw new IOException("Canaries already exist or were previously registered. Missing decoys will not be recreated; investigate first.");
     // Native exclusive folder creation rejects an existing directory, including an adversarial race.
     if(!CreateDirectoryW(folder,IntPtr.Zero))throw new IOException("Cannot create the decoy folder using the service's existing permissions (Windows error "+Marshal.GetLastWin32Error()+").");
     foreach(var p in paths)db.Exec("INSERT INTO canaries(path,hash) VALUES(?,?)",p,CanaryTemplates.ExpectedHash(Path.GetFileName(p)));
     db.Exec("COMMIT");
    }catch{db.Exec("ROLLBACK");throw;}
   }
   // Reservation is deliberately permanent if creation is partial or enrollment fails. Never replace a trusted original.
   SafePath(folder);foreach(var p in paths){SafePath(folder);using(var file=new FileStream(p,FileMode.CreateNew,FileAccess.Write,FileShare.None)){EndpointResponse.VerifyHandle(file.SafeFileHandle,p);var b=CanaryTemplates.Bytes(Path.GetFileName(p));file.Write(b,0,b.Length);file.Flush(true);}}
   CanaryTemplates.Verify(folder);
  }
  // Administrator-only, exact-file service probe. Never bypasses scope/exclusions,
  // never authorizes quarantine/containment, and never grants filesystem rights.
  static void ProbeSchema(Sqlite db){db.Exec("CREATE TABLE IF NOT EXISTS endpoint_probe(id TEXT PRIMARY KEY,path TEXT NOT NULL,created INTEGER NOT NULL,finished INTEGER,result TEXT,detail TEXT)");}
  internal static int RequestFileProbe(string input){
   if(string.IsNullOrWhiteSpace(input)||input.Length>1024||input.Any(char.IsControl)||input.Length<3||input[1]!=':'||input[2]!='\\'||input.Substring(2).Contains(":"))throw new IOException("Specify an absolute local file path.");
   string path=Path.GetFullPath(input);var c=Config.Load().Endpoint;
   if(!c.Enabled||!c.Paths.Any(x=>Under(path,x))||Excluded(c,path))throw new IOException("File outside enabled scan scope or excluded by policy.");
   if(Directory.Exists(path))throw new IOException("Select a file, not a directory.");
   string fileDb=Path.Combine(Config.Data,"endpoint","endpoint.sqlite");if(!File.Exists(fileDb))throw new IOException("Endpoint database not found. Start LinkScope and enable Endpoint Protection.");
   string id=Guid.NewGuid().ToString("N");long now=History.Now();
   using(var db=new Sqlite(fileDb,false)){
    ProbeSchema(db);db.Exec("BEGIN IMMEDIATE");try{
     db.Exec("DELETE FROM endpoint_probe WHERE created<?",now-86400);
     if(Convert.ToInt64(db.Rows("SELECT COUNT(*) FROM endpoint_probe WHERE finished IS NULL")[0][0])>=64)throw new IOException("Diagnostic queue full.");
     db.Exec("INSERT INTO endpoint_probe(id,path,created) VALUES(?,?,?)",id,path,now);db.Exec("COMMIT");
    }catch{db.Exec("ROLLBACK");throw;}
   }
   Console.WriteLine("Service scan requested: "+id+" | "+path);Console.WriteLine("Waiting for the actual LinkScope service account; no automatic response is authorized by this request.");
   var timer=Stopwatch.StartNew();while(timer.ElapsedMilliseconds<90000){
    using(var db=new Sqlite(fileDb,true)){var row=db.Rows("SELECT finished,result,detail FROM endpoint_probe WHERE id=?",id).FirstOrDefault();if(row!=null&&row[0]!=null){Console.WriteLine("Service result: "+row[1]);Console.WriteLine("Detail: "+row[2]);return Equals(row[1],"Clean")||Equals(row[1],"Infected")||Equals(row[1],"Heuristic")?0:1;}}
    Thread.Sleep(500);
   }
   Console.WriteLine("No service result within 90 seconds; request remains queued until processed or expired. Check service status and endpoint logs.");return 2;
  }
  void ProcessFileProbe(Sqlite db,EndpointSettings c,WaitHandle stop,Func<bool> authorized){
   if(stop.WaitOne(0)||!authorized())return;
   db.Exec("DELETE FROM endpoint_probe WHERE created<?",History.Now()-86400);
   var request=db.Rows("SELECT id,path FROM endpoint_probe WHERE finished IS NULL ORDER BY created,rowid LIMIT 1").FirstOrDefault();if(request==null)return;
   string id=(string)request[0],path=(string)request[1],result="Unavailable",detail="No signature verdict";
   try{
    if(!c.Enabled||!c.Paths.Any(x=>Under(path,x))||Excluded(c,path)){result="Excluded";detail="Current monitoring policy does not include this file.";}
    else if(Directory.Exists(path)){result="Failed";detail="Request must identify a file, not a directory.";}
    else if(!online){result="Unavailable";detail="ClamAV is offline; no file scan performed.";}
    else {
     long before=Convert.ToInt64(db.Rows("SELECT COALESCE(MAX(seq),0) FROM scan_activity")[0][0]);
     // The normal service scanner records findings and activity; prohibit automatic response for this diagnostic.
     CheckFile(db,c,path,stop,()=>false,false,MaxLockedRetries);
     var row=db.Rows("SELECT result,detail FROM scan_activity WHERE seq>? AND path=? COLLATE NOCASE ORDER BY seq DESC LIMIT 1",before,path).FirstOrDefault();
     if(row!=null){result=(string)row[0];detail=(string)row[1];}
    }
   }catch(OperationCanceledException){throw;}catch(Exception ex){result="Failed";detail=ex.GetType().Name+": "+ex.Message;}
   db.Exec("UPDATE endpoint_probe SET finished=?,result=?,detail=? WHERE id=?",History.Now(),result,detail,id);
   AppJournal.Event(LogLevel.Info,"Endpoint","exact-file-probe",result+" | "+path+" | "+detail);
  }
  internal static int TestEngineSignature(){
   var c=Config.Load().Endpoint;
   // Standard harmless EICAR test string, assembled in memory; no test file is written.
   byte[] test=Encoding.ASCII.GetBytes(@"X5O!P%@AP[4\PZX54(P^)7CC)7}"+"$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
   using(var stop=new ManualResetEvent(false))using(var stream=new MemoryStream(test,false)){
    string reply=Command(c.Port,"INSTREAM",stream,stop);Console.WriteLine("ClamAV EICAR memory probe: "+reply);
    bool found=Malware(reply)&&reply.IndexOf("Eicar",StringComparison.OrdinalIgnoreCase)>=0;
    Console.WriteLine(found?"PASS: ClamAV recognizes EICAR.":"FAIL: expected an EICAR signature verdict; check signature database and engine configuration.");return found?0:1;
   }
  }
  internal static void DiagnoseFile(string input){
   if(string.IsNullOrWhiteSpace(input)||input.Length>1024||input.Any(char.IsControl)||input.Length<3||input[1]!=':'||input[2]!='\\'||input.Substring(2).Contains(":"))throw new IOException("Specify an absolute local file path.");
   string path=Path.GetFullPath(input);var c=Config.Load().Endpoint;
   Console.WriteLine("Path: "+path);Console.WriteLine("Enabled: "+c.Enabled+"; real-time: "+c.RealTime+"; mode: "+c.Mode);
   bool inScope=c.Paths.Any(x=>Under(path,x)), excluded=Excluded(c,path);
   Console.WriteLine("In configured scope: "+inScope+"; excluded: "+excluded);
   string fileDb=Path.Combine(Config.Data,"endpoint","endpoint.sqlite");
   if(File.Exists(fileDb))using(var db=new Sqlite(fileDb,true)){
    var rows=db.Rows("SELECT utc,source,result,detail FROM scan_activity WHERE path=? COLLATE NOCASE ORDER BY seq DESC LIMIT 20",path);
    Console.WriteLine("Service scan activity (latest 20 retained matches): "+rows.Count);
    foreach(var row in rows)Console.WriteLine(Telemetry.Utc(Convert.ToInt64(row[0]))+" | "+row[1]+" | "+row[2]+" | "+row[3]);
    foreach(var row in db.Rows("SELECT change,severity,detail,active FROM findings WHERE path=? COLLATE NOCASE ORDER BY last DESC LIMIT 20",path))Console.WriteLine("Finding: "+row[0]+" | "+row[1]+" | active="+row[3]+" | "+row[2]);
    string key=Id(Config.Json().Serialize(new {c.Paths,c.ExcludedPaths,c.ExcludedPatterns}));
    Console.WriteLine("Durable journal pending: "+(db.Rows("SELECT 1 FROM usn_pending WHERE scope=? AND path=?",key,path).Count>0));
   }else Console.WriteLine("Service endpoint database not found.");
   Console.WriteLine("Direct engine probe uses the invoking account, NOT the LinkScope service identity; it does not create an alert or change the file.");
   if(!c.Enabled||!inScope||excluded){Console.WriteLine("Probe skipped: path outside enabled scan policy.");return;}
   try{SafePath(path);using(var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read))using(var stop=new ManualResetEvent(false)){
    if(file.Length>c.MaxFileMiB*1048576L){Console.WriteLine("Probe skipped: file exceeds configured size cap.");return;}
    Console.WriteLine("Direct ClamAV result: "+Command(c.Port,"INSTREAM",file,stop));
   }}catch(Exception ex){Console.WriteLine("Direct probe failed: "+ex.GetType().Name+": "+ex.Message);}
  }
  void Activity(Sqlite db,string path,bool full,string result,Stopwatch timer,string detail=""){
   if(result=="Cached clean")cachedChecks++;else if(result=="Clean")cleanChecks++;else if(result=="Clean snapshot")snapshotCleanChecks++;else if(result=="Infected")infectedChecks++;else if(result=="Heuristic")heuristicChecks++;else if(result=="Excluded")excludedChecks++;else if(result=="Quarantined"){infectedChecks++;quarantinedChecks++;}else if(result=="Deferred")deferredChecks++;else failedChecks++;
   // Fixed-size persistent activity ring; threat incidents and alert outbox are independent.
   db.Exec("INSERT INTO scan_activity(utc,path,source,result,durationMs,detail) VALUES(?,?,?,?,?,?)",History.Now(),path,downloadSource??(full?"Scheduled / manual":"Real-time / canary"),result,timer.ElapsedMilliseconds,detail.Length>1024?detail.Substring(0,1024):detail);
   db.Exec("DELETE FROM scan_activity WHERE seq<=(SELECT MAX(seq)-1000 FROM scan_activity)");
  }
  void Issue(Sqlite db,string path,string change,string severity,string detail,string hash=""){string id=Id(path+"|"+change);long now=History.Now();var prior=db.Rows("SELECT active,hash,detail,severity FROM findings WHERE id=?",id).FirstOrDefault();bool fresh=prior==null||Convert.ToInt64(prior[0])==0||!Equals(prior[1],hash)||!Equals(prior[3],severity);db.Exec("BEGIN IMMEDIATE");try{if(fresh){db.Exec("INSERT INTO incidents(utc,id,path,change,severity,detail,hash) VALUES(?,?,?,?,?,?,?)",now,id,path,change,severity,detail,hash);db.Exec("INSERT OR REPLACE INTO findings VALUES(?,?,?,?,?,?,?,?,1)",id,path,change,severity,detail,hash,now,now);db.Exec("INSERT INTO endpoint_outbox(utc,id,path,change,severity,detail,hash,active) VALUES(?,?,?,?,?,?,?,1)",now,id,path,change,severity,detail,hash);}else db.Exec("UPDATE findings SET last=?,detail=? WHERE id=?",now,detail,id);db.Exec("COMMIT");}catch{db.Exec("ROLLBACK");throw;}}
  void Resolve(Sqlite db,string path,string change){string id=Id(path+"|"+change);var current=db.Rows("SELECT severity FROM findings WHERE id=? AND active=1",id).FirstOrDefault();if(current==null)return;if(Equals(current[0],"coverage")){db.Exec("UPDATE findings SET active=0 WHERE id=?",id);return;}db.Exec("BEGIN IMMEDIATE");try{db.Exec("INSERT INTO endpoint_outbox(utc,id,path,change,severity,detail,hash,active) SELECT ?,id,path,change,severity,detail,hash,0 FROM findings WHERE id=? AND active=1",History.Now(),id);db.Exec("UPDATE findings SET active=0 WHERE id=?",id);db.Exec("COMMIT");}catch{db.Exec("ROLLBACK");throw;}}
  // Ordinary scan failures are coverage diagnostics, not threat incidents. Keep
  // the latest per-path state durable, but publish only one aggregate warning.
  internal const string CoverageConsolidated="Superseded by consolidated scan coverage warning";
  internal static bool RoutineCoverage(EndpointSettings c,string path,string change){
   // A shared scanner outage is always one engine incident, including canary and explicit file roots.
   return change=="Engine scan incomplete"||(change=="File scan error"||change=="File scan limited")&&!c.Paths.Contains(path,StringComparer.OrdinalIgnoreCase)&&!c.CanaryPaths.Contains(path,StringComparer.OrdinalIgnoreCase);
  }
  internal static void RecordCoverage(Sqlite db,string path,string change,string detail){
   string id=Id(path+"|"+change);long now=History.Now();
   db.Exec("INSERT OR IGNORE INTO findings VALUES(?,?,?,?,?,?,?,?,1)",id,path,change,"coverage",detail,"",now,now);
   db.Exec("UPDATE findings SET severity='coverage',detail=?,last=?,active=1 WHERE id=?",detail,now,id);
  }
  void ScanIssue(Sqlite db,EndpointSettings c,string path,string change,string detail){
   if(RoutineCoverage(c,path,change))RecordCoverage(db,path,change,detail);
   else Issue(db,path,change,"warning",detail);
  }
  // Convert old per-file alerts transactionally. A special close transition
  // retires obsolete notifications without claiming the file became readable.
  internal static int ConsolidateCoverage(Sqlite db,EndpointSettings c){
   int count=0;db.Exec("BEGIN IMMEDIATE");try{
    foreach(var row in db.Rows("SELECT id,path,change,severity,active FROM findings WHERE change IN ('File scan error','File scan limited','Engine scan incomplete')")){
     string id=(string)row[0],path=(string)row[1],change=(string)row[2];
     bool routine=RoutineCoverage(c,path,change),wasCoverage=Equals(row[3],"coverage");
     if(!routine){if(wasCoverage)db.Exec("UPDATE findings SET active=0 WHERE id=?",id);continue;}
     if(wasCoverage)continue;
     // No malware, heuristic, canary violation or other security row is touched.
     bool live=Convert.ToInt64(row[4])!=0&&!ObsoleteCoverageFinding(c,path,change);
     db.Exec("DELETE FROM endpoint_outbox WHERE id=?",id);
     db.Exec("INSERT INTO endpoint_outbox(utc,id,path,change,severity,detail,hash,active) VALUES(?,?,?,?,?,?,?,0)",History.Now(),id,path,change,"warning",CoverageConsolidated,"");
     db.Exec("UPDATE findings SET severity='coverage',active=? WHERE id=?",live?1:0,id);count++;
    }
    db.Exec("COMMIT");return count;
   }catch{db.Exec("ROLLBACK");throw;}
  }
  internal static string CoverageKind(string change,string detail){
   if(change=="File scan limited")return "Size limit";
   if(change=="Engine scan incomplete")return "Engine incomplete";
   if(detail.StartsWith("Deferred: file in use",StringComparison.Ordinal))return "Deferred — file in use";
   if(detail.StartsWith("Reparse boundary:",StringComparison.Ordinal))return "Reparse boundary — target unverified";
   return change;
  }
  void CoverageSummary(Sqlite db,long count){
   if(count>0)Issue(db,"Protected paths","File scan coverage incomplete","warning",count+" outstanding file/path checks. See Scan coverage details for deferred, inaccessible, reparse-boundary, size-limited or engine-incomplete checks. No malware verdict is implied.");
   else Resolve(db,"Protected paths","File scan coverage incomplete");
  }
  // Policy changes retire obsolete operational coverage warnings, not security evidence.
  // Use the same path boundary and exclusion rules as the actual scanner.
  internal static bool ObsoleteCoverageFinding(EndpointSettings c,string path,string change){
   if(change=="USN journal unavailable"||change=="USN journal coverage gap")
    return !c.RealTime||!c.Paths.Select(Path.GetPathRoot).Any(root=>string.Equals(root,path,StringComparison.OrdinalIgnoreCase));
   if(change=="Protected path unavailable")return !c.Paths.Contains(path,StringComparer.OrdinalIgnoreCase)||Excluded(c,path);
   if(change!="File scan error"&&change!="File scan limited"&&change!="Engine scan incomplete")return false;
   return !c.Paths.Any(root=>Under(path,root))||Excluded(c,path);
  }
  internal static int ReconcileCoverageScope(Sqlite db,EndpointSettings c){
   // Run before scanning or reporting, including on the first tick after upgrade.
   // Each retirement and its central-alert transition are committed together.
   int count=0;db.Exec("BEGIN IMMEDIATE");try{
    foreach(var row in db.Rows("SELECT id,path,change FROM findings WHERE active=1 AND change IN ('File scan error','File scan limited','Engine scan incomplete','Protected path unavailable','USN journal unavailable','USN journal coverage gap')")){
     if(!ObsoleteCoverageFinding(c,(string)row[1],(string)row[2]))continue;
     string id=(string)row[0];
     db.Exec("INSERT INTO endpoint_outbox(utc,id,path,change,severity,detail,hash,active) SELECT ?,id,path,change,severity,detail,hash,0 FROM findings WHERE id=? AND active=1 AND severity<>'coverage'",History.Now(),id);
     db.Exec("UPDATE findings SET active=0 WHERE id=?",id);count++;
    }
    db.Exec("COMMIT");return count;
   }catch{db.Exec("ROLLBACK");throw;}
  }
  internal void Publish(Alerts alerts,Config cfg,bool successfulTick){if(!File.Exists(dbPath))return;using(var db=Open()){
   var batch=db.Rows("SELECT seq,utc,id,path,change,severity,detail,hash,active FROM endpoint_outbox ORDER BY seq LIMIT 256");
   if(batch.Count>0){alerts.EndpointTransitions((string)db.Rows("SELECT id FROM endpoint_stream LIMIT 1")[0][0],batch,cfg);db.Exec("DELETE FROM endpoint_outbox WHERE seq<=?",batch.Last()[0]);}
   // Refresh the one operational watcher alert from its authoritative finding even if
   // the full scan is incomplete. Do not create a new incident or email on detail changes.
   if(successfulTick&&cfg.Endpoint.Enabled&&db.Rows("SELECT 1 FROM endpoint_outbox LIMIT 1").Count==0){
    string watcherId=Id("Protected paths|Watcher coverage incomplete");
    var watcher=db.Rows("SELECT detail FROM findings WHERE id=? AND active=1",watcherId).FirstOrDefault();
    alerts.RefreshEndpointWatcherFinding(watcherId,watcher==null?null:"Protected paths · "+(string)watcher[0]);
   }
   // Reconcile legacy/orphaned central incident keys only after a complete successful scan
   // and delivery of ALL pending transitions. Never infer recovery from the 200-row UI cap.
   if(reconcilePending&&successfulTick&&cfg.Endpoint.Enabled&&complete&&online&&!running&&db.Rows("SELECT 1 FROM endpoint_outbox LIMIT 1").Count==0){
    var ids=new HashSet<string>(db.Rows("SELECT id FROM findings WHERE active=1 AND severity<>'coverage'").Select(r=>(string)r[0]),StringComparer.Ordinal);
    alerts.ReconcileEndpointFindings(ids);reconcilePending=false;
   }
  }}
  void ClearBaselineRows(Sqlite db){db.Exec("DELETE FROM baseline_state");db.Exec("DELETE FROM baseline_frontier");db.Exec("DELETE FROM baseline_visited");}
  void ClearBaseline(Sqlite db){db.Exec("BEGIN IMMEDIATE");try{ClearBaselineRows(db);db.Exec("COMMIT");}catch{db.Exec("ROLLBACK");throw;}}
  void StartScan(Sqlite db,EndpointSettings c){
   long id=DateTime.UtcNow.Ticks;
   db.Exec("BEGIN IMMEDIATE");try{
    ClearBaselineRows(db);db.Exec("INSERT INTO baseline_state VALUES(1,?,?,0,0,0,0,0,0)",CachePolicy(c),id);
    foreach(var p in c.Paths)db.Exec("INSERT INTO baseline_frontier(path) VALUES(?)",p);
    db.Exec("COMMIT");
   }catch{db.Exec("ROLLBACK");baselineRestorePending=true;throw;}
   baselineCached=0;baselineResumed=false;running=true;traversalLimitReached=false;journalGapDuringScan=false;complete=false;reconcilePending=true;scanId=id;pending.Clear();visited.Clear();foreach(var p in c.Paths)pending.Push(p);scanned=excluded=limited=errors=0;
  }
  void RestoreBaseline(Sqlite db,EndpointSettings c){
   if(!baselineRestorePending)return;
   var state=db.Rows("SELECT policy,scan,scanned,excluded,limited,errors,cached,capped FROM baseline_state WHERE id=1").FirstOrDefault();
   if(state!=null&&Equals(state[0],CachePolicy(c))){
    var frontier=db.Rows("SELECT path FROM baseline_frontier ORDER BY seq LIMIT 100001");var seen=db.Rows("SELECT path FROM baseline_visited LIMIT 100002");
    if(frontier.Count<=MaxEntries&&seen.Count<=MaxEntries+1&&frontier.Concat(seen).All(x=>x[0] is string&&c.Paths.Any(root=>Under((string)x[0],root)))){
     scanId=Convert.ToInt64(state[1]);scanned=Convert.ToInt32(state[2]);excluded=Convert.ToInt32(state[3]);limited=Convert.ToInt32(state[4]);errors=Convert.ToInt32(state[5]);baselineCached=Convert.ToInt32(state[6]);traversalLimitReached=Convert.ToInt32(state[7])!=0;
     pending.Clear();visited.Clear();foreach(var row in frontier)pending.Push((string)row[0]);foreach(var row in seen)visited.Add((string)row[0]);
     // Resume work, but never declare a pre-restart traversal authoritative. A new
     // content-verified reconciliation follows it, even if journal replay succeeds.
     running=true;complete=false;baselineResumed=true;rescan=true;journalGapDuringScan=true;reconcilePending=true;
     AppJournal.Event(LogLevel.Info,"Endpoint","baseline-resume","Resuming "+pending.Count+" saved paths; follow-up reconciliation required.");
    }else ClearBaseline(db);
   }else if(state!=null)ClearBaseline(db);
   baselineRestorePending=false;
  }
  void PushBaselineChild(string child){pending.Push(child);if(baselineChildren!=null)baselineChildren.Add(child);}
  void CheckpointBaselineStep(Sqlite db,long seq,string path,bool added){
   db.Exec("BEGIN IMMEDIATE");try{
    db.Exec("DELETE FROM baseline_frontier WHERE seq=?",seq);
    if(added)db.Exec("INSERT OR IGNORE INTO baseline_visited(path) VALUES(?)",path);
    if(traversalLimitReached)db.Exec("DELETE FROM baseline_frontier");else foreach(string child in baselineChildren)db.Exec("INSERT INTO baseline_frontier(path) VALUES(?)",child);
    db.Exec("UPDATE baseline_state SET scanned=?,excluded=?,limited=?,errors=?,cached=?,capped=? WHERE id=1",scanned,excluded,limited,errors,baselineCached,traversalLimitReached?1:0);
    db.Exec("COMMIT");
   }catch{db.Exec("ROLLBACK");throw;}
  }
  // Coalesce routine directory notifications at the normal interval. A confirmed
  // journal/watcher gap must schedule a fresh reconciliation immediately.
  void RequestReconciliation(EndpointSettings c,bool journalGap){
   if(journalGap){if(running){journalGapDuringScan=true;rescan=true;}else nextScan=0;return;}
   if(running)return;
   long earliest=lastScan==0?History.Now():Math.Max(History.Now(),lastScan+Math.Min(c.IntervalSeconds,300));
   nextScan=Math.Min(nextScan,earliest);
  }
  // Reconciliation has a bounded recovery cadence, independent of the normal
  // baseline interval. Transient errors must not block their own reinspection.
  // Policy limits and reparse boundaries retain the normal schedule.
  internal static long CoverageRecoveryDue(long scheduled,long last,bool running,bool complete,bool online,bool blocked,bool pathFailures,int interval){
   if(running||complete||!online||blocked||last<=0)return scheduled;
   return Math.Min(scheduled,last+Math.Min(interval,pathFailures?900:300));
  }
  void ScheduleCoverageRecovery(Sqlite db,EndpointSettings c){
   if(running||complete||!online||lastScan<=0||traversalLimitReached)return;
   if(db.Rows("SELECT 1 FROM findings WHERE active=1 AND change IN ('Scan incomplete','USN journal coverage gap','Real-time queue overflow') LIMIT 1").Count==0)return;
   bool failures=db.Rows("SELECT 1 FROM findings WHERE active=1 AND (severity='coverage' OR change IN ('File scan error','File scan limited','Engine scan incomplete','Protected path unavailable','Scan traversal limit reached','Watcher coverage incomplete','USN journal unavailable')) LIMIT 1").Count!=0;
   bool policyBoundary=db.Rows("SELECT 1 FROM findings WHERE active=1 AND (change='File scan limited' OR (change='File scan error' AND detail LIKE 'Reparse boundary:%') OR change='Scan traversal limit reached') LIMIT 1").Count!=0;
   long due=CoverageRecoveryDue(nextScan,lastScan,running,complete,online,policyBoundary||(c.BackgroundPauseOnLowMemory&&resourceMonitor.LowMemory),failures,c.IntervalSeconds);
   if(due<nextScan){nextScan=due;AppJournal.Event(LogLevel.Info,"Endpoint","coverage-recovery",failures?"Bounded follow-up reconciliation scheduled for unresolved path checks. Findings remain active until verified recovery.":"Fresh reconciliation scheduled after outstanding path failures cleared. Prior findings remain active until a complete scan verifies recovery.");}
  }
  void Observe(string p,bool entropy){DateTime now=DateTime.UtcNow;if(changes.Count<MaxEntries)changes[p]=now;if(entropy){if(highEntropy.Count<MaxEntries||highEntropy.ContainsKey(p))highEntropy[p]=now;if(extendedEntropy.Count<MaxEntries||extendedEntropy.ContainsKey(p))extendedEntropy[p]=now;}latestChanged=p;}
  void CanaryIssue(Sqlite db,EndpointSettings c,string path,string detail,string hash,WaitHandle stop,Func<bool> authorized){
   string id=Id(path+"|Canary integrity violation");var existing=db.Rows("SELECT hash FROM findings WHERE id=? AND active=1",id).FirstOrDefault();bool fresh=existing==null||!Equals(existing[0],hash);
   var lab=ActiveLabCanary(c,path);EndpointWriter writer=null;string correlation=fresh?Correlate(c,path,out writer,lab==null,lab==null?0:lab.Watermark):"";
   // Controlled incident is generated by the normal detector. Never dispatch process
   // termination for a test enrollment; record the actual watcher source and audit evidence.
   if(lab!=null)detail+=" [Controlled enrolled-canary validation; source="+(string.Equals(watcherInspectionPath,path,StringComparison.OrdinalIgnoreCase)?"watcher":"other scanner")+"; expected="+lab.Expected+"]";
   Issue(db,path,"Canary integrity violation","critical",detail+(fresh?" "+correlation:""),hash);
   var controlled=labCanary;if(controlled!=null&&string.Equals(controlled.Path,path,StringComparison.OrdinalIgnoreCase))return;
   if(fresh&&c.Mode=="contain"&&authorized())try{var a=EndpointResponse.FindWriter(path);if(a==null)throw new IOException("No matching write audit record");bool exitVerified;string result=EndpointResponse.Contain(c,a,stop,authorized,out exitVerified);Issue(db,a.Image,"Containment action",exitVerified?"info":"warning",result);if(exitVerified)Resolve(db,a.Image,"Containment action");}catch(Exception ex){Issue(db,path,"Containment withheld","warning",ex.Message);}
  }
  // Retry one previous peer-access failure after a successful readiness transition.
  // All other failures retain the existing one-hour cooldown. Every retry still re-scans
  // the same bytes and verifies the actual connected process and administrator's pin.
  bool ResponseRetryAllowed(Sqlite db,string path,string hash){
   var prior=db.Rows("SELECT last,detail FROM findings WHERE id=? AND hash=? AND last>?",Id(path+"|Quarantine withheld or failed"),hash,History.Now()-3600).FirstOrDefault();
   if(prior==null)return true;
   return responseEngineStatus=="Ready"&&Convert.ToInt64(prior[0])<responseVerifiedEpoch&&Convert.ToString(prior[1]).StartsWith("IOException: Cannot inspect ClamD peer process",StringComparison.Ordinal);
  }
  void CheckResponseReadiness(Sqlite db,EndpointSettings c,WaitHandle stop,long now,bool force){
   if(!force&&lastResponseCheck!=0&&now-lastResponseCheck<60)return;
   lastResponseCheck=now;string previous=responseEngineStatus;
   if(c.Mode=="monitor"){
    responseEngineStatus="Detection only";responseEngineDetail="Automatic response is disabled in Monitor mode.";responsePathsReadiness=new object[0];
    Resolve(db,"ClamAV","Response engine verification unavailable");return;
   }
   try{
    responseEngineDetail=EndpointResponse.CheckResponseEngine(c,stop);responseEngineStatus="Ready";
    Resolve(db,"ClamAV","Response engine verification unavailable");
    if(previous!="Ready"){responseVerifiedEpoch=History.Now();nextScan=0;if(running)rescan=true;}
   }catch(OperationCanceledException){throw;}catch(Exception ex){
    responseEngineStatus="Not ready";responseEngineDetail=ex.GetType().Name+": "+ex.Message;
    Issue(db,"ClamAV","Response engine verification unavailable","warning",responseEngineDetail);
   }
   responsePathsReadiness=EndpointResponse.CheckResponsePaths(c);
  }
  void ScanNext(Sqlite db,EndpointSettings c,WaitHandle stop,Func<bool> authorized){
   if(stop.WaitOne(0))throw new OperationCanceledException();if(!authorized())return;
   baselineChildren=new List<string>();try{
    var top=db.Rows("SELECT seq,path FROM baseline_frontier ORDER BY seq DESC LIMIT 1").FirstOrDefault();
    if(top==null||!Equals(top[1],pending.Peek()))throw new IOException("Baseline checkpoint and in-memory frontier differ");
    string path=pending.Pop();bool added=visited.Add(path);
    if(added){
     if(visited.Count>MaxEntries){errors++;traversalLimitReached=true;Issue(db,"Protected paths","Scan traversal limit reached","warning","Baseline exceeded "+MaxEntries+" paths; unvisited entries remain unverified. Narrow or split the configured scope only after review.");pending.Clear();}
     else if(!CheckFile(db,c,path,stop,authorized,true)&&c.RealTime&&!c.CanaryPaths.Contains(path,StringComparer.OrdinalIgnoreCase)){if(usn.RetainWatcher(db,path,DownloadPriority(path)))usn.Defer(db,path);else Interlocked.Exchange(ref overflow,1);}
    }
    // File inspection and its findings commit before the frontier advances. If
    // interrupted between them the same path is safely reprocessed on restart.
    if(!authorized())throw new IOException("Endpoint policy changed during baseline step");
    CheckpointBaselineStep(db,Convert.ToInt64(top[0]),path,added);
   }catch{running=false;complete=false;baselineRestorePending=true;throw;}finally{baselineChildren=null;}
  }
  long nextWebAudit; string webAuditState="Not checked";
  void RecordWebInspection(Sqlite db,string path,string hash,string result){
   if(result==WebServerProtection.NoMatch){Resolve(db,path,WebServerProtection.Coverage);Resolve(db,path,WebServerProtection.Finding);}
   else if(result!=null&&result.StartsWith("Review: ",StringComparison.Ordinal)){Resolve(db,path,WebServerProtection.Coverage);Issue(db,path,WebServerProtection.Finding,"warning",result+". Heuristic evidence only; investigate before response.",hash);}
   else Issue(db,path,WebServerProtection.Coverage,"warning",result!=null&&result.StartsWith("Unverified: ",StringComparison.Ordinal)?result:"Supplemental script result missing or unsupported; verify service and helper versions.");
   db.Exec("INSERT OR REPLACE INTO endpoint_metadata(name,value) VALUES('web-script-last-check',?)",History.Now().ToString(System.Globalization.CultureInfo.InvariantCulture));
  }
  void SaveWebAuditCursor(Sqlite db,long record){db.Exec("INSERT OR REPLACE INTO endpoint_metadata(name,value) VALUES('web-audit-cursor',?)",record.ToString(System.Globalization.CultureInfo.InvariantCulture));}
  const string WebAuditSource="Windows Security log (web processes)";
  const string WebAuditPolicySource="Windows Security log (web processes) — audit policy";
  const string WebAuditPolicyGapDetail="Process creation audit policy was disabled or unverified; historical evidence may be incomplete.";
  // Retire only a policy-availability incident after verified current recovery.
  // Keep the original incident/outbox history and a durable historical limitation.
  // Older builds used a shared finding key for all audit gaps: require both the
  // retained opening evidence and latest detail to identify a policy-only gap.
  void RecoverWebAuditPolicyGap(Sqlite db,Func<bool> authorized,long watermark){
   var candidates=new List<object[]>();
   foreach(string path in new[]{WebAuditPolicySource,WebAuditSource}){
    string id=Id(path+"|"+WebServerProtection.AuditGap);
    var row=db.Rows("SELECT first,last,detail FROM findings WHERE id=? AND active=1",id).FirstOrDefault();
    if(row==null||!Equals(row[2],WebAuditPolicyGapDetail))continue;
    if(path==WebAuditSource){
     var opening=db.Rows("SELECT detail FROM incidents WHERE id=? AND utc>=? ORDER BY seq",id,row[0]);
     if(opening.Count==0||opening.Any(x=>!Equals(x[0],WebAuditPolicyGapDetail)))continue;
    }
    candidates.Add(new object[]{path,row[0],row[1]});
   }
   if(candidates.Count==0||!authorized())return;
   if(!WebServerProtection.ProcessAuditEnabled())throw new IOException("Audit Process Creation success policy changed during review.");
   foreach(var row in candidates){
    if(!authorized())return;
    // Persist the limitation before publishing recovery. If interrupted, the
    // finding remains active and the next verified review can safely retry.
    string notice="Historical process audit policy outage: first observed "+Telemetry.Utc(Convert.ToInt64(row[1]))+"; last observed "+Telemetry.Utc(Convert.ToInt64(row[2]))+"; current policy reverified "+Telemetry.Utc(History.Now())+"; retained Security records reviewed through record "+watermark+". Events not recorded during the outage cannot be recovered; historical coverage remains incomplete.";
    db.Exec("INSERT OR REPLACE INTO endpoint_metadata(name,value) VALUES('web-audit-recovered-policy-gap',?)",notice);
    Resolve(db,(string)row[0],WebServerProtection.AuditGap);
   }
  }
  void PollWebProcessAudit(Sqlite db,EndpointSettings c,WaitHandle stop,Func<bool> authorized){
   const string source=WebAuditSource;
   if(!c.WebProtectionEnabled||!c.WebProcessAuditEnabled){webAuditState="Disabled";nextWebAudit=0;return;}
   long now=History.Now();if(now<nextWebAudit)return;nextWebAudit=now+10;
   try{
    try{if(!WebServerProtection.ProcessAuditEnabled())throw new IOException("Audit Process Creation success policy is disabled.");}
    catch(Exception){Issue(db,WebAuditPolicySource,WebServerProtection.AuditGap,"warning",WebAuditPolicyGapDetail);throw;}
    var oldest=WebServerProtection.Edge(false);var newest=WebServerProtection.Edge(true);
    if(!oldest.HasValue||!newest.HasValue)throw new IOException("Security log record bounds unavailable.");
    var row=db.Rows("SELECT value FROM endpoint_metadata WHERE name='web-audit-cursor'").FirstOrDefault();
    long cursor=row==null?Math.Max(0,oldest.Value-1):long.Parse((string)row[0],System.Globalization.CultureInfo.InvariantCulture);
    if(cursor>newest.Value||cursor<oldest.Value-1){Issue(db,source,WebServerProtection.AuditGap,"warning","Security records were cleared or expired before review. Historical process evidence is incomplete; investigate Windows logging and retention.");cursor=Math.Max(0,oldest.Value-1);SaveWebAuditCursor(db,cursor);}
    var timer=Stopwatch.StartNew();int count=0;bool drained=false;
    using(var reader=new EventLogReader(new EventLogQuery("Security",PathType.LogName,WebServerProtection.EventFilter(cursor,newest.Value)))){
     reader.BatchSize=32;
     while(count<256&&timer.ElapsedMilliseconds<1200){if(stop.WaitOne(0))throw new OperationCanceledException();if(!authorized())return;
      using(var ev=reader.ReadEvent(TimeSpan.FromMilliseconds(250))){if(ev==null){drained=true;break;}if(!ev.RecordId.HasValue||ev.RecordId.Value<=cursor)throw new IOException("Unexpected Security event sequence.");
       if(ev.Id==1102)Issue(db,source,WebServerProtection.AuditGap,"warning","Windows Security log clear event observed; investigate historical evidence completeness.");
       else {XmlNamespaceManager ns;var doc=WebServerProtection.EventXml(ev,out ns);string parent=WebServerProtection.Field(doc,ns,"ParentProcessName"),child=WebServerProtection.Field(doc,ns,"NewProcessName");
        if(string.IsNullOrEmpty(parent)||string.IsNullOrEmpty(child)){Issue(db,source,WebServerProtection.AuditGap,"warning","Process creation audit record lacks parent or child image; historical classification incomplete.");}
        else if(WebServerProtection.SuspiciousChild(parent,child)){
         string pair=parent+" → "+child;string stamp=ev.TimeCreated.HasValue?ev.TimeCreated.Value.ToUniversalTime().ToString("o"):"Unknown UTC";
         string evidence=Id(pair+"|"+ev.RecordId.Value+"|"+stamp);
         Issue(db,pair,WebServerProtection.ProcessFinding,"warning","Security event 4688 #"+ev.RecordId.Value+" · "+stamp+" · Unexpected web-server child image. Host-wide signal; application association and malicious intent not proven.",evidence);
        }
       }
       cursor=ev.RecordId.Value;SaveWebAuditCursor(db,cursor);count++;
      }
     }
    }
    // Never skip an unread range after a bounded batch or log truncation.
    var currentOldest=WebServerProtection.Edge(false);var currentNewest=WebServerProtection.Edge(true);
    if(!currentOldest.HasValue||!currentNewest.HasValue||currentOldest.Value>cursor+1||currentNewest.Value<newest.Value)throw new IOException("Security log changed during reading; cursor retained.");
    if(!authorized())return;
    if(drained)SaveWebAuditCursor(db,newest.Value);
    if(drained)RecoverWebAuditPolicyGap(db,authorized,newest.Value);
    if(!authorized())return;
    Resolve(db,source,WebServerProtection.AuditCoverage);webAuditState=drained?"Available — reviewed through captured watermark":"Backlog — continuing review";
    if(!drained)nextWebAudit=now+1;
   }catch(OperationCanceledException){throw;}catch(Exception ex){webAuditState="Unavailable";Issue(db,source,WebServerProtection.AuditCoverage,"warning",ex.GetType().Name+": "+ex.Message);}
  }
  object WebProtectionSnapshot(Sqlite db,EndpointSettings c){
   long last=0;var row=db.Rows("SELECT value FROM endpoint_metadata WHERE name='web-script-last-check'").FirstOrDefault();if(row!=null)long.TryParse((string)row[0],out last);
   var historical=db.Rows("SELECT value FROM endpoint_metadata WHERE name='web-audit-recovered-policy-gap'").FirstOrDefault();
   return new {enabled=c.WebProtectionEnabled,paths=c.WebPaths,processAuditEnabled=c.WebProcessAuditEnabled,processAuditState=webAuditState,lastScriptCheckUtc=last>0?Telemetry.Utc(last):null,historicalAuditLimitation=historical==null?null:historical[0] as string,
    suspiciousScripts=Convert.ToInt64(db.Rows("SELECT COUNT(*) FROM findings WHERE active=1 AND change=?",WebServerProtection.Finding)[0][0]),
    inspectionIssues=Convert.ToInt64(db.Rows("SELECT COUNT(*) FROM findings WHERE active=1 AND change=?",WebServerProtection.Coverage)[0][0]),
    processFindings=Convert.ToInt64(db.Rows("SELECT COUNT(*) FROM findings WHERE active=1 AND change=?",WebServerProtection.ProcessFinding)[0][0]),
    auditIssues=Convert.ToInt64(db.Rows("SELECT COUNT(*) FROM findings WHERE active=1 AND change IN (?,?)",WebServerProtection.AuditCoverage,WebServerProtection.AuditGap)[0][0])};
  }
  string CachePolicy(EndpointSettings c){return Id("clean-verdict-v1|"+Config.Json().Serialize(c));}
  bool CacheEligible(EndpointSettings c,bool full,bool canary){return full&&!canary&&Program.ServiceMode&&c.Port==3310&&online;}
  CacheCandidate CachedCandidate(Sqlite db,EndpointSettings c,string path,bool full,bool canary){
   if(!CacheEligible(c,full,canary))return null;
   if(db.Rows("SELECT 1 FROM findings WHERE path=? COLLATE NOCASE AND active=1 LIMIT 1",path).Count!=0)return null;
   long now=History.Now();var row=db.Rows("SELECT hash,generation,stamp FROM clean_verdict_cache WHERE policy=? AND path=? AND verified>? AND verified<=?",CachePolicy(c),path,now-VerdictCacheMaxAge,now).FirstOrDefault();
   return row==null?null:new CacheCandidate{Hash=(string)row[0],Generation=(string)row[1],Stamp=row[2] as string};
  }
  void ForgetCached(Sqlite db,string p){db.Exec("DELETE FROM clean_verdict_cache WHERE path=? COLLATE NOCASE",p);}
  void SaveCached(Sqlite db,EndpointSettings c,string p,string hash,string generation,string stamp=null){
   if(string.IsNullOrEmpty(generation))return;
   db.Exec("INSERT OR REPLACE INTO clean_verdict_cache(policy,path,hash,generation,verified,stamp) VALUES(?,?,?,?,?,?)",CachePolicy(c),p,hash,generation,History.Now(),stamp??"");
  }
  bool RecordCached(Sqlite db,string p,Stopwatch timer,bool metadata=false){
   // This is a verified content match, not a new antivirus scan. Do not refresh
   // the cache age, last engine check, or clear any active security findings.
   baselineCached++;scanned++;if(metadata){metadataCachedChecks++;db.Exec("UPDATE files SET seen=? WHERE scope=? AND path=?",scanId,scope,p);}
   Activity(db,p,true,"Cached clean",timer,metadata?"NTFS identity, change stamp and live ClamAV generation match; no file content read":"SHA-256 and live ClamAV generation match prior clean verdict; no new signature inspection");return true;
  }
  bool MetadataEligible(Sqlite db,EndpointSettings c,string p,CacheCandidate candidate){
   return !WebServerProtection.Selected(c,p)&&c.MetadataFastCache&&candidate!=null&&!string.IsNullOrEmpty(candidate.Stamp)&&!journalGapDuringScan&&!baselineResumed&&!rescan&&usn.Covers(p)&&
    db.Rows("SELECT 1 FROM files WHERE scope=? AND path=? AND hash=?",scope,p,candidate.Hash).Count==1&&
    db.Rows("SELECT 1 FROM findings WHERE active=1 AND change IN ('USN journal coverage gap','USN journal unavailable','Real-time queue overflow') LIMIT 1").Count==0;
  }
  bool CheckFile(Sqlite db,EndpointSettings c,string p,WaitHandle stop,Func<bool> authorized,bool full,int retries=0){
   var lab=labCanary;if((lab!=null&&string.Equals(lab.Path,p,StringComparison.OrdinalIgnoreCase))||Path.GetFileName(p).StartsWith("LinkScope-Lab-Enrolled-",StringComparison.OrdinalIgnoreCase)){lock(labCanaryGate)return CheckFileCore(db,c,p,stop,authorized,full,retries);}
   return CheckFileCore(db,c,p,stop,authorized,full,retries);
  }
  bool CheckFileCore(Sqlite db,EndpointSettings c,string p,WaitHandle stop,Func<bool> authorized,bool full,int retries){
   WorkerPhase(full?"Baseline: inspecting a path":"Real-time: inspecting a path");
   var activityTimer=Stopwatch.StartNew();string stage="path metadata";
   if(!c.Paths.Any(x=>Under(p,x)))return true;if(Excluded(c,p)){if(full)excluded++;Activity(db,p,full,"Excluded",activityTimer,"Excluded by policy");return true;}bool canary=c.CanaryPaths.Contains(p,StringComparer.OrdinalIgnoreCase)||ActiveLabCanary(c,p)!=null;
   if(full&&BackgroundExcluded(c,p)){excluded++;Activity(db,p,true,"Excluded",activityTimer,"Background-only exclusion; real-time inspection remains enabled");return true;}
   if(full&&!canary&&usn.RetryWaiting(db,p)){errors++;return false;}
   try{bool fixedCanary=canary&&CanaryTemplates.ExpectedForPath(p)!=null;
    if(!fixedCanary)SafePath(p);var attr=File.GetAttributes(p);
    if(fixedCanary&&(attr&(FileAttributes.Directory|FileAttributes.ReparsePoint))!=0)throw new IOException("Invalid fixed canary file type.");if((attr&FileAttributes.Directory)!=0){if(full){foreach(var child in Directory.EnumerateFileSystemEntries(p)){if(pending.Count>=MaxEntries)throw new IOException("Traversal limit");PushBaselineChild(child);}Resolve(db,p,"File scan error");Resolve(db,p,"Protected path unavailable");}else RequestReconciliation(c,false);return true;}
    stage="open file for reading";using(var file=new FileStream(p,FileMode.Open,FileAccess.Read,FileShare.Read)){if(fixedCanary)EndpointResponse.VerifyHandle(file.SafeFileHandle,p);else UsnJournalService.VerifyScanPath(file.SafeFileHandle,p);if(file.Length>c.MaxFileMiB*1048576L){
     if(canary&&CanaryTemplates.ExpectedForPath(p)!=null)CanaryIssue(db,c,p,"Canary size exceeds scan limit and differs from the fixed original.","",stop,authorized);if(full)limited++;string sizeDetail=SizeLimitDetail(file.Length,c.MaxFileMiB);ScanIssue(db,c,p,"File scan limited",sizeDetail);Activity(db,p,full,"Limited",activityTimer,sizeDetail);return true;}
     var candidate=CachedCandidate(db,c,p,full,canary);
     string stamp=c.MetadataFastCache&&CacheEligible(c,full,canary)?UsnJournalService.FileChangeStamp(file.SafeFileHandle,p):null;
     string generation=CacheEligible(c,full,canary)?ClamUpdateWorker.CacheGeneration(stop,false):null;
     if(MetadataEligible(db,c,p,candidate)&&stamp!=null&&stamp==candidate.Stamp&&generation!=null&&generation==candidate.Generation&&authorized()&&stamp==UsnJournalService.FileChangeStamp(file.SafeFileHandle,p))return RecordCached(db,p,activityTimer,true);
     var budget=full&&!canary?new EndpointReadBudget(c.BackgroundReadMiB,stop):null;
     stage="read and hash file";WorkerPhase(full?"Baseline: reading and hashing":"Real-time: reading and hashing");byte[] b=new byte[65536];int n=0,r;while(n<b.Length&&(r=budget==null?file.Read(b,n,b.Length-n):budget.Read(file,b,n,b.Length-n))>0)n+=r;double entropy=Entropy(b,n);file.Position=0;string hash=FileHash(file,budget);file.Position=0;
     RecordFileIdentity(db,c,p,hash,entropy,n,canary,full,stop,authorized);
     if(WebServerProtection.Selected(c,p)&&authorized())RecordWebInspection(db,p,hash,WebServerProtection.Inspect(file,budget,stop));
     Resolve(db,p,"Protected path unavailable");if(!online){if(full)errors++;ScanIssue(db,c,p,"Engine scan incomplete","ClamAV offline; no signature verdict");Activity(db,p,full,"Unavailable",activityTimer,"ClamAV offline; no signature verdict");return false;}stage="ClamAV INSTREAM";WorkerPhase(full?"Baseline: awaiting antivirus verdict":"Real-time: awaiting antivirus verdict");
     if(CacheEligible(c,full,canary))generation=ClamUpdateWorker.CacheGeneration(stop,false);
     if(candidate!=null&&candidate.Hash==hash&&generation!=null&&candidate.Generation==generation&&authorized())return RecordCached(db,p,activityTimer);
     ForgetCached(db,p);
     string reply=Command(c.Port,"INSTREAM",file,stop,Program.ServiceMode&&c.Port==3310?(Action<TcpClient>)ClamUpdateWorker.VerifyScanServiceOwner:null,budget);
     string verifiedGeneration=CleanVerdict(reply)&&generation!=null&&generation==ClamUpdateWorker.CacheGeneration(stop,false)?generation:null;
     string verifiedStamp=verifiedGeneration!=null&&stamp!=null&&stamp==UsnJournalService.FileChangeStamp(file.SafeFileHandle,p)?stamp:null;
     stage="record scan verdict";bool recorded=RecordVerdict(db,c,p,hash,reply,full,canary,retries,activityTimer,stop,authorized,()=>file.Dispose());
     if(recorded&&CleanVerdict(reply)&&authorized())SaveCached(db,c,p,hash,verifiedGeneration,verifiedStamp);return recorded;
    }
   }catch(ScanReparseException ex){return RecordReparseBoundary(db,c,p,full,activityTimer,ex.Message);}catch(FileNotFoundException ex){if(Program.ServiceMode&&c.Port==3310)return CheckPrivileged(db,c,p,stop,authorized,full,canary,retries,activityTimer,ex.Message);Missing(db,c,p,canary,full,stop,authorized);Activity(db,p,full,"Missing",activityTimer,"File no longer present");}catch(DirectoryNotFoundException ex){if(Program.ServiceMode&&c.Port==3310)return CheckPrivileged(db,c,p,stop,authorized,full,canary,retries,activityTimer,ex.Message);Missing(db,c,p,canary,full,stop,authorized);Activity(db,p,full,"Missing",activityTimer,"Directory no longer present");}catch(OperationCanceledException){throw;}catch(Exception ex){if(ex is UnauthorizedAccessException&&(stage=="path metadata"||stage=="open file for reading"||stage=="read and hash file"))return CheckPrivileged(db,c,p,stop,authorized,full,canary,retries,activityTimer,ex.Message);if(stage=="open file for reading"&&LockedFile(ex)){if(SharedLogEligible(c,p,canary)&&online)return CheckSharedLog(db,c,p,stop,authorized,full,retries,activityTimer,ex.Message);RecordLocked(db,c,p,full,canary,retries,activityTimer,ex.Message);return false;}if(full)errors++;if(stage=="ClamAV INSTREAM"){MarkEngineTransportFailed(db,ex.Message);bool scheduled=!full&&!canary&&RetryLocked(c,p,retries);string transport=ex.Message+(scheduled?"; retry scheduled":"");ScanIssue(db,c,p,"Engine scan incomplete",transport);Activity(db,p,full,"Unavailable",activityTimer,transport);return false;}bool retry=!full&&!canary&&(LockedFile(ex)||ex is UnauthorizedAccessException||stage=="ClamAV INSTREAM")&&RetryLocked(c,p,retries);string detail=stage+": "+ex.GetType().Name+": "+ex.Message+(retry?"; retry scheduled":"");ScanIssue(db,c,p,"File scan error",detail);Activity(db,p,full,"Failed",activityTimer,detail);return false;}
   return true;
  }
  // Never use shared-read for canaries, explicit response executables or non-log paths.
  // Do not change sharing on the normal scanner. Read-only fallback does not bypass an OS lock.
  const int SharedLogMaxBytes=8*1048576;
  internal static bool SharedLogEligible(EndpointSettings c,string path,bool canary){
   return !canary&&Program.ServiceMode&&c.Port==3310&&string.Equals(Path.GetExtension(path),".log",StringComparison.OrdinalIgnoreCase)&&!c.ContainmentExecutables.Any(x=>string.Equals(x,path,StringComparison.OrdinalIgnoreCase));
  }
  internal static bool SharedSnapshotMatches(Stream source,byte[] snapshot,EndpointReadBudget budget,WaitHandle stop){
   if(source.Length!=snapshot.LongLength)return false;source.Position=0;var buffer=new byte[65536];int offset=0;
   while(offset<snapshot.Length){if(stop.WaitOne(0))throw new OperationCanceledException();int wanted=Math.Min(buffer.Length,snapshot.Length-offset);int n=budget==null?source.Read(buffer,0,wanted):budget.Read(source,buffer,0,wanted);if(n<=0)return false;for(int i=0;i<n;i++)if(buffer[i]!=snapshot[offset+i])return false;offset+=n;}
   return source.Length==snapshot.LongLength;
  }
  bool CheckSharedLog(Sqlite db,EndpointSettings c,string path,WaitHandle stop,Func<bool> authorized,bool full,int retries,Stopwatch timer,string originalError){
   // Only the existing scanner worker can enter here. One bounded in-memory copy;
   // no filesystem snapshot, privileged reader, write access or new permission.
   byte[] snapshot=null;string reply=null,hash=null;bool reported=false;
   try{
    if(stop.WaitOne(0))throw new OperationCanceledException();if(!authorized())return false;
    SafePath(path);WorkerPhase(full?"Baseline: shared log snapshot":"Real-time: shared log snapshot");
    ForgetCached(db,path);
    using(var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite,1)){
     string before=UsnJournalService.SharedReadStamp(file.SafeFileHandle,path);long length=file.Length;
     if(length<0||length>Math.Min((long)SharedLogMaxBytes,c.MaxFileMiB*1048576L))throw new IOException("Shared log exceeds bounded whole-file snapshot limit (8 MiB or configured limit); no signature verdict.");
     var budget=full?new EndpointReadBudget(c.BackgroundReadMiB,stop):null;
     snapshot=new byte[(int)length];int offset=0;
     while(offset<snapshot.Length){if(stop.WaitOne(0))throw new OperationCanceledException();if(!authorized())return false;int wanted=Math.Min(65536,snapshot.Length-offset);int n=budget==null?file.Read(snapshot,offset,wanted):budget.Read(file,snapshot,offset,wanted);if(n<=0)throw new IOException("Shared log shortened during capture.");offset+=n;}
     if(file.Length!=length||before!=UsnJournalService.SharedReadStamp(file.SafeFileHandle,path))throw new IOException("Shared log changed during capture.");
     hash=Hash(snapshot);using(var data=new MemoryStream(snapshot,false)){try{reply=Command(c.Port,"INSTREAM",data,stop,ClamUpdateWorker.VerifyScanServiceOwner);}catch(OperationCanceledException){throw;}catch(Exception ex){MarkEngineTransportFailed(db,ex.Message);ScanIssue(db,c,path,"Engine scan incomplete",ex.Message);throw;}}
     if(stop.WaitOne(0))throw new OperationCanceledException();if(!authorized())return false;
     // A positive finding is evidence for the captured bytes. Do not lose that
     // evidence if the live path subsequently changes; never act on it automatically.
     if(Malware(reply)){
      bool heuristic=reply.IndexOf("Heuristics.",StringComparison.OrdinalIgnoreCase)>=0;
      Issue(db,path,heuristic?"Heuristic signature finding":"Malware signature detected",heuristic?"warning":"critical","Shared log snapshot: "+reply+"; captured bytes only; strict stable-file verification required before response.",hash);
      Activity(db,path,full,heuristic?"Heuristic":"Infected",timer,"Shared log snapshot: "+reply);reported=true;
     }
     if(!CleanVerdict(reply))throw new IOException(reported?"Signature found in captured bytes; strict stable-file verification still required.":"No complete shared-log signature verdict: "+reply);
     if(before!=UsnJournalService.SharedReadStamp(file.SafeFileHandle,path)||!SharedSnapshotMatches(file,snapshot,budget,stop)||before!=UsnJournalService.SharedReadStamp(file.SafeFileHandle,path))throw new IOException("Shared log changed during inspection or byte-for-byte recheck; no current clean verdict.");
     SafePath(path);if(stop.WaitOne(0))throw new OperationCanceledException();if(!authorized())return false;
     // Record only a verified observation of the sampled bytes. Never clear a
     // malware/heuristic finding or save/reuse a clean-cache entry here.
     int sample=Math.Min(65536,snapshot.Length);RecordFileIdentity(db,c,path,hash,Entropy(snapshot,sample),sample,false,full,stop,authorized);
     Resolve(db,path,"Engine scan incomplete");Resolve(db,path,"Protected path unavailable");
     lastFileScan=History.Now();lastScannedPath=path;if(full)scanned++;else{realTimeChecked++;lastRealTimeScan=lastFileScan;}
     Activity(db,path,full,"Clean snapshot",timer,"Whole log bytes captured, scanned by authenticated ClamD and matched on re-read; "+length+" bytes; SHA-256 "+hash+"; no cache or response authority.");return true;
    }
   }catch(OperationCanceledException){throw;}catch(ScanReparseException ex){return RecordReparseBoundary(db,c,path,full,timer,ex.Message);}catch(Exception ex){RecordLocked(db,c,path,full,false,retries,timer,"Shared log inspection incomplete: "+ex.Message+"; original open: "+originalError);return false;}finally{if(snapshot!=null)Array.Clear(snapshot,0,snapshot.Length);}
  }
  internal static string SizeLimitDetail(long size,int cap){return "Configured file-size cap: "+cap+" MiB; file size: "+(size>0?size.ToString()+" bytes":"not reported by helper")+"; no signature verdict.";}
  internal static int EngineBackoffSeconds(int failures){return 15 << Math.Min(3,Math.Max(0,failures-1));}
  void MarkEngineTransportFailed(Sqlite db,string detail){
   online=false;lastEngine=History.Now();signatureFreshness="Unknown";engineNeedsScanProbe=true;
   engineFailures=Math.Min(4,engineFailures+1);nextEngineProbe=lastEngine+EngineBackoffSeconds(engineFailures);
   Issue(db,"ClamAV","Engine unavailable","warning","Signature transport failure; scans paused until a verified scan succeeds. "+detail);
   if(running)rescan=true;else nextScan=0;
  }
  // A verified reparse boundary is not a transient access error. Do not retry it
  // continuously, or report its target as clean. Future filesystem events or a
  // scheduled reconciliation inspect it again; explicit roots/canaries stay visible.
  bool RecordReparseBoundary(Sqlite db,EndpointSettings c,string path,bool full,Stopwatch timer,string detail){
   if(full)errors++;
   // No containment action based solely on a path type; the explicit canary scan warning remains active.
   string text="Reparse boundary: target not followed; no signature verdict. "+(detail??"");
   ScanIssue(db,c,path,"File scan error",text);
   Activity(db,path,full,"Reparse boundary",timer,text);
   return true; // terminal for this event only; coverage finding remains active
  }
  void RecordLocked(Sqlite db,EndpointSettings c,string path,bool full,bool canary,int retries,Stopwatch timer,string detail){
   // Do not weaken file sharing or claim a verdict on a changing file. Persist retry work even for baseline files.
   if(full)errors++;
   if(c.RealTime&&!canary){if(!usn.RetainWatcher(db,path,DownloadPriority(path)))Interlocked.Exchange(ref overflow,1);else usn.Defer(db,path);}
   ScanIssue(db,c,path,"File scan error","Deferred: file in use (sharing/lock violation); no signature verdict. "+detail);
   Activity(db,path,full,"Deferred",timer,"File in use; retry pending under scan policy");
  }
  internal static bool CanaryContentChanged(string expected,string actual){return expected!=null&&!Equals(expected,actual);}
  void RecordFileIdentity(Sqlite db,EndpointSettings c,string p,string hash,double entropy,int n,bool canary,bool full,WaitHandle stop,Func<bool> authorized){
   var old=db.Rows("SELECT hash,entropy FROM files WHERE scope=? AND path=?",scope,p).FirstOrDefault();if(old!=null&&!Equals(old[0],hash))Observe(p,EntropyTransition(n,entropy,Convert.ToDouble(old[1]),c));else if(old==null&&!full)Observe(p,false);
     db.Exec("INSERT OR REPLACE INTO files VALUES(?,?,?,?,?)",scope,p,hash,entropy,running?scanId:0);
     Resolve(db,p,"File scan limited");Resolve(db,p,"File scan error");
     if(canary){var baseline=db.Rows("SELECT hash FROM canaries WHERE path=?",p).FirstOrDefault();string expected=CanaryTemplates.ExpectedForPath(p);
      if(baseline==null&&ActiveLabCanary(c,p)!=null)throw new IOException("Temporary canary baseline missing; cannot establish detection evidence.");
      if(baseline==null){db.Exec("INSERT INTO canaries VALUES(?,?)",p,expected??hash);AppJournal.Event(LogLevel.Info,"Endpoint","canary-enroll","Recorded canary baseline: "+p);}
      else if(expected==null)expected=(string)baseline[0];
      if(CanaryContentChanged(expected,hash))CanaryIssue(db,c,p,"Canary content changed.",hash,stop,authorized);else if(expected!=null&&baseline!=null&&!Equals(baseline[0],expected))Issue(db,p,"Canary integrity violation","critical","Stored setup canary baseline differs from the original template.",hash);else {Resolve(db,p,"Canary integrity violation");Resolve(db,p,"Containment withheld");}}
  }
  bool RecordVerdict(Sqlite db,EndpointSettings c,string p,string hash,string reply,bool full,bool canary,int retries,Stopwatch activityTimer,WaitHandle stop,Func<bool> authorized,Action release){
   if(Malware(reply)||CleanVerdict(reply)){Resolve(db,p,"Engine scan incomplete");lastFileScan=History.Now();lastScannedPath=p;if(!full){realTimeChecked++;lastRealTimeScan=lastFileScan;}}if(Malware(reply)){bool quarantined=false;bool heuristic=reply.IndexOf("Heuristics.",StringComparison.OrdinalIgnoreCase)>=0;Issue(db,p,heuristic?"Heuristic signature finding":"Malware signature detected",heuristic?"warning":"critical",reply,hash);release();if(!heuristic&&c.Mode!="monitor"&&authorized()&&ResponseRetryAllowed(db,p,hash)&&c.ResponsePaths.Any(x=>Under(p,x))&&EndpointResponse.SafeScope(p)){try{string detail;lock(vaultGate)detail=EndpointResponse.Quarantine(store,c,p,hash,stop,authorized);Issue(db,p,"Malware quarantined","info",detail,hash);Resolve(db,p,"Malware quarantined");Resolve(db,p,"Quarantine withheld or failed");quarantined=true;ResolveQuarantinedOriginal(db,p,hash);}catch(Exception ex){Issue(db,p,"Quarantine withheld or failed","warning",ex.GetType().Name+": "+ex.Message,hash);}}Activity(db,p,full,quarantined?"Quarantined":heuristic?"Heuristic":"Infected",activityTimer,reply);}else if(CleanVerdict(reply)){Activity(db,p,full,"Clean",activityTimer,reply);Resolve(db,p,"Malware signature detected");Resolve(db,p,"Heuristic signature finding");Resolve(db,p,"Quarantine withheld or failed");Resolve(db,p,"Engine scan incomplete");}else {if(full)errors++;ScanIssue(db,c,p,"Engine scan incomplete",reply);Activity(db,p,full,"Failed",activityTimer,reply);if(!full&&!canary)RetryLocked(c,p,retries);return false;}if(full&&(Malware(reply)||CleanVerdict(reply)))scanned++;
   return true;
  }
  bool CheckPrivileged(Sqlite db,EndpointSettings c,string p,WaitHandle stop,Func<bool> authorized,bool full,bool canary,int retries,Stopwatch timer,string originalError){
   WorkerPhase(full?"Baseline: SYSTEM-assisted inspection":"Real-time: SYSTEM-assisted inspection");
   try{
    if(stop.WaitOne(0))throw new OperationCanceledException();
    if(!Program.ServiceMode||c.Port!=3310)throw new IOException("Restricted SYSTEM reader requires Windows service mode and standard ClamD port 3310");
    if(!online){if(full)errors++;ScanIssue(db,c,p,"Engine scan incomplete","ClamAV offline; restricted scan deferred");Activity(db,p,full,"Unavailable",timer,"ClamAV offline; restricted scan deferred");return false;}
    var candidate=CachedCandidate(db,c,p,full,canary);
    bool cacheEligible=CacheEligible(c,full,canary);
    var result=cacheEligible?UsnJournalService.FetchBaselineScan(p,candidate==null?"":candidate.Hash,candidate==null?"":candidate.Generation,MetadataEligible(db,c,p,candidate)?candidate.Stamp:""):UsnJournalService.FetchScan(p,full);
    if(result.Kind=="Missing"){Missing(db,c,p,canary,full,stop,authorized);Activity(db,p,full,"Missing",timer,"Privileged reader: path no longer present");return true;}
    if(result.Kind=="Directory"){
     if(canary)throw new IOException("Expected canary file, found directory");
     if(full){foreach(var child in result.Children){if(pending.Count>=MaxEntries)throw new IOException("Traversal limit");PushBaselineChild(child);}if(!string.IsNullOrEmpty(result.Detail))throw new IOException(result.Detail);Resolve(db,p,"File scan error");Resolve(db,p,"Protected path unavailable");}
     else RequestReconciliation(c,false);return true;
    }
    if(result.Kind=="Limited"){if(canary&&CanaryTemplates.ExpectedForPath(p)!=null)CanaryIssue(db,c,p,"Canary size exceeds scan limit and differs from the fixed original.","",stop,authorized);if(full)limited++;string sizeDetail=SizeLimitDetail(result.Size,c.MaxFileMiB);ScanIssue(db,c,p,"File scan limited",sizeDetail);Activity(db,p,full,"Limited",timer,sizeDetail);return true;}
    if(result.Kind=="Reparse"){return RecordReparseBoundary(db,c,p,full,timer,result.Detail);}
    if(result.Kind=="Locked"){RecordLocked(db,c,p,full,canary,retries,timer,result.Detail??"Restricted reader sharing violation");return false;}
    if(result.Kind!="File")throw new IOException(result.Detail??"Privileged reader failed");
    if(WebServerProtection.Selected(c,p)&&authorized())RecordWebInspection(db,p,result.Hash,result.WebInspection);
    if(result.Cached){
     if(candidate==null||!authorized()||result.Hash!=candidate.Hash||result.Generation!=candidate.Generation)throw new IOException("Unverified privileged cached verdict");
     if(result.MetadataCached){if(!MetadataEligible(db,c,p,candidate)||candidate.Stamp!=result.Stamp)throw new IOException("Unverified NTFS cached verdict");return RecordCached(db,p,timer,true);}
     RecordFileIdentity(db,c,p,result.Hash,result.Entropy,result.Sample,canary,full,stop,authorized);
     Resolve(db,p,"Protected path unavailable");return RecordCached(db,p,timer);
    }
    ForgetCached(db,p);
    RecordFileIdentity(db,c,p,result.Hash,result.Entropy,result.Sample,canary,full,stop,authorized);
    Resolve(db,p,"Protected path unavailable");
    if(Malware(result.Verdict)||CleanVerdict(result.Verdict))privilegedFileChecks++;
    if(result.Verdict.StartsWith("Privileged ClamAV scan error:",StringComparison.Ordinal))MarkEngineTransportFailed(db,result.Verdict);
    bool recorded=RecordVerdict(db,c,p,result.Hash,result.Verdict,full,canary,retries,timer,stop,authorized,()=>{});
    if(cacheEligible&&recorded&&CleanVerdict(result.Verdict)&&authorized())SaveCached(db,c,p,result.Hash,result.Generation,result.Stamp);return recorded;
   }catch(OperationCanceledException){throw;}catch(Exception ex){if(full)errors++;bool retry=!full&&!canary&&RetryLocked(c,p,retries);string detail="Restricted SYSTEM scan: "+ex.GetType().Name+": "+ex.Message+"; original access: "+originalError+(retry?"; retry scheduled":"");ScanIssue(db,c,p,"File scan error",detail);Activity(db,p,full,"Failed",timer,detail);return false;}
  }
  void Missing(Sqlite db,EndpointSettings c,string p,bool canary,bool full,WaitHandle stop,Func<bool> authorized){ForgetCached(db,p);Resolve(db,p,WebServerProtection.Finding);Resolve(db,p,WebServerProtection.Coverage);if(canary)CanaryIssue(db,c,p,"Canary missing.","",stop,authorized);if(RoutineCoverage(c,p,"File scan error")){Resolve(db,p,"File scan limited");Resolve(db,p,"File scan error");Resolve(db,p,"Engine scan incomplete");}if(full&&c.Paths.Contains(p,StringComparer.OrdinalIgnoreCase)){errors++;Issue(db,p,"Protected path unavailable","warning","Configured path missing; scan incomplete.");}else if(db.Rows("SELECT path FROM files WHERE scope=? AND path=?",scope,p).Count>0){Observe(p,false);db.Exec("DELETE FROM files WHERE scope=? AND path=?",scope,p);Resolve(db,p,"File scan limited");Resolve(db,p,"File scan error");Resolve(db,p,"Engine scan incomplete");Resolve(db,p,"Malware signature detected");Resolve(db,p,"Heuristic signature finding");Resolve(db,p,"Quarantine withheld or failed");}}
  // Only verified absence of the original closes its malware finding. A vault purge
  // never clears an unrelated, recurrent, inaccessible or still-present threat.
  static bool ConfirmAbsent(string path){try{File.GetAttributes(path);return false;}catch(FileNotFoundException){return true;}catch(DirectoryNotFoundException){return true;}catch(Exception){return false;}}
  void ResolveQuarantinedOriginal(Sqlite db,string path,string hash){
   if(!db.Rows("SELECT 1 FROM findings WHERE path=? COLLATE NOCASE AND hash=? AND active=1 AND change IN ('Malware signature detected','Quarantine withheld or failed') LIMIT 1",path,hash).Any()||!ConfirmAbsent(path))return;
   db.Exec("BEGIN IMMEDIATE");try{
    foreach(var change in new[]{"Malware signature detected","Quarantine withheld or failed",WebServerProtection.Finding}){
     string id=Id(path+"|"+change);
     db.Exec("INSERT INTO endpoint_outbox(utc,id,path,change,severity,detail,hash,active) SELECT ?,id,path,change,severity,detail,hash,0 FROM findings WHERE id=? AND hash=? AND active=1",History.Now(),id,hash);
     db.Exec("UPDATE findings SET active=0 WHERE id=? AND hash=? AND active=1",id,hash);
    }
    db.Exec("COMMIT");
   }catch{db.Exec("ROLLBACK");throw;}
  }
  static bool EvidenceId(string id){return id!=null&&id.Length==32&&Regex.IsMatch(id,"^[a-f0-9]{32}$",RegexOptions.CultureInvariant);}
  Dictionary<string,object> EvidenceMetadata(string vault,string id){
   if(!EvidenceId(id))throw new IOException("Invalid evidence identifier.");
   string meta=Path.Combine(vault,id+".json");SafePath(meta);
   using(var f=new FileStream(meta,FileMode.Open,FileAccess.Read,FileShare.Read)){
    EndpointResponse.VerifyHandle(f.SafeFileHandle,meta);if(f.Length>32768)throw new IOException("Oversized evidence metadata.");
    using(var reader=new StreamReader(f,Encoding.UTF8)){
     var row=Config.Json().Deserialize<Dictionary<string,object>>(reader.ReadToEnd());
     if(row==null||!row.ContainsKey("id")||!row.ContainsKey("path")||!row.ContainsKey("sha256")||!row.ContainsKey("state")||!row.ContainsKey("utc")||!Equals(row["id"],id)||(Convert.ToString(row["sha256"]).Length!=64||!Regex.IsMatch(Convert.ToString(row["sha256"]),"^[a-f0-9]{64}$",RegexOptions.CultureInvariant)))throw new IOException("Invalid evidence metadata.");
     return row;
    }
   }
  }
  // Enumerate sealed payloads, not the historical metadata files. Deleted items do
  // not consume the live inventory limit. Incomplete deletions remain retryable.
  object[] QuarantineInventory(Sqlite db){
   lock(vaultGate){string vault=Path.Combine(store,"quarantine");if(ConfirmAbsent(vault))return new object[0];SafePath(vault);
    var files=Directory.EnumerateFiles(vault,"*.sealed").Take(1001).ToArray();if(files.Length>1000)throw new IOException("Quarantine inventory exceeds supported vault quota.");
    var ids=new HashSet<string>(files.Select(f=>Path.GetFileNameWithoutExtension(f)),StringComparer.Ordinal);
    foreach(var r in db.Rows("SELECT id FROM quarantine_deletions WHERE completed IS NULL LIMIT 1001"))ids.Add((string)r[0]);
    var list=new List<Dictionary<string,object>>();
    foreach(var id in ids){try{
     var row=EvidenceMetadata(vault,id);string sealedPath=Path.Combine(vault,id+".sealed");
     var journal=db.Rows("SELECT completed FROM quarantine_deletions WHERE id=?",id).FirstOrDefault();
     bool pending=journal!=null&&journal[0]==null;bool present=!ConfirmAbsent(sealedPath);long size=0;
     if(present){SafePath(sealedPath);using(var f=new FileStream(sealedPath,FileMode.Open,FileAccess.Read,FileShare.Read)){EndpointResponse.VerifyHandle(f.SafeFileHandle,sealedPath);size=f.Length;}}
     string originalState=Convert.ToString(row["state"]);
     row["state"]=pending?"purge_pending":journal!=null?"unexpected_payload":originalState;
     row["payloadPresent"]=present;row["sealedBytes"]=size;
     row["deletable"]=originalState=="quarantined"&&(journal==null?present:pending);
     list.Add(row);
    }catch(Exception){list.Add(new Dictionary<string,object>{{"id",EvidenceId(id)?id:"Invalid identifier"},{"state","unavailable"},{"deletable",false}});}}
    return list.OrderByDescending(r=>r.ContainsKey("utc")?Convert.ToString(r["utc"]):"").Cast<object>().ToArray();
   }
  }
  static object[] DeletionHistory(Sqlite db){return db.Rows("SELECT id,path,hash,actor,requested,completed FROM quarantine_deletions WHERE completed IS NOT NULL ORDER BY completed DESC, id LIMIT 100").Select(r=>new {id=r[0],path=r[1],sha256=r[2],actor=r[3],requestedUtc=Telemetry.Utc(Convert.ToInt64(r[4])),deletedUtc=Telemetry.Utc(Convert.ToInt64(r[5])),state="deleted"}).Cast<object>().ToArray();}
  internal object RunEnrolledCanaryProbe(EndpointSettings c,string directory,string run,WaitHandle stop,Action wake,Func<bool> authorized,Action<string,string,string> add){
   string path=null,identity=null,expected=null,changed=null,seq=null,record=null,eventUtc=null,image=null,mask=null,source=null,incidentBaseline=null,securityBaseline=null,modifiedUtc=null,detail=null;int pid=0,expectedPid=0;string expectedImage=null;bool clean=false,detected=false,attributed=false,registered=false,baselineRemoved=false,refusal=false;byte[] bytes=CanaryTemplates.Bytes("Reference_Notes.txt");
   try{
    if(!c.ProcessCorrelation||stop.WaitOne(0)||!authorized())throw new IOException("Live correlation and current saved policy are required.");
    path=EndpointResponse.ProtectionLabPath(c,directory,"LinkScope-Lab-Enrolled-"+run+".txt");expected=Hash(bytes);var modified=(byte[])bytes.Clone();modified[0]^=1;changed=Hash(modified);
    using(var self=Process.GetCurrentProcess()){expectedPid=self.Id;expectedImage=self.MainModule.FileName;}
    long before;using(var db=Open()){before=Convert.ToInt64(db.Rows("SELECT COALESCE(MAX(seq),0) FROM incidents")[0][0]);}incidentBaseline=before.ToString(System.Globalization.CultureInfo.InvariantCulture);
    long eventBefore=EndpointResponse.SecurityWatermark();securityBaseline=eventBefore.ToString(System.Globalization.CultureInfo.InvariantCulture);
    lock(labCanaryGate){
     if(labCanary!=null||!authorized())throw new IOException("Another test canary is active or policy changed.");
     EndpointResponse.CreateOwnedLabSample(path,bytes,out identity);
     using(var db=Open()){db.Exec("INSERT INTO canaries(path,hash) VALUES(?,?)",path,expected);}registered=true;
     var enrollment=new LabCanaryEnrollment{Path=path,Expected=expected,Policy=Config.Json().Serialize(c),Watermark=eventBefore};modifiedUtc=DateTime.UtcNow.ToString("o");labCanary=enrollment;
     if(!authorized())throw new OperationCanceledException();EndpointResponse.ChangeEnrolledLabCanary(path,identity,bytes);
    }
    wake();var wait=Stopwatch.StartNew();while(wait.ElapsedMilliseconds<12000&&!stop.WaitOne(0)&&authorized()){
     using(var db=new Sqlite(dbPath,true)){
      var row=db.Rows("SELECT seq,detail FROM incidents WHERE seq>? AND path=? COLLATE NOCASE AND hash=? AND change='Canary integrity violation' ORDER BY seq",before,path,changed).FirstOrDefault();
      if(row!=null){seq=Convert.ToString(row[0]);detail=Convert.ToString(row[1]);source=detail.Contains("source=watcher; expected="+expected)?"watcher":"other scanner";detected=detail.Contains("Controlled enrolled-canary validation;")&&detail.Contains("expected="+expected+"]");
       var match=Regex.Match(detail,@"Windows 4663: (.+?) PID ([0-9]+) record ([0-9]+) UTC (\S+) mask (0x[0-9A-Fa-f]+) \(correlation, not proof\)\.");long auditRecord;DateTime auditUtc;long access;
       if(detected&&match.Success&&int.TryParse(match.Groups[2].Value,out pid)&&pid==expectedPid&&string.Equals(match.Groups[1].Value,expectedImage,StringComparison.OrdinalIgnoreCase)&&long.TryParse(match.Groups[3].Value,out auditRecord)&&auditRecord>eventBefore&&DateTime.TryParse(match.Groups[4].Value,null,System.Globalization.DateTimeStyles.RoundtripKind,out auditUtc)&&auditUtc.ToUniversalTime()>=DateTime.Parse(modifiedUtc,null,System.Globalization.DateTimeStyles.RoundtripKind).ToUniversalTime()&&auditUtc.ToUniversalTime()<=DateTime.UtcNow.AddSeconds(2)&&long.TryParse(match.Groups[5].Value.Substring(2),System.Globalization.NumberStyles.HexNumber,System.Globalization.CultureInfo.InvariantCulture,out access)&&(access&0x6)!=0){record=match.Groups[3].Value;eventUtc=auditUtc.ToUniversalTime().ToString("o");image=match.Groups[1].Value;mask=match.Groups[5].Value;attributed=true;refusal=!EndpointResponse.EligibleContainmentTarget(c,new EndpointWriter{Pid=pid,Image=image,Record=auditRecord,Utc=auditUtc,Mask=access});}
       break;
      }
     }stop.WaitOne(200);
    }
   }catch(Exception ex){add("Enrolled canary exercise detail","Review",ex.GetType().Name+": "+ex.Message);}
   finally{
    lock(labCanaryGate){
     if(path!=null&&labCanary!=null&&string.Equals(labCanary.Path,path,StringComparison.OrdinalIgnoreCase))labCanary=null;
     try{if(path!=null&&identity!=null){if(!ConfirmAbsent(path))EndpointResponse.CleanupEnrolledLabCanary(path,identity,expected,changed,bytes.Length);clean=ConfirmAbsent(path);}}catch(Exception ex){add("Enrolled canary cleanup detail","Review",ex.GetType().Name+": "+ex.Message+"; inspect "+path);}
     if(registered)try{using(var db=Open()){db.Exec("DELETE FROM canaries WHERE path=? AND hash=?",path,expected);baselineRemoved=db.Rows("SELECT 1 FROM canaries WHERE path=?",path).Count==0;if(clean&&baselineRemoved){Resolve(db,path,"Canary integrity violation");Resolve(db,path,"Containment withheld");}}}catch(Exception ex){clean=false;add("Enrolled canary enrollment cleanup detail","Review",ex.GetType().Name+": "+ex.Message);}
    }
   }
   add("Live enrolled-canary watcher detection",detected&&source=="watcher"?"Pass":"Review",detected?"Actual detector incident "+seq+"; source "+source+"; "+path+"; expected "+expected+"; changed "+changed:"No matching new normal detector incident; no watcher verdict.");
   add("Controlled production incident attribution",attributed?"Pass":"Review",attributed?"Actual canary incident "+seq+" carries matching Security 4663 record "+record+"; PID "+pid+"; image "+image+"; UTC "+eventUtc+"; mask "+mask+". Controlled service writer; not a malicious-process attribution test.":"No matching fresh unambiguous writer evidence in the normal detector incident.");
   add("Live containment target refusal",attributed&&refusal?"Pass":"Review",attributed&&refusal?"The shared production eligibility predicate rejected the actual audited service writer PID "+pid+". No termination API was called; this verifies refusal only.":"Live target refusal could not be established from matching incident evidence.");
   clean=clean&&registered&&baselineRemoved;
   add("Enrolled canary cleanup",clean?"Pass":"Review",clean?"Owned test file absent and temporary baseline removed; original enrolled canaries unchanged.":"Cleanup unverified; inspect "+path);
   return new {path,expected,changed,seq,source,incidentBaseline,securityBaseline,modifiedUtc,record,eventUtc,pid,image,mask,expectedPid,expectedImage,detected,attributed,clean,registered,baselineRemoved,refusal};
  }
  // Explicit lab-only disk comparison plus a real normal-scanner EICAR quarantine exercise.
  // Lab observations are persisted separately from active production canary findings.
  internal object RunProtectionLab(EndpointSettings c,string directory,WaitHandle stop,Action wake,Func<bool> authorized){
   var rows=new List<object>();var timer=Stopwatch.StartNew();Action<string,string,string> add=(name,state,evidence)=>{rows.Add(new {name=name,state=state,evidence=evidence,durationMs=timer.ElapsedMilliseconds});timer.Restart();};
   object enrolled=null,termination=null;string run=Guid.NewGuid().ToString("N"),canaryPath=null,eicarPath=null,expected=null,actual=null,identity=null,eicarHash=null,receipt=null,verdict=null,canaryIncident=null,malwareIncident=null,quarantineIncident=null,receiptUtcText=null,incidentWatermark=null;bool canaryClean=false,eicarClean=false,quarantineVerified=false,scopeVerified=false,sampleCreated=false;var started=DateTime.UtcNow;var pins=new List<SafeFileHandle>();
   try{
    pins=EndpointResponse.PinProtectionLab(c,directory);EndpointResponse.CheckResponseEngine(c,stop);scopeVerified=true;add("Lab scope and engine","Pass",directory+"; saved leaf response path; authenticated ClamD peer.");
    if(stop.WaitOne(0)||!authorized())throw new OperationCanceledException();
    try{
     canaryPath=EndpointResponse.ProtectionLabPath(c,directory,"LinkScope-Lab-Canary-"+run+".txt");var bytes=CanaryTemplates.Bytes("Reference_Notes.txt");expected=Hash(bytes);string before;EndpointResponse.DisposableCanary(canaryPath,bytes,out before,out actual);
     var modified=(byte[])bytes.Clone();modified[0]^=1;if(before!=expected||!CanaryContentChanged(expected,actual)||actual!=Hash(modified))throw new IOException("On-disk baseline or change comparison did not match the test requirements.");
     using(var db=Open()){string id=Id(canaryPath+"|Lab canary comparison");db.Exec("INSERT INTO incidents(utc,id,path,change,severity,detail,hash) VALUES(?,?,?,?,?,?,?)",History.Now(),id,canaryPath,"Lab canary comparison","info","Controlled disposable file; shared production hash comparator detected a real change. Not watcher/enrollment validation. Expected SHA-256 "+expected,actual);var row=db.Rows("SELECT seq FROM incidents WHERE id=? AND path=? AND hash=?",id,canaryPath,actual).Single();canaryIncident=Convert.ToString(row[0]);}
     add("Disposable canary comparison","Pass","Real disk hash change; lab incident "+canaryIncident+"; expected "+expected+"; actual "+actual+"; "+canaryPath+". Not an enrolled-canary watcher test.");
    }catch(Exception ex){add("Disposable canary comparison","Review",ex.GetType().Name+": "+ex.Message);}
    canaryClean=canaryPath!=null&&actual!=null&&ConfirmAbsent(canaryPath);add("Canary cleanup",canaryClean?"Pass":"Review",canaryClean?"Disposable file is absent after delete-on-close.":"No verified cleanup; inspect exact test path: "+canaryPath);
    enrolled=RunEnrolledCanaryProbe(c,directory,run,stop,wake,authorized,add);
    if(!stop.WaitOne(0)&&authorized())termination=EndpointResponse.OwnedChildTerminationProbe(stop,authorized,add);
    try{
     if(stop.WaitOne(0)||!authorized())throw new OperationCanceledException();
     eicarPath=EndpointResponse.ProtectionLabPath(c,directory,"LinkScope-Lab-EICAR-"+run+".com");byte[] sample=Encoding.ASCII.GetBytes(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");eicarHash=Hash(sample);
     long watermark;using(var db=Open()){watermark=Convert.ToInt64(db.Rows("SELECT COALESCE(MAX(seq),0) FROM incidents")[0][0]);incidentWatermark=watermark.ToString(System.Globalization.CultureInfo.InvariantCulture);}
     if(!authorized())throw new OperationCanceledException();EndpointResponse.CreateEicarLabSample(eicarPath,sample,out identity);sampleCreated=true;add("EICAR sample creation","Pass",eicarPath+"; SHA-256 "+eicarHash+"; waiting for the normal scanner (real-time or baseline).");wake();
     var wait=Stopwatch.StartNew();while(wait.ElapsedMilliseconds<15000&&!stop.WaitOne(0)&&authorized()){
      using(var db=new Sqlite(dbPath,true)){
       var evidence=db.Rows("SELECT seq,change,detail FROM incidents WHERE seq>? AND path=? COLLATE NOCASE AND hash=? AND change IN ('Malware signature detected','Malware quarantined') ORDER BY seq",watermark,eicarPath,eicarHash);
       var detection=evidence.FirstOrDefault(x=>Equals(x[1],"Malware signature detected")&&Malware(Convert.ToString(x[2]))&&Convert.ToString(x[2]).IndexOf("EICAR",StringComparison.OrdinalIgnoreCase)>=0&&Convert.ToString(x[2]).IndexOf("Heuristics.",StringComparison.OrdinalIgnoreCase)<0);
       if(detection!=null){malwareIncident=Convert.ToString(detection[0]);verdict=Convert.ToString(detection[2]);var q=evidence.FirstOrDefault(x=>Equals(x[1],"Malware quarantined")&&Convert.ToInt64(x[0])>Convert.ToInt64(detection[0]));if(q!=null){var match=Regex.Match(Convert.ToString(q[2]),@"Sealed evidence ID ([a-f0-9]{32})");if(match.Success&&ConfirmAbsent(eicarPath)&&Monitor.TryEnter(vaultGate,100)){try{
        string vault=Path.Combine(store,"quarantine"),id=match.Groups[1].Value;var meta=EvidenceMetadata(vault,id);if(!Equals(meta["state"],"quarantined")||!string.Equals(Convert.ToString(meta["path"]),eicarPath,StringComparison.OrdinalIgnoreCase)||!Equals(meta["sha256"],eicarHash))throw new IOException("Quarantine receipt does not match the sample.");
        DateTime receiptUtc;if(!DateTime.TryParse(Convert.ToString(meta["utc"]),null,System.Globalization.DateTimeStyles.RoundtripKind,out receiptUtc)||receiptUtc.ToUniversalTime()<started||receiptUtc.ToUniversalTime()>DateTime.UtcNow.AddSeconds(2))throw new IOException("Quarantine receipt timestamp invalid.");
        string payload=Path.Combine(vault,id+".sealed");SafePath(payload);using(var f=new FileStream(payload,FileMode.Open,FileAccess.Read,FileShare.Read)){EndpointResponse.VerifyHandle(f.SafeFileHandle,payload);if(f.Length<1||f.Length>16384)throw new IOException("Unexpected sealed sample size.");byte[] encrypted=new byte[(int)f.Length];int count=0,n;while(count<encrypted.Length&&(n=f.Read(encrypted,count,encrypted.Length-count))>0)count+=n;if(count!=encrypted.Length)throw new IOException("Incomplete sealed sample read.");byte[] plain=ProtectedData.Unprotect(encrypted,null,DataProtectionScope.LocalMachine);try{if(plain.Length!=68||Hash(plain)!=eicarHash)throw new IOException("Sealed payload hash mismatch.");}finally{Array.Clear(plain,0,plain.Length);}}
        receipt=id;receiptUtcText=receiptUtc.ToUniversalTime().ToString("o");quarantineIncident=Convert.ToString(q[0]);quarantineVerified=true;
       }finally{Monitor.Exit(vaultGate);}}}}
      }
      if(quarantineVerified)break;stop.WaitOne(250);
     }
     add("EICAR signature detection",malwareIncident!=null?"Pass":"Review",malwareIncident!=null?"Actual scanner incident "+malwareIncident+"; "+verdict+"; SHA-256 "+eicarHash:"No matching new LinkScope EICAR verdict within bounded observation. Another antivirus may intercept first; do not disable it.");
     add("EICAR sealed quarantine",quarantineVerified?"Pass":"Review",quarantineVerified?"Actual quarantine incident "+quarantineIncident+"; receipt "+receipt+"; decrypted in memory and SHA-256 verified; original absent. Sealed sample retained for review.":"No matching verified sealed receipt and original removal within the observation window.");
    }catch(Exception ex){add("EICAR execution","Review",ex.GetType().Name+": "+ex.Message);}
    finally{if(eicarPath!=null){try{if(!ConfirmAbsent(eicarPath))EndpointResponse.CleanupEicarLabSample(eicarPath,identity,eicarHash);eicarClean=identity!=null&&ConfirmAbsent(eicarPath);}catch(Exception ex){eicarClean=identity!=null&&ConfirmAbsent(eicarPath);if(!eicarClean)add("EICAR cleanup detail","Review",ex.GetType().Name+": "+ex.Message+"; inspect "+eicarPath);}}add("EICAR original cleanup",eicarClean?"Pass":"Review",eicarClean?(quarantineVerified?"Original absent after verified quarantine.":"Original absent; absence alone is not quarantine evidence."):"No verified original cleanup; inspect "+eicarPath);}
   }catch(Exception ex){add("Protection lab prerequisite","Review",ex.GetType().Name+": "+ex.Message);}
   finally{foreach(var pin in pins)pin.Dispose();if(canaryPath!=null||eicarPath!=null)wake();}
   return new {utc=DateTime.UtcNow.ToString("o"),runId=run,directory=directory,startedUtc=started.ToString("o"),checks=rows,proof=new {scopeVerified,sampleCreated,incidentWatermark,receiptUtc=receiptUtcText,canaryPath,expected,actual,canaryIncident,canaryClean,eicarPath,eicarHash,malwareIncident,verdict,quarantineIncident,receipt,quarantineVerified,eicarClean,enrolled,termination}};
  }
  internal object QuarantineStatus(){
   if(!Monitor.TryEnter(vaultGate,500))throw new HttpError(409,"The quarantine vault is busy. Retry shortly.");
   try{using(var db=Open()){var items=QuarantineInventory(db);return new {items=items,total=items.Length,deletedCount=Convert.ToInt64(db.Rows("SELECT COUNT(*) FROM quarantine_deletions WHERE completed IS NOT NULL")[0][0]),recentDeletions=DeletionHistory(db)};}}finally{Monitor.Exit(vaultGate);}
  }
  internal object DeleteQuarantine(string[] ids,string actor,string ip){
   if(ids==null||ids.Length<1||ids.Length>100||ids.Any(id=>!EvidenceId(id))||ids.Distinct(StringComparer.Ordinal).Count()!=ids.Length)throw new HttpError(400,"Select 1–100 distinct valid quarantine evidence IDs.");
   if(!Monitor.TryEnter(vaultGate,500))throw new HttpError(409,"The quarantine vault is busy. Retry shortly.");
   try{using(var db=Open()){
    string vault=Path.Combine(store,"quarantine");SafePath(vault);var results=new List<object>();int deleted=0;
    foreach(string id in ids){try{
     var row=EvidenceMetadata(vault,id);string path=Convert.ToString(row["path"]),hash=Convert.ToString(row["sha256"]),sealedPath=Path.Combine(vault,id+".sealed");
     if(!Equals(row["state"],"quarantined"))throw new IOException("Only completed quarantines may be deleted. Review incomplete evidence locally.");
     var prior=db.Rows("SELECT path,hash,completed FROM quarantine_deletions WHERE id=?",id).FirstOrDefault();
     if(prior!=null&&(!Equals(prior[0],path)||!Equals(prior[1],hash)))throw new IOException("Deletion journal does not match metadata.");
     if(prior!=null&&prior[2]!=null){if(!ConfirmAbsent(sealedPath))throw new IOException("Unexpected sealed payload after completed deletion.");results.Add(new {id=id,ok=true,detail="Already deleted"});deleted++;continue;}
     // Record intent before removal. If interrupted, explicit retry can finalize the same ID.
     if(prior==null&&ConfirmAbsent(sealedPath))throw new IOException("Sealed payload is missing; no verified deletion recorded.");
     db.Exec("INSERT OR IGNORE INTO quarantine_deletions(id,path,hash,actor,requested,completed) VALUES(?,?,?,?,?,NULL)",id,path,hash,actor,History.Now());
     if(!ConfirmAbsent(sealedPath))EndpointResponse.DeleteSealedPayload(sealedPath);
     if(!ConfirmAbsent(sealedPath))throw new IOException("Cannot confirm removal of sealed payload.");
     long now=History.Now();string eventId=Id("Quarantine deletion|"+id);string detail="Permanently removed sealed quarantine payload "+id+" by "+actor+". Original detection and SHA-256 retained.";
     db.Exec("BEGIN IMMEDIATE");try{
      db.Exec("UPDATE quarantine_deletions SET completed=? WHERE id=? AND completed IS NULL",now,id);
      db.Exec("INSERT INTO incidents(utc,id,path,change,severity,detail,hash) VALUES(?,?,?,?,?,?,?)",now,eventId,path,"Quarantine payload deleted","info",detail,hash);
      db.Exec("INSERT INTO endpoint_outbox(utc,id,path,change,severity,detail,hash,active) VALUES(?,?,?,?,?,?,?,1)",now,eventId,path,"Quarantine payload deleted","info",detail,hash);
      db.Exec("INSERT INTO endpoint_outbox(utc,id,path,change,severity,detail,hash,active) VALUES(?,?,?,?,?,?,?,0)",now,eventId,path,"Quarantine payload deleted","info",detail,hash);
      db.Exec("COMMIT");
     }catch{db.Exec("ROLLBACK");throw;}
     deleted++;results.Add(new {id=id,ok=true,detail="Deleted"});
     try{UserAudit.Write(actor,ip,"Permanently deleted quarantine evidence "+id+"; SHA-256 "+hash,200,"Success");AppJournal.Event(LogLevel.Info,"Endpoint","quarantine-delete",detail,ip);}catch(Exception ex){AppJournal.Fault("Endpoint","quarantine-delete-audit",ex);}
    }catch(Exception ex){results.Add(new {id=id,ok=false,detail=ex is IOException?ex.Message:"Deletion not completed; check application logs and retry."});AppJournal.Fault("Endpoint","quarantine-delete",ex);try{UserAudit.Write(actor,ip,"Quarantine deletion not completed: "+id,409,"Error");}catch(Exception audit){AppJournal.Fault("Endpoint","audit",audit);}}}
    return new {deleted=deleted,failed=ids.Length-deleted,results=results.ToArray()};
   }}finally{Monitor.Exit(vaultGate);}
  }
  string Correlate(EndpointSettings c,string p){EndpointWriter writer;return Correlate(c,p,out writer);}
  string Correlate(EndpointSettings c,string p,out EndpointWriter writer,bool publish=true,long minRecord=0){writer=null;if(!c.ProcessCorrelation)return "Process attribution disabled.";try{writer=EndpointResponse.FindIncidentWriter(p,minRecord);if(publish)auditStatus=writer==null?"No matching unambiguous audit evidence":"Matching Windows audit event";return writer==null?"No matching unambiguous write audit event.":"Windows 4663: "+writer.Image+" PID "+writer.Pid+" record "+writer.Record+" UTC "+writer.Utc.ToString("o")+" mask 0x"+writer.Mask.ToString("X")+" (correlation, not proof).";}catch(Exception ex){string message="Audit query inconclusive: "+ex.GetType().Name;if(publish)auditStatus=message;return message;}}
  internal static bool RansomwareCorroborated(int changed,int entropyIncreases,int threshold){return changed>=threshold&&entropyIncreases>=3;}
  internal static bool EntropyTransition(int sample,double current,double previous){return EntropyTransition(sample,current,previous,new EndpointSettings());}
  internal static bool EntropyTransition(int sample,double current,double previous,EndpointSettings c){return sample>=c.EntropyMinimumSampleBytes&&current>=c.EntropyMinimumCurrent&&current-previous>=c.EntropyMinimumIncrease;}
  // Extended evidence is grouped by immediate directory and counted once per path.
  // Observation time is scan time, not an asserted write timestamp or process identity.
  internal static KeyValuePair<string,int> ExtendedEntropyPeak(IDictionary<string,DateTime> evidence,DateTime now){return ExtendedEntropyPeak(evidence,now,new EndpointSettings().ExtendedEntropyWindowSeconds);}
  internal static KeyValuePair<string,int> ExtendedEntropyPeak(IDictionary<string,DateTime> evidence,DateTime now,int windowSeconds){
   DateTime cutoff=now.AddSeconds(-windowSeconds);
   return evidence.Where(x=>x.Value>=cutoff&&x.Value<=now).GroupBy(x=>Path.GetDirectoryName(x.Key)??"",StringComparer.OrdinalIgnoreCase)
    .Select(g=>new KeyValuePair<string,int>(g.Key,g.Count())).OrderByDescending(x=>x.Value).ThenBy(x=>x.Key,StringComparer.OrdinalIgnoreCase).FirstOrDefault();
  }
  void ExtendedBehavior(Sqlite db,EndpointSettings c,bool rapidSuspect){
   DateTime now=DateTime.UtcNow,cutoff=now.AddSeconds(-c.ExtendedEntropyWindowSeconds);
   foreach(var p in extendedEntropy.Where(x=>x.Value<cutoff||x.Value>now).Select(x=>x.Key).ToArray())extendedEntropy.Remove(p);
   var peak=ExtendedEntropyPeak(extendedEntropy,now,c.ExtendedEntropyWindowSeconds);extendedEntropyPeak=peak.Value;
   // This warning is detection-only even in contain mode. Never attribute all changes to a process.
   if(!rapidSuspect&&peak.Value>=c.ExtendedEntropyThreshold){
    Issue(db,"Protected paths","Possible ransomware activity (extended observation)","warning",peak.Value+" distinct files in "+peak.Key+" with verified content changes and significant entropy increases observed within "+c.ExtendedEntropyWindowSeconds+" seconds. Scan observation times; legitimate encryption or compression may also cause this pattern. No automatic containment from this signal.");
   }else Resolve(db,"Protected paths","Possible ransomware activity (extended observation)");
  }

  void Behavior(Sqlite db,EndpointSettings c,WaitHandle stop,Func<bool> authorized){DateTime cutoff=DateTime.UtcNow.AddSeconds(-c.BehaviorWindowSeconds);foreach(var p in changes.Where(x=>x.Value<cutoff).Select(x=>x.Key).ToArray())changes.Remove(p);foreach(var p in highEntropy.Where(x=>x.Value<cutoff).Select(x=>x.Key).ToArray())highEntropy.Remove(p);bool suspect=RansomwareCorroborated(changes.Count,highEntropy.Count,c.ChangeThreshold);bool critical=suspect&&highEntropy.Count>=Math.Max(3,c.ChangeThreshold/5);ExtendedBehavior(db,c,suspect);if(suspect){bool newIncident=db.Rows("SELECT active FROM findings WHERE id=? AND active=1",Id("Protected paths|Possible ransomware activity")).Count==0;string detail=changes.Count+" distinct changed files; "+highEntropy.Count+" entropy increases in "+c.BehaviorWindowSeconds+" seconds. "+(newIncident?Correlate(c,latestChanged):"Investigate legitimate bulk activity.");Issue(db,"Protected paths","Possible ransomware activity",critical?"critical":"warning",detail);if(critical&&newIncident&&c.Mode=="contain"&&authorized())try{var a=EndpointResponse.FindWriter(latestChanged);if(a==null)throw new IOException("No matching write audit record");bool exitVerified;string result=EndpointResponse.Contain(c,a,stop,authorized,out exitVerified);Issue(db,a.Image,"Containment action",exitVerified?"info":"warning",result);if(exitVerified)Resolve(db,a.Image,"Containment action");}catch(Exception ex){Issue(db,"Protected paths","Containment withheld","warning",ex.Message);}}else{Resolve(db,"Protected paths","Possible ransomware activity");Resolve(db,"Protected paths","Containment withheld");}}
  // The service owns the schedule; the elevated task remains demand-only and accepts no arguments.
  const string SignatureScheduleRecord="signature_schedule_v1";
  sealed class ScheduleRecord {
   public ScheduleRecord(){}
   public string Policy {get;set;} public long Next {get;set;} public long LastRequest {get;set;} public string Status {get;set;}
  }
  static long ScheduleEpoch(DateTime utc){return (utc.Ticks-621355968000000000L)/TimeSpan.TicksPerSecond;}
  static long NextScheduleEpoch(EndpointSettings c,long now){return ScheduleEpoch(c.NextSignatureUpdate(new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc).AddSeconds(now),TimeZoneInfo.Local));}
  ScheduleRecord ReadSchedule(Sqlite db){var row=db.Rows("SELECT value FROM endpoint_metadata WHERE name=?",SignatureScheduleRecord).FirstOrDefault();if(row==null)return new ScheduleRecord();return Config.Json().Deserialize<ScheduleRecord>((string)row[0])??new ScheduleRecord();}
  void SaveSchedule(Sqlite db,ScheduleRecord record){db.Exec("INSERT OR REPLACE INTO endpoint_metadata(name,value) VALUES(?,?)",SignatureScheduleRecord,Config.Json().Serialize(record));}
  long nextProviderScheduleCheck;
  void ScheduleProviders(Sqlite db,EndpointSettings c,ClamUpdateState state,long now,Func<bool> authorized){
   if(now<nextProviderScheduleCheck)return;nextProviderScheduleCheck=now+60;
   if(!Program.ServiceMode||c.Port!=3310||!authorized())return;
   var providers=ClamUpdateState.ReadProviders();
   if(providers!=null){var failed=providers.Where(x=>x.status=="Failed"||(x.status=="Attempt reserved"&&!state.Busy)).Select(x=>x.provider).ToArray();
    if(failed.Length>0)Issue(db,"Third-party signature providers","Provider update needs review","warning","Last batch failed or was interrupted for "+String.Join(", ",failed)+". The configured retry cooldown is retained; official signatures are evaluated independently.");
    else Resolve(db,"Third-party signature providers","Provider update needs review");}
   if(!online||state.Busy||state.CoolingDown||state.status=="Unavailable")return;
   // A missing summary means migration has not yet been verified. Request one fixed maintenance run.
   DateTime due=DateTime.UtcNow;
   if(providers!=null){if(providers.Length==0)return;due=providers.Select(x=>{DateTime d;return DateTime.TryParse(x.nextUtc,System.Globalization.CultureInfo.InvariantCulture,System.Globalization.DateTimeStyles.RoundtripKind,out d)?d.ToUniversalTime():DateTime.MaxValue;}).Min();if(due>DateTime.UtcNow)return;}
   if(resourceMonitor.LowMemory&&c.SignatureMemoryDeferralMinutes>0&&providers!=null&&DateTime.UtcNow<due.AddMinutes(c.SignatureMemoryDeferralMinutes))return;
   try{Program.QueueSignatureUpdate();Resolve(db,"ClamAV","Provider schedule request failed");nextProviderScheduleCheck=now+120;}
   catch(HttpError ex){if(ex.Message.IndexOf("just requested",StringComparison.OrdinalIgnoreCase)>=0||ex.Message.IndexOf("within the last 60 minutes",StringComparison.OrdinalIgnoreCase)>=0)return;Issue(db,"ClamAV","Provider schedule request failed","warning","Could not queue provider maintenance: "+ex.GetType().Name+". Review Setup and Task Scheduler.");nextProviderScheduleCheck=now+300;}catch(Exception ex){Issue(db,"ClamAV","Provider schedule request failed","warning","Provider scheduling unavailable: "+ex.GetType().Name);nextProviderScheduleCheck=now+300;}
  }
  object ScheduledSignatures(Sqlite db,EndpointSettings c,ClamUpdateState state,long now,Func<bool> authorized){
   var r=ReadSchedule(db);string view;
   if(!c.SignatureScheduleEnabled){
    if(r.Policy!=null){r.Policy=null;r.Next=0;r.Status="Disabled";SaveSchedule(db,r);}
    Resolve(db,"ClamAV","Scheduled signature update request failed");view="Disabled";
   }else if(!Program.ServiceMode||c.Port!=3310){view="Requires installed service on port 3310";}
   else{
    var key=c.SignatureScheduleKey()+"|"+TimeZoneInfo.Local.Id;
    if(r.Policy!=key||r.Next<=0){r.Policy=key;r.Next=NextScheduleEpoch(c,now);r.Status="Scheduled";SaveSchedule(db,r);}
    // A successful schtasks invocation only confirms a request. Wait for protected worker state.
    if(r.Status=="Update requested"||r.Status=="Request reserved; task completion not confirmed"){
     DateTime attempt;
     if(DateTime.TryParse(state.attemptUtc,System.Globalization.CultureInfo.InvariantCulture,System.Globalization.DateTimeStyles.RoundtripKind,out attempt)&&ScheduleEpoch(attempt.ToUniversalTime())>=r.LastRequest){r.Status="Worker attempt recorded; see signature maintenance";SaveSchedule(db,r);}
     else if(now-r.LastRequest>=120){r.Status="Task startup not confirmed; see alerts and setup";SaveSchedule(db,r);Issue(db,"ClamAV","Scheduled signature update request failed","warning","The scheduled request did not produce a recorded worker attempt within two minutes. Check Task Scheduler and setup logs.");}
    }
    view=r.Status??"Scheduled";
    if(now>=r.Next){
     if(!authorized()){view="Policy changed; waiting for current settings";}
     else if(state.Busy||state.CoolingDown){view="Waiting for the current update or 60-minute cooldown";}
     else if(resourceMonitor.LowMemory&&c.SignatureMemoryDeferralMinutes>0&&now-r.Next<c.SignatureMemoryDeferralMinutes*60L){view="Deferred by memory pressure; latest deferral deadline: "+Telemetry.Utc(r.Next+c.SignatureMemoryDeferralMinutes*60L);}
     else{
      // Reserve exactly one occurrence before task launch. Never replay missed periods.
      r.Next=NextScheduleEpoch(c,now);r.LastRequest=now;r.Status="Request reserved; task completion not confirmed";SaveSchedule(db,r);
      try{Program.QueueSignatureUpdate();r.Status="Update requested";Resolve(db,"ClamAV","Scheduled signature update request failed");AppJournal.Event(LogLevel.Info,"Endpoint","signature-schedule","Scheduled ClamAV signature update requested.");}
      catch(Exception ex){r.Status="Request failed; see alerts and setup";Issue(db,"ClamAV","Scheduled signature update request failed","warning","Scheduled signature refresh could not be queued: "+(ex is HttpError?ex.Message:ex.GetType().Name)+". Next scheduled occurrence: "+Telemetry.Utc(r.Next));AppJournal.Event(LogLevel.Warning,"Endpoint","signature-schedule","Scheduled signature update request failed: "+ex.GetType().Name);}
      SaveSchedule(db,r);view=r.Status;
     }
    }
   }
   return new {enabled=c.SignatureScheduleEnabled,frequency=c.SignatureScheduleFrequency,localTime=c.SignatureScheduleTime,weekday=c.SignatureScheduleWeekday,monthDay=c.SignatureScheduleMonthDay,timeZone=TimeZoneInfo.Local.Id,status=view,nextRunUtc=c.SignatureScheduleEnabled&&Program.ServiceMode&&c.Port==3310&&r.Next>0?Telemetry.Utc(r.Next):null,lastScheduledRequestUtc=r.LastRequest>0?Telemetry.Utc(r.LastRequest):null};
  }
  bool ScanWatcher(Sqlite db,EndpointSettings c,WaitHandle stop,Func<bool> authorized,int lane){
   if(stop.WaitOne(0))throw new OperationCanceledException();if(!authorized())return false;
   var work=TakeWatcher(lane);if(work==null)return false;
   // Durable cooldown owns retries; a new watcher notification must not create a parallel retry loop.
   if(!c.CanaryPaths.Contains(work.Path,StringComparer.OrdinalIgnoreCase)&&usn.RetryWaiting(db,work.Path))return true;
   if(!usn.RetainWatcher(db,work.Path,work.Priority))Interlocked.Exchange(ref overflow,1);
   bool finished;watcherInspectionPath=work.ObservedWatcher?work.Path:null;try{finished=CheckFile(db,c,work.Path,stop,authorized,false,work.Retries);}finally{watcherInspectionPath=null;}if(finished&&!HasWatcher(work.Path))usn.Ack(db,work.Path);else if(!finished)usn.Defer(db,work.Path);
   return true;
  }
  void RefreshSignatureComparison(Sqlite db,EndpointSettings c){
   long loadedDatabase;DateTime stamp;string ageStatus=ClamUpdateWorker.DefinitionFreshness(version,DateTime.Now,out loadedDatabase,out stamp);
   signatureFreshness=ClamUpdateWorker.CompareOfficialDefinition(ageStatus,loadedDatabase,false,out signatureComparison);
   if(Program.ServiceMode&&c.Port==3310){long diskDaily=ClamUpdateWorker.LogDailyDatabaseHeaders(System.IO.TextWriter.Null);if(loadedDatabase>0&&diskDaily>loadedDatabase){signatureFreshness="Stale";signatureComparison+=" Reload pending: daily archive on disk "+diskDaily+" is newer than loaded "+loadedDatabase+".";}}
   if(signatureFreshness=="Current")Resolve(db,"ClamAV","Signature database may be stale");else Issue(db,"ClamAV","Signature database may be stale","warning",signatureComparison);
  }
  internal object Tick(EndpointSettings c,WaitHandle stop,bool force,Func<bool> authorized){WorkerPhase("Preparing scan cycle");string next=Config.Json().Serialize(c);if(policy!=next){Configure(c);policy=next;}if(!c.Enabled)return new {status="disabled",items=new object[0]};using(var db=Open()){
   if(Interlocked.Exchange(ref resetRequested,0)!=0){
    // Retire old per-path scan warnings. Journal/overflow and watcher gaps require verified recovery; security findings and immutable evidence are retained.
    db.Exec("UPDATE findings SET active=0 WHERE active=1 AND severity='coverage'");
    foreach(var row in db.Rows("SELECT path,change FROM findings WHERE active=1 AND severity='warning' AND change IN ('File scan error','File scan limited','Engine scan incomplete','Protected path unavailable','Scan incomplete','File scan coverage incomplete')"))Resolve(db,(string)row[0],(string)row[1]);
    db.Exec("DELETE FROM clean_verdict_cache");ClearBaseline(db);baselineRestorePending=false;baselineResumed=false;cachedChecks=metadataCachedChecks=0;baselineCached=0;
    cleanChecks=infectedChecks=heuristicChecks=excludedChecks=failedChecks=quarantinedChecks=deferredChecks=snapshotCleanChecks=realTimeChecked=0;
    lastFileScan=lastRealTimeScan=0;privilegedFileChecks=0;ResetDownloads();lastScannedPath="";running=false;complete=false;rescan=false;nextScan=0;force=true;lastCanary=0;
    AppJournal.Event(LogLevel.Info,"Endpoint","reset-rescan","Scan counters reset; operational findings will be re-evaluated. Security evidence and journal queue retained.");
   }
   if(scopeReconcilePending)ConsolidateCoverage(db,c);
   if(scopeReconcilePending){db.Exec("DELETE FROM clean_verdict_cache WHERE policy<>? OR verified<=?",CachePolicy(c),History.Now()-VerdictCacheMaxAge);int retired=ReconcileCoverageScope(db,c);scopeReconcilePending=false;if(retired>0)AppJournal.Event(LogLevel.Info,"Endpoint","scope-change","Retired "+retired+" operational warnings outside the current monitoring policy; historical incidents and security findings retained.");}
   RestoreBaseline(db,c);
   if(authorized())PollWebProcessAudit(db,c,stop,authorized);
   var maintenance=ClamUpdateState.Read();string maintenanceKey=(maintenance.attemptUtc??"")+"/"+maintenance.status+"/"+(maintenance.updatedUtc??"")+"/"+(maintenance.checkedUtc??"")+"/"+(maintenance.detail??"");
   const string recoveredDefinitionKey="signature-definition-warning-recovered-v70";
   var recoveredDefinition=db.Rows("SELECT value FROM endpoint_metadata WHERE name=?",recoveredDefinitionKey).FirstOrDefault();
   bool alreadyRecovered=maintenance.DefinitionOnlyWarning&&recoveredDefinition!=null&&Equals(recoveredDefinition[0],maintenanceKey);
   if(maintenanceKey!=signatureMaintenanceSeen){
    if(!alreadyRecovered&&(maintenance.status=="Failed"||maintenance.status=="Warning"||maintenance.status=="Interrupted"))Issue(db,"ClamAV","Signature update needs review","warning",(maintenance.detail??"Signature update did not complete.")+" · Attempt UTC: "+(maintenance.attemptUtc??"Unknown"));
    else if(maintenance.status=="Updated"||maintenance.status=="Checked"){Resolve(db,"ClamAV","Signature update needs review");AppJournal.Event(LogLevel.Info,"Endpoint","signatures",maintenance.detail);lastEngine=0;}
    if(!String.IsNullOrEmpty(maintenance.updatedUtc)){
      var marker=db.Rows("SELECT value FROM endpoint_metadata WHERE name='provider-signature-content-change'").FirstOrDefault();
      if(marker==null||!Equals(marker[0],maintenance.updatedUtc)){db.Exec("BEGIN IMMEDIATE");try{db.Exec("DELETE FROM clean_verdict_cache");db.Exec("INSERT OR REPLACE INTO endpoint_metadata(name,value) VALUES('provider-signature-content-change',?)",maintenance.updatedUtc);db.Exec("COMMIT");}catch{db.Exec("ROLLBACK");throw;}nextScan=0;if(running)rescan=true;}
    }
    signatureMaintenanceSeen=maintenanceKey;
   }
   long now=History.Now();resourceMonitor.Sample(c);object signatureSchedule;
   try{signatureSchedule=ScheduledSignatures(db,c,maintenance,now,authorized);Resolve(db,"ClamAV","Signature schedule unavailable");}
   catch(Exception ex){signatureSchedule=new {enabled=c.SignatureScheduleEnabled,frequency=c.SignatureScheduleFrequency,localTime=c.SignatureScheduleTime,weekday=c.SignatureScheduleWeekday,monthDay=c.SignatureScheduleMonthDay,timeZone=TimeZoneInfo.Local.Id,status="Schedule unavailable; review alerts",nextRunUtc=(string)null,lastScheduledRequestUtc=(string)null};Issue(db,"ClamAV","Signature schedule unavailable","warning","Scheduled signature maintenance could not be evaluated: "+ex.GetType().Name);}
   ScheduleProviders(db,c,maintenance,now,authorized);
   if(lastSignatureLogCheck==0||now-lastSignatureLogCheck>=60){lastSignatureLogCheck=now;
    var prior=db.Rows("SELECT value FROM endpoint_metadata WHERE name='reported_signature_update'").FirstOrDefault();reportedUpdateUtc=prior==null?null:(string)prior[0];
    try{string reported=ClamUpdateWorker.ReadReportedUpdate();signatureLogReadable=reported!=null;
     if(reported!=null&&(reportedUpdateUtc==null||string.CompareOrdinal(reported,reportedUpdateUtc)>0)){
      db.Exec("BEGIN IMMEDIATE");try{db.Exec("DELETE FROM clean_verdict_cache");db.Exec("INSERT OR REPLACE INTO endpoint_metadata(name,value) VALUES('reported_signature_update',?)",reported);db.Exec("COMMIT");}catch{db.Exec("ROLLBACK");throw;}
      reportedUpdateUtc=reported;nextScan=0;if(running)rescan=true;
     }
    }catch(Exception){signatureLogReadable=false;}
   }
   WorkerPhase("Checking antivirus and response readiness");
   if((force||lastEngine==0||now-lastEngine>=(online?60:15))&&now>=nextEngineProbe){lastEngine=now;bool previouslyOnline=online;string previousVersion=version;try{version=Command(c.Port,"VERSION",null,stop,Program.ServiceMode&&c.Port==3310?(Action<TcpClient>)ClamUpdateWorker.VerifyScanServiceOwner:null);online=version.StartsWith("ClamAV",StringComparison.OrdinalIgnoreCase);if(!online)throw new IOException("Unexpected engine version");
     if(engineNeedsScanProbe){using(var probe=new MemoryStream(Encoding.ASCII.GetBytes("LinkScope benign engine readiness probe"))){string verdict=Command(c.Port,"INSTREAM",probe,stop,Program.ServiceMode&&c.Port==3310?(Action<TcpClient>)ClamUpdateWorker.VerifyScanServiceOwner:null);if(!CleanVerdict(verdict))throw new IOException("Engine readiness scan did not return a clean verdict: "+verdict);}}
     if(previouslyOnline&&!string.Equals(previousVersion,version,StringComparison.Ordinal)){db.Exec("DELETE FROM clean_verdict_cache");nextScan=0;if(running)rescan=true;}engineNeedsScanProbe=false;engineFailures=0;nextEngineProbe=0;lastSignatureCheck=History.Now();signatureFreshness="Unknown";Resolve(db,"ClamAV","Engine unavailable");if(!previouslyOnline){nextScan=0;reconcilePending=true;if(running)rescan=true;}var parts=version.Split('/');signatureVersion=parts.Length>=2?parts[1]:"Unknown";signatureTimestamp=parts.Length>=3?parts[2]:"Unknown";lastSignatureComparison=0;}catch(OperationCanceledException){throw;}catch(Exception ex){online=false;version="Unavailable";signatureVersion=signatureTimestamp=signatureFreshness="Unknown";MarkEngineTransportFailed(db,ex.GetType().Name+": "+ex.Message);}}
   // DNS is asynchronous. Harvest it independently of the 60-second ClamD VERSION poll.
   // Do not change the engine observation timestamp when only the DNS comparison is refreshed.
   if(online&&(lastSignatureComparison==0||now<lastSignatureComparison||now-lastSignatureComparison>=5)){
    lastSignatureComparison=now;
    RefreshSignatureComparison(db,c);
   }
   // Only the specific historical definition comparison warning is reconciled. A failed
   // download, explicit expected-version reload failure, provider failure, interrupted worker or updater readiness warning is not.
   // A current engine observation newer than the completed download is mandatory.
   if(Program.ServiceMode&&c.Port==3310&&!alreadyRecovered&&maintenance.CanReconcileDefinitionWarning(online&&!engineNeedsScanProbe,signatureFreshness,lastSignatureCheck,History.Now())){
    Resolve(db,"ClamAV","Signature update needs review");
    db.Exec("INSERT OR REPLACE INTO endpoint_metadata(name,value) VALUES(?,?)",recoveredDefinitionKey,maintenanceKey);alreadyRecovered=true;
    AppJournal.Event(LogLevel.Info,"Endpoint","signatures","Historical definition comparison warning resolved by newer authenticated engine/version comparison; original maintenance result retained. "+signatureComparison);
   }
   CheckResponseReadiness(db,c,stop,now,force);
   ConsumeWatcherFaults();RetryFailedWatchers(now);
   ConsumeCoverageOverflow(db);
   WorkerPhase("Replaying filesystem journal");
   usn.Poll(db,c,(root,detail)=>Issue(db,root,"USN journal unavailable","warning",detail),root=>Resolve(db,root,"USN journal unavailable"),(root,detail)=>Issue(db,root,"USN journal coverage gap","warning",detail),()=>RequestReconciliation(c,true),root=>IndependentLocalCoverage(c,root));
   now=History.Now();
   SyncPrivilegedWatchers(c);
   if(Interlocked.Exchange(ref privilegedWatcherReconcile,0)!=0)RequestReconciliation(c,true);
   if(!running&&c.RealTime&&lastScan>0){var providers=PrivilegedWatcherSnapshot();if(c.Paths.Any(root=>!Excluded(c,root)&&!localWatchers.ContainsKey(root)&&!usn.Covers(root)&&(!providers.ContainsKey(root)||!PrivilegedWatcherCovers(providers[root],History.Now()))))nextScan=Math.Min(nextScan,lastScan+Math.Min(c.IntervalSeconds,300));}
   ScheduleCoverageRecovery(db,c);
   if(force){nextScan=0;if(running)rescan=true;}if(!running&&now>=nextScan){db.Exec("DELETE FROM clean_verdict_cache WHERE verified<=? OR verified>?",now-VerdictCacheMaxAge,now);db.Exec("DELETE FROM clean_verdict_cache WHERE rowid IN (SELECT rowid FROM clean_verdict_cache ORDER BY verified DESC LIMIT -1 OFFSET 100000)");rescan=false;StartScan(db,c);}
   // Canaries have a dedicated lane; ordinary queue pressure must not prevent integrity checks.
   WorkerPhase("Checking canaries and pending file events");
   var timer=Stopwatch.StartNew();if(now-lastCanary>=10){lastCanary=now;foreach(string canary in c.CanaryPaths.Take(100)){if(stop.WaitOne(0))throw new OperationCanceledException();if(!authorized())break;if(CheckFile(db,c,canary,stop,authorized,false)&&c.RealTime&&online&&!HasWatcher(canary))usn.Ack(db,canary);}}
   ProcessFileProbe(db,c,stop,authorized);
   if(c.RealTime&&authorized()){PollDownloads(c,now);ScanDownload(db,c,stop,authorized,now);}
   // New downloads and copied/renamed files precede scheduled and replay work.
   if(c.RealTime&&online){ScanWatcher(db,c,stop,authorized,0);if(online&&timer.ElapsedMilliseconds<800)ScanWatcher(db,c,stop,authorized,2);}
   // Journal arrivals may be the only events for protected user directories. Give
   // them a chance before a slow background file scan, even if the watcher is busy.
   if(c.RealTime&&online){
    foreach(string path in usn.Pending(db,4)){if(stop.WaitOne(0))throw new OperationCanceledException();if(!authorized())break;
     // Let the watcher debounce and retry a file that is still being written.
     if(HasWatcher(path))continue;
     if(CheckFile(db,c,path,stop,authorized,false))usn.Ack(db,path);else usn.Defer(db,path);if(!online||timer.ElapsedMilliseconds>1200)break;
    }
    if(online)ScanWatcher(db,c,stop,authorized,1);
    for(int count=0;online&&count<6&&timer.ElapsedMilliseconds<1200;count++)if(!ScanWatcher(db,c,stop,authorized,count%2==0?0:1)&&!ScanWatcher(db,c,stop,authorized,1))break;
   }
   // Guarantee one background step even under sustained arrivals.
   resourceMonitor.Sample(c);
   baselineThrottleReason=running?(c.BackgroundPauseOnLowMemory&&resourceMonitor.LowMemory?"Low available physical memory":diskPressure.PauseReason(c)):"";
   if(online&&running&&pending.Count>0&&string.IsNullOrEmpty(baselineThrottleReason)){using(var priority=new EndpointBackgroundPriority(true)){
    ScanNext(db,c,stop,authorized);
    int countFull=1;while(online&&running&&pending.Count>0&&countFull++<c.BackgroundBatchSize&&timer.ElapsedMilliseconds<500&&WatchCounts()[0]==0&&usn.ReadyDepth(db)==0)ScanNext(db,c,stop,authorized);
   }}
   // Catch watcher loss signalled while this tick was scanning before certifying completion.
   ConsumeCoverageOverflow(db);
   if(running&&pending.Count==0){running=false;lastScan=History.Now();nextScan=rescan?lastScan:lastScan+c.IntervalSeconds;complete=errors==0&&limited==0&&online&&!baselineResumed&&!rescan;if(!traversalLimitReached)Resolve(db,"Protected paths","Scan traversal limit reached");if(complete){/* A complete scan reconciles old coverage gaps, but not newer real-time failures. */foreach(var oldCoverage in db.Rows("SELECT id,path FROM findings WHERE active=1 AND severity='coverage' AND last<?",new DateTimeOffset(new DateTime(scanId,DateTimeKind.Utc)).ToUnixTimeSeconds()))if(!BackgroundExcluded(c,(string)oldCoverage[1]))db.Exec("UPDATE findings SET active=0 WHERE id=?",oldCoverage[0]);foreach(var missing in db.Rows("SELECT path FROM files WHERE scope=? AND seen<>? LIMIT 100001",scope,scanId)){string path=(string)missing[0];if(BackgroundExcluded(c,path))continue;if(!Excluded(c,path)){Observe(path,false);if(c.CanaryPaths.Contains(path,StringComparer.OrdinalIgnoreCase))CanaryIssue(db,c,path,"Canary missing during reconciliation.","",stop,authorized);}ForgetCached(db,path);if(WebServerProtection.InScope(c,path)&&ConfirmAbsent(path)){Resolve(db,path,WebServerProtection.Finding);Resolve(db,path,WebServerProtection.Coverage);}db.Exec("DELETE FROM files WHERE scope=? AND path=?",scope,path);Resolve(db,path,"Malware signature detected");Resolve(db,path,"Heuristic signature finding");Resolve(db,path,"File scan error");Resolve(db,path,"File scan limited");Resolve(db,path,"Engine scan incomplete");Resolve(db,path,"Quarantine withheld or failed");}if(!rescan)Resolve(db,"Protected paths","Real-time queue overflow");Resolve(db,"Protected paths","Scan incomplete");if(!rescan&&!journalGapDuringScan)foreach(var root in c.Paths.Select(Path.GetPathRoot).Distinct(StringComparer.OrdinalIgnoreCase))Resolve(db,root,"USN journal coverage gap");}else Issue(db,"Protected paths","Scan incomplete","warning",baselineResumed?"Resumed baseline finished; fresh reconciliation required after interruption.":rescan?"Follow-up reconciliation pending due to a new scan or coverage request.":errors+" errors; "+limited+" size-limited files; engine online: "+online);ClearBaseline(db);AppJournal.Event(LogLevel.Info,"Endpoint","scan","Scanned "+scanned+"; excluded "+excluded+"; errors "+errors+"; limited "+limited);}
   WorkerPhase("Publishing findings and scan statistics");
   Behavior(db,c,stop,authorized);object[] vaultItems;bool vaultAvailable=true;try{vaultItems=QuarantineInventory(db);Resolve(db,"Quarantine vault","Quarantine inventory unavailable");}catch(Exception ex){vaultAvailable=false;vaultItems=new object[0];Issue(db,"Quarantine vault","Quarantine inventory unavailable","warning",ex.GetType().Name);}
   // Reconcile completed quarantine and deletion evidence only when the original
   // path is verifiably absent and the finding has the identical recorded hash.
   if(vaultAvailable&&online){
    foreach(var entry in vaultItems.OfType<Dictionary<string,object>>().Where(x=>x.ContainsKey("state")&&Equals(x["state"],"quarantined")))
     ResolveQuarantinedOriginal(db,Convert.ToString(entry["path"]),Convert.ToString(entry["sha256"]));
    foreach(var receipt in db.Rows("SELECT q.path,q.hash FROM quarantine_deletions q JOIN findings f ON f.path=q.path COLLATE NOCASE AND f.hash=q.hash WHERE q.completed IS NOT NULL AND f.active=1 AND f.change IN ('Malware signature detected','Quarantine withheld or failed') LIMIT 200"))
     ResolveQuarantinedOriginal(db,(string)receipt[0],(string)receipt[1]);
   }
   // Evaluate fresh coverage at publication time, not before a potentially slow scan.
   now=History.Now();ConsumeWatcherFaults();SyncPrivilegedWatchers(c);var privilegedSnapshot=PrivilegedWatcherSnapshot();
   Func<string,PrivilegedWatcherState> watcherState=root=>{PrivilegedWatcherState state;return privilegedSnapshot.TryGetValue(root,out state)?state:null;};
   var uncoveredWatchers=failedWatchers.Where(x=>!usn.Covers(x.Key)&&!PrivilegedWatcherCovers(watcherState(x.Key),now)).ToArray();
   var confirmedUncovered=uncoveredWatchers.Where(x=>!PrivilegedWatcherInitializing(watcherState(x.Key),now)).ToArray();
   // A bounded initial handshake is not a verified watcher. Keep partial telemetry,
   // but avoid creating a transient alert unless the helper fails or exceeds grace.
   if(confirmedUncovered.Length>0)Issue(db,"Protected paths","Watcher coverage incomplete","warning",confirmedUncovered.Length+" configured roots lack verified local watcher, journal or privileged watcher coverage. "+string.Join("; ",confirmedUncovered.Take(3).Select(x=>x.Key+" ("+x.Value+(watcherState(x.Key)!=null?"; helper: "+watcherState(x.Key).Detail:Program.ServiceMode?"; helper: no eligible privileged watcher":"; helper: Windows service mode required")+")")));else if(uncoveredWatchers.Length==0)Resolve(db,"Protected paths","Watcher coverage incomplete");
   var coverageCount=Convert.ToInt64(db.Rows("SELECT COUNT(*) FROM findings WHERE active=1 AND severity='coverage'")[0][0]);CoverageSummary(db,coverageCount);
   var coverageRows=db.Rows("SELECT path,change,detail,last FROM findings WHERE active=1 AND severity='coverage' ORDER BY last DESC,path LIMIT 100");
   var coverageBreakdown=db.Rows("SELECT CASE WHEN change='File scan limited' THEN 'Size limit' WHEN change='Engine scan incomplete' THEN 'Engine incomplete' WHEN detail LIKE 'Deferred: file in use%' THEN 'Deferred — file in use' WHEN detail LIKE 'Reparse boundary:%' THEN 'Reparse boundary — target unverified' ELSE change END AS category, COUNT(*) FROM findings WHERE active=1 AND severity='coverage' GROUP BY category ORDER BY category").Select(x=>new {category=x[0],count=x[1]}).ToArray();
   var watchCounts=WatchCounts();int journalDepth=usn.Depth(db);
   var rootCoverage=c.Paths.Select(root=>{var helper=watcherState(root);bool local=localWatchers.ContainsKey(root);bool journal=usn.Covers(root);bool privileged=PrivilegedWatcherCovers(helper,now);string error;failedWatchers.TryGetValue(root,out error);return new {path=root,localWatcher=local,journal=journal,privilegedWatcher=privileged,state=Excluded(c,root)?"Excluded":!c.RealTime?"Scheduled only":local||privileged?"Watching":journal?"Journal only":PrivilegedWatcherInitializing(helper,now)?"Initializing":"Uncovered",localWatcherDiagnostic=error,privilegedWatcherDiagnostic=helper==null?null:helper.Verified>0&&!privileged?"Awaiting fresh privileged watcher response":helper.Detail,detail=(error??"")+(helper==null?"":"; helper: "+helper.Detail)};}).ToArray();
   var active=db.Rows("SELECT id,path,change,severity,detail,hash,first,last FROM findings WHERE active=1 AND severity<>'coverage' ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END,last DESC LIMIT 201");var history=db.Rows("SELECT utc,path,change,severity,detail,hash FROM incidents ORDER BY seq DESC LIMIT 100");return new {webProtection=WebProtectionSnapshot(db,c),status=!online?"unavailable":active.Count>200||uncoveredWatchers.Length>0||coverageCount>0||signatureFreshness!="Current"||rootCoverage.Any(x=>x.state=="Excluded")||(!running&&(!complete||watchCounts[0]+journalDepth>0))?"partial":(running||(c.WebProtectionEnabled&&c.WebProcessAuditEnabled&&!webAuditState.StartsWith("Available —",StringComparison.Ordinal)))?"scanning":"ok",engineVersion=version,engineOnline=online,engineRetryUtc=nextEngineProbe>0?Telemetry.Utc(nextEngineProbe):null,engineRecoveryPending=engineNeedsScanProbe,signatureDatabaseVersion=signatureVersion,signatureDatabaseTimestamp=signatureTimestamp,signatureFreshness=signatureFreshness,signatureComparison=online?signatureComparison:"Engine unavailable; comparison not verified.",signatureMaintenance=maintenance,signatureMaintenanceDefinitionRecovered=alreadyRecovered,signatureSchedule=signatureSchedule,lastSuccessfulSignatureUpdateUtc=maintenance.updatedUtc,lastSuccessfulSignatureRefreshUtc=maintenance.checkedUtc,lastReportedSignatureUpdateUtc=reportedUpdateUtc,signatureUpdateLogRecognized=signatureLogReadable,lastSignatureCheckUtc=lastSignatureCheck==0?null:Telemetry.Utc(lastSignatureCheck),cleanChecks=cleanChecks,snapshotCleanChecks=snapshotCleanChecks,cachedChecks=cachedChecks,metadataCachedChecks=metadataCachedChecks,backgroundReadMiB=c.BackgroundReadMiB,resources=resourceMonitor.Snapshot(c),backgroundBatchSize=c.BackgroundBatchSize,baselineThrottleReason=baselineThrottleReason,baselineFollowupRequired=rescan||baselineResumed||journalGapDuringScan,diskPressureStatus=diskPressure.Status,baselineCached=baselineCached,baselineResumed=baselineResumed,verdictCacheMaxAgeSeconds=VerdictCacheMaxAge,infectedChecks=infectedChecks,heuristicChecks=heuristicChecks,excludedChecks=excludedChecks,failedChecks=failedChecks,deferredChecks=deferredChecks,quarantinedChecks=quarantinedChecks,scanActivityLimit=100,scanActivity=db.Rows("SELECT utc,path,source,result,durationMs,detail FROM scan_activity ORDER BY seq DESC LIMIT 100").Select(x=>new {utc=Telemetry.Utc(Convert.ToInt64(x[0])),path=x[1],source=x[2],result=x[3],durationMs=x[4],detail=x[5]}).ToArray(),canaries=c.CanaryPaths.Select(path=>{var baseline=db.Rows("SELECT hash FROM canaries WHERE path=?",path).FirstOrDefault();var issue=db.Rows("SELECT change,severity,last FROM findings WHERE path=? COLLATE NOCASE AND active=1 AND change IN ('Canary integrity violation','File scan error','File scan limited','Engine scan incomplete') ORDER BY CASE severity WHEN 'critical' THEN 0 ELSE 1 END LIMIT 1",path).FirstOrDefault();return new {path=path,expectedHash=CanaryTemplates.ExpectedForPath(path)??(baseline==null?null:(string)baseline[0]),status=issue!=null?(string)issue[1]:baseline==null?"Pending baseline":"Enrolled",detail=issue==null?"No active canary finding recorded":(string)issue[0]};}).ToArray(),mode=c.Mode,responseEngineStatus=responseEngineStatus,responseEngineDetail=responseEngineDetail,responseCheckedUtc=lastResponseCheck==0?null:Telemetry.Utc(lastResponseCheck),responsePathsReadiness=responsePathsReadiness,testPaths=c.TestPaths,realTime=c.RealTime,watcherCount=watchers.Count,watcherFailures=watcherFailures,watcherRootsCoveredByJournal=failedWatchers.Count(x=>usn.Covers(x.Key)),watcherRootsCoveredByPrivileged=failedWatchers.Count(x=>PrivilegedWatcherCovers(watcherState(x.Key),now)),watcherCoverageInitializing=uncoveredWatchers.Length>0&&confirmedUncovered.Length==0&&online&&active.Count<=200&&(running||(complete&&coverageCount==0)),privilegedWatcherDetails=privilegedSnapshot.Select(x=>new {path=x.Key,active=PrivilegedWatcherCovers(x.Value,now),detail=x.Value.Verified>0&&!PrivilegedWatcherCovers(x.Value,now)?"Awaiting fresh privileged watcher response":x.Value.Detail}).ToArray(),usnVolumes=usn.Status(),usnQueueDepth=journalDepth,deferredQueueDepth=usn.DeferredDepth(db),durableReadyDepth=usn.ReadyDepth(db),watcherQueueDepth=watchCounts[0],priorityQueueDepth=watchCounts[1]+usn.PriorityDepth(db),queueDepth=watchCounts[0]+journalDepth,overflowCount=seenOverflow,scanRunning=running,scanStartedUtc=scanId==0?null:new DateTime(scanId,DateTimeKind.Utc).ToString("o"),realTimeChecked=realTimeChecked,privilegedFileChecks=privilegedFileChecks,downloadRoots=downloadRoots,downloadStatus=downloadStatus,downloadChecks=downloadChecks,downloadPending=downloadWork.Values.Count(x=>!x.Done),downloadLastPath=downloadLastPath,downloadLastResult=downloadLastResult,lastFileScanUtc=lastFileScan==0?null:Telemetry.Utc(lastFileScan),lastRealTimeScanUtc=lastRealTimeScan==0?null:Telemetry.Utc(lastRealTimeScan),lastScannedPath=lastScannedPath,lastScanUtc=lastScan==0?null:Telemetry.Utc(lastScan),nextScanUtc=running?null:Telemetry.Utc(nextScan),scannedFiles=scanned,baselineVisited=visited.Count,baselineDiscoveredPending=pending.Count,baselineErrors=errors,baselineEntryLimit=MaxEntries,configuredMaxFileMiB=c.MaxFileMiB,excludedEntries=excluded,sizeLimitedFiles=limited,changedFiles=changes.Count,entropyChanges=highEntropy.Count,behaviorWindowSeconds=c.BehaviorWindowSeconds,behaviorChangeThreshold=c.ChangeThreshold,extendedEntropyPeak=extendedEntropyPeak,extendedEntropyWindowSeconds=c.ExtendedEntropyWindowSeconds,extendedEntropyThreshold=c.ExtendedEntropyThreshold,entropyMinimumSampleBytes=c.EntropyMinimumSampleBytes,entropyMinimumCurrent=c.EntropyMinimumCurrent,entropyMinimumIncrease=c.EntropyMinimumIncrease,canaryCount=c.CanaryPaths.Length,processCorrelation=auditStatus,violations=Convert.ToInt64(db.Rows("SELECT COUNT(*) FROM findings WHERE active=1 AND severity IN ('critical','warning')")[0][0]),protectedPaths=c.Paths,rootCoverage=rootCoverage,fullScanComplete=complete,truncated=active.Count>200,historyLimit=100,activeMalware=Convert.ToInt64(db.Rows("SELECT COUNT(*) FROM findings WHERE active=1 AND change='Malware signature detected'")[0][0]),activeHeuristic=Convert.ToInt64(db.Rows("SELECT COUNT(*) FROM findings WHERE active=1 AND change='Heuristic signature finding'")[0][0]),coverageIssueCount=coverageCount,coverageBreakdown=coverageBreakdown,coverageDetails=coverageRows.Select(x=>new {path=x[0],issue=CoverageKind((string)x[1],(string)x[2]),detail=x[2],lastUtc=Telemetry.Utc(Convert.ToInt64(x[3]))}).ToArray(),activeScanIssues=Convert.ToInt64(db.Rows("SELECT COUNT(*) FROM findings WHERE active=1 AND severity<>'coverage' AND change IN ('File scan error','File scan limited','Engine scan incomplete','Scan incomplete','File scan coverage incomplete','Protected path unavailable','Engine unavailable','Watcher coverage incomplete','Real-time queue overflow','USN journal unavailable','USN journal coverage gap','Scan traversal limit reached')")[0][0]),quarantineCount=vaultAvailable?(long?)vaultItems.Length:null,quarantineDeletedCount=Convert.ToInt64(db.Rows("SELECT COUNT(*) FROM quarantine_deletions WHERE completed IS NOT NULL")[0][0]),quarantineItems=vaultItems.Take(100).ToArray(),quarantineDeletions=DeletionHistory(db),pendingAlertDelivery=Convert.ToInt64(db.Rows("SELECT COUNT(*) FROM endpoint_outbox")[0][0]),items=active.Take(200).Select(x=>new {id=x[0],path=x[1],change=x[2],severity=x[3],status=x[3],detail=x[4],actualHash=x[5],firstUtc=Telemetry.Utc(Convert.ToInt64(x[6])),lastUtc=Telemetry.Utc(Convert.ToInt64(x[7]))}).ToArray(),recentIncidents=history.Select(x=>new {utc=Telemetry.Utc(Convert.ToInt64(x[0])),path=x[1],change=x[2],severity=x[3],detail=x[4],hash=x[5]}).ToArray()};}}
  public void Dispose(){CloseWatchers();Thread thread;lock(privilegedWatcherGate){privilegedWatcherStopping=true;thread=privilegedWatcherThread;}if(thread!=null)thread.Join(2000);}
 }
}
