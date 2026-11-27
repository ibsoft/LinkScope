// Endpoint source layout: split-response-v2
using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using System.Xml;
using Microsoft.Win32.SafeHandles;
namespace LinkScope {
 public sealed class EndpointSettings {
  public bool Enabled {get;set;} public bool WriteEvents {get;set;} public bool RealTime {get;set;} public bool ProcessCorrelation {get;set;}
  public bool SignatureScheduleEnabled {get;set;} public string SignatureScheduleFrequency {get;set;} public string SignatureScheduleTime {get;set;} public int SignatureScheduleWeekday {get;set;} public int SignatureScheduleMonthDay {get;set;}
  public int IntervalSeconds {get;set;} public int ChangeThreshold {get;set;} public int Port {get;set;} public int MaxFileMiB {get;set;} public int BehaviorWindowSeconds {get;set;}
  public string Mode {get;set;} public string TrustedEnginePath {get;set;} public string TrustedEngineSha256 {get;set;} public string[] Paths {get;set;} public string[] ExcludedPaths {get;set;} public string[] ExcludedPatterns {get;set;} public string[] CanaryPaths {get;set;} public string[] ResponsePaths {get;set;} public string[] ContainmentExecutables {get;set;}
  public EndpointSettings(){SignatureScheduleFrequency="daily";SignatureScheduleTime="03:00";SignatureScheduleWeekday=1;SignatureScheduleMonthDay=1;IntervalSeconds=300;ChangeThreshold=50;Port=3310;MaxFileMiB=25;BehaviorWindowSeconds=60;RealTime=true;Mode="monitor";TrustedEnginePath="";TrustedEngineSha256="";Paths=new string[0];ExcludedPaths=new string[0];ExcludedPatterns=new string[0];CanaryPaths=new string[0];ResponsePaths=new string[0];ContainmentExecutables=new string[0];}
  internal void Validate(){if(!new[]{"daily","weekly","monthly"}.Contains(SignatureScheduleFrequency)||!Regex.IsMatch(SignatureScheduleTime??"",@"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$")||SignatureScheduleWeekday<0||SignatureScheduleWeekday>6||SignatureScheduleMonthDay<1||SignatureScheduleMonthDay>31)throw new InvalidDataException("Invalid ClamAV signature schedule.");if(SignatureScheduleEnabled&&Port!=3310)throw new InvalidDataException("Scheduled signature maintenance requires the standard ClamD port 3310.");if(IntervalSeconds<60||IntervalSeconds>86400||ChangeThreshold<5||ChangeThreshold>10000||Port<1||Port>65535||MaxFileMiB<1||MaxFileMiB>100||BehaviorWindowSeconds<10||BehaviorWindowSeconds>600||!new[]{"monitor","protect","contain"}.Contains(Mode))throw new InvalidDataException("Invalid endpoint monitoring settings.");Paths=Normalize(Paths);ExcludedPaths=Normalize(ExcludedPaths);CanaryPaths=Normalize(CanaryPaths);ResponsePaths=Normalize(ResponsePaths);ContainmentExecutables=Normalize(ContainmentExecutables);ExcludedPatterns=ExcludedPatterns??new string[0];if(ExcludedPatterns.Length>100||ExcludedPatterns.Any(x=>string.IsNullOrWhiteSpace(x)||x.Length>200||x.Any(char.IsControl)||x.IndexOfAny(new[]{'\\','/',':'})>=0))throw new InvalidDataException("Use filename wildcard patterns only.");if(Enabled&&Paths.Length==0)throw new InvalidDataException("Configure at least one endpoint scan path.");if(CanaryPaths.Any(x=>!Paths.Any(p=>EndpointProtection.Under(x,p))||EndpointProtection.Excluded(this,x)))throw new InvalidDataException("Canary files must be monitored and not excluded.");if(ResponsePaths.Any(x=>!Paths.Any(p=>EndpointProtection.Under(x,p))||!EndpointResponse.SafeScope(x)))throw new InvalidDataException("Response paths must be monitored non-system directories or files, not drive roots.");TrustedEnginePath=TrustedEnginePath??"";TrustedEngineSha256=(TrustedEngineSha256??"").Trim().ToLowerInvariant();if(Mode!="monitor"&&(!EndpointResponse.TrustedEngineLocation(TrustedEnginePath)||!Regex.IsMatch(TrustedEngineSha256,"^[a-f0-9]{64}$")))throw new InvalidDataException("Automatic response requires an administrator-pinned clamd.exe path under Program Files and SHA-256.");if(Mode!="monitor"&&ResponsePaths.Length==0)throw new InvalidDataException("Specify restricted response paths before enabling automatic actions.");if(ContainmentExecutables.Any(x=>!ResponsePaths.Any(p=>EndpointProtection.Under(x,p))||!x.EndsWith(".exe",StringComparison.OrdinalIgnoreCase)||EndpointProtection.Excluded(this,x)))throw new InvalidDataException("Containment executables must be exact monitored EXE paths inside response scope.");if(Mode=="contain"&&(!RealTime||!ProcessCorrelation||ContainmentExecutables.Length==0))throw new InvalidDataException("Contain mode requires real-time monitoring, process auditing and explicit executable paths.");}
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
  readonly string store; readonly string dbPath; readonly object vaultGate=new object(); readonly List<FileSystemWatcher> watchers=new List<FileSystemWatcher>();
  readonly ConcurrentQueue<string> queue=new ConcurrentQueue<string>(); int queued,overflow; long seenOverflow; int watcherFailures;
  readonly Dictionary<string,DateTime> deferred=new Dictionary<string,DateTime>(StringComparer.OrdinalIgnoreCase);
  readonly Dictionary<string,DateTime> changes=new Dictionary<string,DateTime>(StringComparer.OrdinalIgnoreCase);
  readonly Dictionary<string,DateTime> highEntropy=new Dictionary<string,DateTime>(StringComparer.OrdinalIgnoreCase);
  readonly Stack<string> pending=new Stack<string>(); readonly HashSet<string> visited=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
  string signatureMaintenanceSeen="",reportedUpdateUtc=null;long lastSignatureLogCheck;bool signatureLogReadable;
  string responseEngineStatus="Not checked",responseEngineDetail="Waiting for response verification";
  long lastResponseCheck,responseVerifiedEpoch;object[] responsePathsReadiness=new object[0];
  string signatureFreshness="Unknown"; string policy,scope,version="Unavailable",auditStatus="Disabled",signatureVersion="Unknown",signatureTimestamp="Unknown"; long nextScan,scanId,lastScan,lastEngine,lastCanary,lastSignatureCheck; bool running,online,complete,rescan,reconcilePending=true; int scanned,excluded,limited,errors; long cleanChecks,infectedChecks,heuristicChecks,excludedChecks,failedChecks,quarantinedChecks; long realTimeChecked,lastFileScan,lastRealTimeScan; string latestChanged="",lastScannedPath="";
  internal EndpointProtection():this(Path.Combine(Config.Data,"endpoint")){} internal EndpointProtection(string directory){store=directory;dbPath=Path.Combine(store,"endpoint.sqlite");}
  internal static string Hash(byte[] b){using(var h=SHA256.Create())return BitConverter.ToString(h.ComputeHash(b)).Replace("-","").ToLowerInvariant();}
  internal static string Id(string p){return Hash(Encoding.UTF8.GetBytes(p.ToUpperInvariant()));}
  internal static bool Under(string p,string root){return string.Equals(p.TrimEnd('\\'),root.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase)||p.StartsWith(root.TrimEnd('\\')+"\\",StringComparison.OrdinalIgnoreCase);}
  internal static bool Excluded(EndpointSettings c,string p){return Under(p,Config.Root)||c.ExcludedPaths.Any(x=>Under(p,x))||c.ExcludedPatterns.Any(x=>Regex.IsMatch(Path.GetFileName(p),"^"+Regex.Escape(x).Replace("\\*",".*").Replace("\\?",".")+"$",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant,TimeSpan.FromMilliseconds(50)));}
  internal static void SafePath(string p){for(string q=p;!string.IsNullOrEmpty(q);q=Path.GetDirectoryName(q)){if((File.GetAttributes(q)&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse point skipped");}}
  internal static double Entropy(byte[] b,int n){if(n==0)return 0;var counts=new int[256];for(int i=0;i<n;i++)counts[b[i]]++;double h=0;foreach(int count in counts)if(count>0){double f=(double)count/n;h-=f*Math.Log(f,2);}return h;}
  internal static string FileHash(Stream s){using(var h=SHA256.Create())return BitConverter.ToString(h.ComputeHash(s)).Replace("-","").ToLowerInvariant();}
  internal static string Command(int port,string cmd,Stream file,WaitHandle stop,Action<TcpClient> verifyPeer=null){using(var c=new TcpClient(AddressFamily.InterNetwork)){var ar=c.BeginConnect(IPAddress.Loopback,port,null,null);using(var wait=ar.AsyncWaitHandle){if(!wait.WaitOne(2000))throw new IOException("ClamAV connection timed out");c.EndConnect(ar);}if(verifyPeer!=null)verifyPeer(c);c.ReceiveTimeout=5000;c.SendTimeout=5000;using(var s=c.GetStream()){var command=Encoding.ASCII.GetBytes("z"+cmd+"\0");s.Write(command,0,command.Length);var deadline=Stopwatch.StartNew();if(file!=null){byte[] b=new byte[65536];int n;while((n=file.Read(b,0,b.Length))>0){if(stop.WaitOne(0))throw new OperationCanceledException();if(deadline.ElapsedMilliseconds>30000)throw new IOException("Scan deadline exceeded");var size=BitConverter.GetBytes(IPAddress.HostToNetworkOrder(n));s.Write(size,0,4);s.Write(b,0,n);}s.Write(new byte[4],0,4);}var reply=new List<byte>();while(reply.Count<4096){if(stop.WaitOne(0))throw new OperationCanceledException();if(deadline.ElapsedMilliseconds>30000)throw new IOException("Scan deadline exceeded");int x=s.ReadByte();if(x==0||x==10)return Encoding.UTF8.GetString(reply.ToArray());if(x<0)throw new IOException("Incomplete engine reply");reply.Add((byte)x);}throw new IOException("Oversized engine reply");}}}
  internal static bool Malware(string reply){return reply.EndsWith(" FOUND",StringComparison.Ordinal)&&!reply.StartsWith("stream: Heuristics.Limits.Exceeded",StringComparison.OrdinalIgnoreCase);}
  void Enqueue(string path){if(Interlocked.Increment(ref queued)>MaxQueue){Interlocked.Decrement(ref queued);Interlocked.Exchange(ref overflow,1);return;}queue.Enqueue(path);}
  void CloseWatchers(){foreach(var w in watchers)w.Dispose();watchers.Clear();}
  void Configure(EndpointSettings c){CloseWatchers();string q;while(queue.TryDequeue(out q))Interlocked.Decrement(ref queued);deferred.Clear();changes.Clear();highEntropy.Clear();pending.Clear();visited.Clear();running=false;rescan=false;reconcilePending=true;nextScan=0;lastEngine=0;lastCanary=0;lastResponseCheck=0;responseVerifiedEpoch=0;responseEngineStatus="Not checked";responseEngineDetail="Waiting for response verification";responsePathsReadiness=new object[0];watcherFailures=0;realTimeChecked=lastFileScan=lastRealTimeScan=0;cleanChecks=infectedChecks=heuristicChecks=excludedChecks=failedChecks=quarantinedChecks=0;lastScannedPath="";auditStatus=c.ProcessCorrelation?"Awaiting matching audit evidence":"Disabled";scope=Id(Config.Json().Serialize(new {c.Paths,c.ExcludedPaths,c.ExcludedPatterns}));if(!c.Enabled||!c.RealTime)return;foreach(var p in c.Paths)try{SafePath(p);bool dir=Directory.Exists(p);var w=new FileSystemWatcher(dir?p:Path.GetDirectoryName(p),dir?"*":Path.GetFileName(p));w.IncludeSubdirectories=dir;w.InternalBufferSize=32768;w.NotifyFilter=NotifyFilters.FileName|NotifyFilters.DirectoryName|NotifyFilters.LastWrite|NotifyFilters.Size;w.Changed+=(s,e)=>Enqueue(e.FullPath);w.Created+=(s,e)=>Enqueue(e.FullPath);w.Deleted+=(s,e)=>Enqueue(e.FullPath);w.Renamed+=(s,e)=>{Enqueue(e.OldFullPath);Enqueue(e.FullPath);};w.Error+=(s,e)=>Interlocked.Exchange(ref overflow,1);w.EnableRaisingEvents=true;watchers.Add(w);}catch(Exception){watcherFailures++;}}
  Sqlite Open(){Directory.CreateDirectory(store);SafePath(store);var db=new Sqlite(dbPath,false);try{db.Exec("PRAGMA journal_mode=WAL");db.Exec("PRAGMA synchronous=FULL");db.Exec("CREATE TABLE IF NOT EXISTS files(scope TEXT,path TEXT COLLATE NOCASE,hash TEXT,entropy REAL,seen INTEGER,PRIMARY KEY(scope,path))");db.Exec("CREATE TABLE IF NOT EXISTS canaries(path TEXT COLLATE NOCASE PRIMARY KEY,hash TEXT NOT NULL)");db.Exec("CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY,path TEXT,change TEXT,severity TEXT,detail TEXT,hash TEXT,first INTEGER,last INTEGER,active INTEGER)");db.Exec("CREATE TABLE IF NOT EXISTS incidents(seq INTEGER PRIMARY KEY AUTOINCREMENT,utc INTEGER,id TEXT,path TEXT,change TEXT,severity TEXT,detail TEXT,hash TEXT)");db.Exec("CREATE INDEX IF NOT EXISTS ep_incidents_utc ON incidents(utc)");db.Exec("CREATE TABLE IF NOT EXISTS quarantine_deletions(id TEXT PRIMARY KEY,path TEXT NOT NULL,hash TEXT NOT NULL,actor TEXT NOT NULL,requested INTEGER NOT NULL,completed INTEGER)");db.Exec("CREATE TABLE IF NOT EXISTS scan_activity(seq INTEGER PRIMARY KEY AUTOINCREMENT,utc INTEGER,path TEXT,source TEXT,result TEXT,durationMs INTEGER,detail TEXT)");db.Exec("CREATE TABLE IF NOT EXISTS endpoint_metadata(name TEXT PRIMARY KEY,value TEXT NOT NULL)");db.Exec("CREATE TABLE IF NOT EXISTS endpoint_stream(id TEXT NOT NULL)");db.Exec("INSERT INTO endpoint_stream SELECT ? WHERE NOT EXISTS (SELECT 1 FROM endpoint_stream)",Guid.NewGuid().ToString("N"));db.Exec("CREATE TABLE IF NOT EXISTS endpoint_outbox(seq INTEGER PRIMARY KEY AUTOINCREMENT,utc INTEGER,id TEXT,path TEXT,change TEXT,severity TEXT,detail TEXT,hash TEXT,active INTEGER)");return db;}catch{db.Dispose();throw;}}
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
  void Activity(Sqlite db,string path,bool full,string result,Stopwatch timer,string detail=""){
   if(result=="Clean")cleanChecks++;else if(result=="Infected")infectedChecks++;else if(result=="Heuristic")heuristicChecks++;else if(result=="Excluded")excludedChecks++;else if(result=="Quarantined"){infectedChecks++;quarantinedChecks++;}else failedChecks++;
   // Fixed-size persistent activity ring; threat incidents and alert outbox are independent.
   db.Exec("INSERT INTO scan_activity(utc,path,source,result,durationMs,detail) VALUES(?,?,?,?,?,?)",History.Now(),path,full?"Scheduled / manual":"Real-time / canary",result,timer.ElapsedMilliseconds,detail.Length>1024?detail.Substring(0,1024):detail);
   db.Exec("DELETE FROM scan_activity WHERE seq<=(SELECT MAX(seq)-1000 FROM scan_activity)");
  }
  void Issue(Sqlite db,string path,string change,string severity,string detail,string hash=""){string id=Id(path+"|"+change);long now=History.Now();var prior=db.Rows("SELECT active,hash,detail,severity FROM findings WHERE id=?",id).FirstOrDefault();bool fresh=prior==null||Convert.ToInt64(prior[0])==0||!Equals(prior[1],hash)||!Equals(prior[3],severity);db.Exec("BEGIN IMMEDIATE");try{if(fresh){db.Exec("INSERT INTO incidents(utc,id,path,change,severity,detail,hash) VALUES(?,?,?,?,?,?,?)",now,id,path,change,severity,detail,hash);db.Exec("INSERT OR REPLACE INTO findings VALUES(?,?,?,?,?,?,?,?,1)",id,path,change,severity,detail,hash,now,now);db.Exec("INSERT INTO endpoint_outbox(utc,id,path,change,severity,detail,hash,active) VALUES(?,?,?,?,?,?,?,1)",now,id,path,change,severity,detail,hash);}else db.Exec("UPDATE findings SET last=?,detail=? WHERE id=?",now,detail,id);db.Exec("COMMIT");}catch{db.Exec("ROLLBACK");throw;}}
  void Resolve(Sqlite db,string path,string change){string id=Id(path+"|"+change);if(db.Rows("SELECT id FROM findings WHERE id=? AND active=1",id).Count==0)return;db.Exec("BEGIN IMMEDIATE");try{db.Exec("INSERT INTO endpoint_outbox(utc,id,path,change,severity,detail,hash,active) SELECT ?,id,path,change,severity,detail,hash,0 FROM findings WHERE id=? AND active=1",History.Now(),id);db.Exec("UPDATE findings SET active=0 WHERE id=?",id);db.Exec("COMMIT");}catch{db.Exec("ROLLBACK");throw;}}
  internal void Publish(Alerts alerts,Config cfg,bool successfulTick){if(!File.Exists(dbPath))return;using(var db=Open()){
   var batch=db.Rows("SELECT seq,utc,id,path,change,severity,detail,hash,active FROM endpoint_outbox ORDER BY seq LIMIT 64");
   if(batch.Count>0){alerts.EndpointTransitions((string)db.Rows("SELECT id FROM endpoint_stream LIMIT 1")[0][0],batch,cfg);db.Exec("DELETE FROM endpoint_outbox WHERE seq<=?",batch.Last()[0]);}
   // Reconcile legacy/orphaned central incident keys only after a complete successful scan
   // and delivery of ALL pending transitions. Never infer recovery from the 200-row UI cap.
   if(reconcilePending&&successfulTick&&cfg.Endpoint.Enabled&&complete&&online&&!running&&db.Rows("SELECT 1 FROM endpoint_outbox LIMIT 1").Count==0){
    var ids=new HashSet<string>(db.Rows("SELECT id FROM findings WHERE active=1").Select(r=>(string)r[0]),StringComparer.Ordinal);
    alerts.ReconcileEndpointFindings(ids);reconcilePending=false;
   }
  }}
  void StartScan(EndpointSettings c){running=true;complete=false;reconcilePending=true;scanId=DateTime.UtcNow.Ticks;pending.Clear();visited.Clear();foreach(var p in c.Paths)pending.Push(p);scanned=excluded=limited=errors=0;}
  void Observe(string p,bool entropy){DateTime now=DateTime.UtcNow;if(changes.Count<MaxEntries)changes[p]=now;if(entropy&&highEntropy.Count<MaxEntries)highEntropy[p]=now;latestChanged=p;}
  void CanaryIssue(Sqlite db,EndpointSettings c,string path,string detail,string hash,WaitHandle stop,Func<bool> authorized){
   string id=Id(path+"|Canary integrity violation");var existing=db.Rows("SELECT hash FROM findings WHERE id=? AND active=1",id).FirstOrDefault();bool fresh=existing==null||!Equals(existing[0],hash);
   Issue(db,path,"Canary integrity violation","critical",detail+(fresh?" "+Correlate(c,path):""),hash);
   if(fresh&&c.Mode=="contain"&&authorized())try{var a=EndpointResponse.FindWriter(path);if(a==null)throw new IOException("No matching write audit record");string result=EndpointResponse.Contain(c,a,stop,authorized);Issue(db,a.Image,"Containment action","info",result);Resolve(db,a.Image,"Containment action");}catch(Exception ex){Issue(db,path,"Containment withheld","warning",ex.Message);}
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
  void CheckFile(Sqlite db,EndpointSettings c,string p,WaitHandle stop,Func<bool> authorized,bool full){
   var activityTimer=Stopwatch.StartNew();
   if(!c.Paths.Any(x=>Under(p,x)))return;if(Excluded(c,p)){if(full)excluded++;Activity(db,p,full,"Excluded",activityTimer,"Excluded by policy");return;}bool canary=c.CanaryPaths.Contains(p,StringComparer.OrdinalIgnoreCase);
   try{bool fixedCanary=canary&&CanaryTemplates.ExpectedForPath(p)!=null;
    if(!fixedCanary)SafePath(p);var attr=File.GetAttributes(p);
    if(fixedCanary&&(attr&(FileAttributes.Directory|FileAttributes.ReparsePoint))!=0)throw new IOException("Invalid fixed canary file type.");if((attr&FileAttributes.Directory)!=0){if(full)foreach(var child in Directory.EnumerateFileSystemEntries(p)){if(pending.Count>=MaxEntries)throw new IOException("Traversal limit");pending.Push(child);}else {nextScan=0;if(running)rescan=true;}return;}
    using(var file=new FileStream(p,FileMode.Open,FileAccess.Read,FileShare.Read)){if(fixedCanary)EndpointResponse.VerifyHandle(file.SafeFileHandle,p);if(file.Length>c.MaxFileMiB*1048576L){
     if(canary&&CanaryTemplates.ExpectedForPath(p)!=null)CanaryIssue(db,c,p,"Canary size exceeds scan limit and differs from the fixed original.","",stop,authorized);if(full)limited++;Issue(db,p,"File scan limited","warning","File exceeds configured size cap; not verified.");Activity(db,p,full,"Limited",activityTimer,"Size cap exceeded");return;}
     byte[] b=new byte[65536];int n=0,r;while(n<b.Length&&(r=file.Read(b,n,b.Length-n))>0)n+=r;double entropy=Entropy(b,n);file.Position=0;string hash=FileHash(file);file.Position=0;
     var old=db.Rows("SELECT hash,entropy FROM files WHERE scope=? AND path=?",scope,p).FirstOrDefault();if(old!=null&&!Equals(old[0],hash))Observe(p,n>=4096&&entropy>=7.5&&entropy-Convert.ToDouble(old[1])>=1.0);else if(old==null&&!full)Observe(p,false);
     db.Exec("INSERT OR REPLACE INTO files VALUES(?,?,?,?,?)",scope,p,hash,entropy,running?scanId:0);
     Resolve(db,p,"File scan limited");Resolve(db,p,"File scan error");
     if(canary){var baseline=db.Rows("SELECT hash FROM canaries WHERE path=?",p).FirstOrDefault();string expected=CanaryTemplates.ExpectedForPath(p);
      if(baseline==null){db.Exec("INSERT INTO canaries VALUES(?,?)",p,expected??hash);AppJournal.Event(LogLevel.Info,"Endpoint","canary-enroll","Recorded canary baseline: "+p);}
      else if(expected==null)expected=(string)baseline[0];
      if(expected!=null&&!Equals(expected,hash))CanaryIssue(db,c,p,"Canary content changed.",hash,stop,authorized);else if(expected!=null&&baseline!=null&&!Equals(baseline[0],expected))Issue(db,p,"Canary integrity violation","critical","Stored setup canary baseline differs from the original template.",hash);else {Resolve(db,p,"Canary integrity violation");Resolve(db,p,"Containment withheld");}}
     Resolve(db,p,"Protected path unavailable");if(!online){Activity(db,p,full,"Unavailable",activityTimer,"ClamAV offline; no signature verdict");return;}string reply=Command(c.Port,"INSTREAM",file,stop);if(Malware(reply)||reply.EndsWith(": OK",StringComparison.Ordinal)){lastFileScan=History.Now();lastScannedPath=p;if(!full){realTimeChecked++;lastRealTimeScan=lastFileScan;}}if(Malware(reply)){bool quarantined=false;bool heuristic=reply.IndexOf("Heuristics.",StringComparison.OrdinalIgnoreCase)>=0;Issue(db,p,heuristic?"Heuristic signature finding":"Malware signature detected",heuristic?"warning":"critical",reply,hash);file.Dispose();if(!heuristic&&c.Mode!="monitor"&&authorized()&&ResponseRetryAllowed(db,p,hash)&&c.ResponsePaths.Any(x=>Under(p,x))&&EndpointResponse.SafeScope(p)){try{string detail;lock(vaultGate)detail=EndpointResponse.Quarantine(store,c,p,hash,stop,authorized);Issue(db,p,"Malware quarantined","info",detail,hash);Resolve(db,p,"Malware quarantined");Resolve(db,p,"Quarantine withheld or failed");quarantined=true;ResolveQuarantinedOriginal(db,p,hash);}catch(Exception ex){Issue(db,p,"Quarantine withheld or failed","warning",ex.GetType().Name+": "+ex.Message,hash);}}Activity(db,p,full,quarantined?"Quarantined":heuristic?"Heuristic":"Infected",activityTimer,reply);}else if(reply.EndsWith(": OK",StringComparison.Ordinal)){Activity(db,p,full,"Clean",activityTimer,reply);Resolve(db,p,"Malware signature detected");Resolve(db,p,"Heuristic signature finding");Resolve(db,p,"Quarantine withheld or failed");Resolve(db,p,"Engine scan incomplete");}else {if(full)errors++;Issue(db,p,"Engine scan incomplete","warning",reply);Activity(db,p,full,"Failed",activityTimer,reply);}if(full)scanned++;
    }
   }catch(FileNotFoundException){Missing(db,c,p,canary,full,stop,authorized);Activity(db,p,full,"Missing",activityTimer,"File no longer present");}catch(DirectoryNotFoundException){Missing(db,c,p,canary,full,stop,authorized);Activity(db,p,full,"Missing",activityTimer,"Directory no longer present");}catch(OperationCanceledException){throw;}catch(Exception ex){if(full)errors++;Issue(db,p,"File scan error","warning",ex.GetType().Name+": "+ex.Message);Activity(db,p,full,"Failed",activityTimer,ex.GetType().Name);}
  }
  void Missing(Sqlite db,EndpointSettings c,string p,bool canary,bool full,WaitHandle stop,Func<bool> authorized){if(canary)CanaryIssue(db,c,p,"Canary missing.","",stop,authorized);if(full&&c.Paths.Contains(p,StringComparer.OrdinalIgnoreCase)){errors++;Issue(db,p,"Protected path unavailable","warning","Configured path missing; scan incomplete.");}else if(db.Rows("SELECT path FROM files WHERE scope=? AND path=?",scope,p).Count>0){Observe(p,false);db.Exec("DELETE FROM files WHERE scope=? AND path=?",scope,p);Resolve(db,p,"File scan limited");Resolve(db,p,"File scan error");Resolve(db,p,"Engine scan incomplete");Resolve(db,p,"Malware signature detected");Resolve(db,p,"Heuristic signature finding");Resolve(db,p,"Quarantine withheld or failed");}}
  // Only verified absence of the original closes its malware finding. A vault purge
  // never clears an unrelated, recurrent, inaccessible or still-present threat.
  static bool ConfirmAbsent(string path){try{File.GetAttributes(path);return false;}catch(FileNotFoundException){return true;}catch(DirectoryNotFoundException){return true;}catch(Exception){return false;}}
  void ResolveQuarantinedOriginal(Sqlite db,string path,string hash){
   if(!db.Rows("SELECT 1 FROM findings WHERE path=? COLLATE NOCASE AND hash=? AND active=1 AND change IN ('Malware signature detected','Quarantine withheld or failed') LIMIT 1",path,hash).Any()||!ConfirmAbsent(path))return;
   db.Exec("BEGIN IMMEDIATE");try{
    foreach(var change in new[]{"Malware signature detected","Quarantine withheld or failed"}){
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
  string Correlate(EndpointSettings c,string p){if(!c.ProcessCorrelation)return "Process attribution disabled.";try{var a=EndpointResponse.FindWriter(p);auditStatus=a==null?"No matching audit evidence":"Matching Windows audit event";return a==null?"No matching write audit event.":"Windows 4663: "+a.Image+" PID "+a.Pid+" record "+a.Record+" (correlation, not proof).";}catch(Exception){auditStatus="Unavailable: check Security log permissions and SACL";return auditStatus;}}
  void Behavior(Sqlite db,EndpointSettings c,WaitHandle stop,Func<bool> authorized){DateTime cutoff=DateTime.UtcNow.AddSeconds(-c.BehaviorWindowSeconds);foreach(var p in changes.Where(x=>x.Value<cutoff).Select(x=>x.Key).ToArray())changes.Remove(p);foreach(var p in highEntropy.Where(x=>x.Value<cutoff).Select(x=>x.Key).ToArray())highEntropy.Remove(p);bool suspect=changes.Count>=c.ChangeThreshold;bool critical=suspect&&highEntropy.Count>=Math.Max(3,c.ChangeThreshold/5);if(suspect){bool newIncident=db.Rows("SELECT active FROM findings WHERE id=? AND active=1",Id("Protected paths|Possible ransomware activity")).Count==0;string detail=changes.Count+" distinct changed files; "+highEntropy.Count+" entropy increases in "+c.BehaviorWindowSeconds+" seconds. "+(newIncident?Correlate(c,latestChanged):"Investigate legitimate bulk activity.");Issue(db,"Protected paths","Possible ransomware activity",critical?"critical":"warning",detail);if(critical&&newIncident&&c.Mode=="contain"&&authorized())try{var a=EndpointResponse.FindWriter(latestChanged);if(a==null)throw new IOException("No matching write audit record");string result=EndpointResponse.Contain(c,a,stop,authorized);Issue(db,a.Image,"Containment action","info",result);Resolve(db,a.Image,"Containment action");}catch(Exception ex){Issue(db,"Protected paths","Containment withheld","warning",ex.Message);}}else{Resolve(db,"Protected paths","Possible ransomware activity");Resolve(db,"Protected paths","Containment withheld");}}
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
  internal object Tick(EndpointSettings c,WaitHandle stop,bool force,Func<bool> authorized){string next=Config.Json().Serialize(c);if(policy!=next){Configure(c);policy=next;}if(!c.Enabled)return new {status="disabled",items=new object[0]};using(var db=Open()){
   var maintenance=ClamUpdateState.Read();string maintenanceKey=(maintenance.attemptUtc??"")+"/"+maintenance.status;
   if(maintenanceKey!=signatureMaintenanceSeen){
    if(maintenance.status=="Failed"||maintenance.status=="Warning"||maintenance.status=="Interrupted")Issue(db,"ClamAV","Signature update needs review","warning",(maintenance.detail??"Signature update did not complete.")+" · Attempt UTC: "+(maintenance.attemptUtc??"Unknown"));
    else if(maintenance.status=="Updated"||maintenance.status=="Checked"){Resolve(db,"ClamAV","Signature update needs review");AppJournal.Event(LogLevel.Info,"Endpoint","signatures",maintenance.detail);lastEngine=0;if(maintenance.status=="Updated"){nextScan=0;if(running)rescan=true;}}
    signatureMaintenanceSeen=maintenanceKey;
   }
   long now=History.Now();object signatureSchedule;
   try{signatureSchedule=ScheduledSignatures(db,c,maintenance,now,authorized);Resolve(db,"ClamAV","Signature schedule unavailable");}
   catch(Exception ex){signatureSchedule=new {enabled=c.SignatureScheduleEnabled,frequency=c.SignatureScheduleFrequency,localTime=c.SignatureScheduleTime,weekday=c.SignatureScheduleWeekday,monthDay=c.SignatureScheduleMonthDay,timeZone=TimeZoneInfo.Local.Id,status="Schedule unavailable; review alerts",nextRunUtc=(string)null,lastScheduledRequestUtc=(string)null};Issue(db,"ClamAV","Signature schedule unavailable","warning","Scheduled signature maintenance could not be evaluated: "+ex.GetType().Name);}
   if(lastSignatureLogCheck==0||now-lastSignatureLogCheck>=60){lastSignatureLogCheck=now;
    var prior=db.Rows("SELECT value FROM endpoint_metadata WHERE name='reported_signature_update'").FirstOrDefault();reportedUpdateUtc=prior==null?null:(string)prior[0];
    try{string reported=ClamUpdateWorker.ReadReportedUpdate();signatureLogReadable=reported!=null;
     if(reported!=null&&(reportedUpdateUtc==null||string.CompareOrdinal(reported,reportedUpdateUtc)>0)){reportedUpdateUtc=reported;db.Exec("INSERT OR REPLACE INTO endpoint_metadata(name,value) VALUES('reported_signature_update',?)",reported);}
    }catch(Exception){signatureLogReadable=false;}
   }
   if(force||lastEngine==0||now-lastEngine>=60){lastEngine=now;bool previouslyOnline=online;try{version=Command(c.Port,"VERSION",null,stop);online=version.StartsWith("ClamAV",StringComparison.OrdinalIgnoreCase);if(!online)throw new IOException("Unexpected engine version");lastSignatureCheck=History.Now();signatureFreshness="Unknown";Resolve(db,"ClamAV","Engine unavailable");if(!previouslyOnline){nextScan=0;reconcilePending=true;if(running)rescan=true;}var parts=version.Split('/');signatureVersion=parts.Length>=2?parts[1]:"Unknown";signatureTimestamp=parts.Length>=3?parts[2]:"Unknown";DateTime stamp;if(DateTime.TryParseExact(Regex.Replace(signatureTimestamp,@"\s+"," "),"ddd MMM d HH:mm:ss yyyy",System.Globalization.CultureInfo.InvariantCulture,System.Globalization.DateTimeStyles.None,out stamp)&&stamp<DateTime.Now.AddDays(1)){if((DateTime.Now-stamp).TotalDays>=3){signatureFreshness="Stale";Issue(db,"ClamAV","Signature database may be stale","warning","Engine-reported definition date is more than three days old: "+signatureTimestamp);}else{signatureFreshness="Current";Resolve(db,"ClamAV","Signature database may be stale");}}}catch(OperationCanceledException){throw;}catch(Exception ex){online=false;version="Unavailable";signatureVersion=signatureTimestamp=signatureFreshness="Unknown";Issue(db,"ClamAV","Engine unavailable","warning",ex.GetType().Name);}}
   CheckResponseReadiness(db,c,stop,now,force);
   if(Interlocked.Exchange(ref overflow,0)!=0){seenOverflow++;nextScan=0;rescan=true;Issue(db,"Protected paths","Real-time queue overflow","warning","Events may have been missed; full reconciliation requested.");}if(watcherFailures>0)Issue(db,"Protected paths","Watcher coverage incomplete","warning",watcherFailures+" configured watchers unavailable; periodic scanning continues.");else Resolve(db,"Protected paths","Watcher coverage incomplete");
   string p;int drain=0;while(drain++<2048&&queue.TryDequeue(out p)){Interlocked.Decrement(ref queued);if(!deferred.ContainsKey(p)){if(deferred.Count<MaxQueue)deferred[p]=DateTime.UtcNow;else Interlocked.Exchange(ref overflow,1);}}
   if(force){nextScan=0;if(running)rescan=true;}if(!running&&now>=nextScan){rescan=false;StartScan(c);}
   var timer=Stopwatch.StartNew();if(now-lastCanary>=10){lastCanary=now;foreach(string canary in c.CanaryPaths.Take(100)){if(stop.WaitOne(0))throw new OperationCanceledException();if(deferred.Count<MaxQueue&&!deferred.ContainsKey(canary))deferred[canary]=DateTime.UtcNow.AddSeconds(-2);}}foreach(var item in deferred.Where(x=>(DateTime.UtcNow-x.Value).TotalMilliseconds>=750).Take(8).ToArray()){if(stop.WaitOne(0))throw new OperationCanceledException();deferred.Remove(item.Key);CheckFile(db,c,item.Key,stop,authorized,false);if(timer.ElapsedMilliseconds>1200)break;}
   int count=0;while(running&&pending.Count>0&&count++<16&&timer.ElapsedMilliseconds<1500){if(stop.WaitOne(0))throw new OperationCanceledException();p=pending.Pop();if(!visited.Add(p))continue;if(visited.Count>MaxEntries){errors++;pending.Clear();break;}CheckFile(db,c,p,stop,authorized,true);}
   if(running&&pending.Count==0){running=false;lastScan=History.Now();nextScan=rescan?lastScan:lastScan+c.IntervalSeconds;complete=errors==0&&limited==0&&online;if(complete){foreach(var missing in db.Rows("SELECT path FROM files WHERE scope=? AND seen<>? LIMIT 100001",scope,scanId)){string path=(string)missing[0];if(!Excluded(c,path)){Observe(path,false);if(c.CanaryPaths.Contains(path,StringComparer.OrdinalIgnoreCase))CanaryIssue(db,c,path,"Canary missing during reconciliation.","",stop,authorized);}db.Exec("DELETE FROM files WHERE scope=? AND path=?",scope,path);Resolve(db,path,"Malware signature detected");Resolve(db,path,"Heuristic signature finding");Resolve(db,path,"File scan error");Resolve(db,path,"File scan limited");Resolve(db,path,"Engine scan incomplete");Resolve(db,path,"Quarantine withheld or failed");}if(!rescan)Resolve(db,"Protected paths","Real-time queue overflow");Resolve(db,"Protected paths","Scan incomplete");}else Issue(db,"Protected paths","Scan incomplete","warning",errors+" errors; "+limited+" size-limited files; engine online: "+online);AppJournal.Event(LogLevel.Info,"Endpoint","scan","Scanned "+scanned+"; excluded "+excluded+"; errors "+errors+"; limited "+limited);}
   Behavior(db,c,stop,authorized);object[] vaultItems;bool vaultAvailable=true;try{vaultItems=QuarantineInventory(db);Resolve(db,"Quarantine vault","Quarantine inventory unavailable");}catch(Exception ex){vaultAvailable=false;vaultItems=new object[0];Issue(db,"Quarantine vault","Quarantine inventory unavailable","warning",ex.GetType().Name);}
   // Reconcile completed quarantine and deletion evidence only when the original
   // path is verifiably absent and the finding has the identical recorded hash.
   if(vaultAvailable&&online){
    foreach(var entry in vaultItems.OfType<Dictionary<string,object>>().Where(x=>x.ContainsKey("state")&&Equals(x["state"],"quarantined")))
     ResolveQuarantinedOriginal(db,Convert.ToString(entry["path"]),Convert.ToString(entry["sha256"]));
    foreach(var receipt in db.Rows("SELECT q.path,q.hash FROM quarantine_deletions q JOIN findings f ON f.path=q.path COLLATE NOCASE AND f.hash=q.hash WHERE q.completed IS NOT NULL AND f.active=1 AND f.change IN ('Malware signature detected','Quarantine withheld or failed') LIMIT 200"))
     ResolveQuarantinedOriginal(db,(string)receipt[0],(string)receipt[1]);
   }
   var active=db.Rows("SELECT id,path,change,severity,detail,hash,first,last FROM findings WHERE active=1 ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END,last DESC LIMIT 201");var history=db.Rows("SELECT utc,path,change,severity,detail,hash FROM incidents ORDER BY seq DESC LIMIT 100");return new {status=!online?"unavailable":active.Count>200||watcherFailures>0||(!running&&!complete)?"partial":running?"scanning":"ok",engineVersion=version,engineOnline=online,signatureDatabaseVersion=signatureVersion,signatureDatabaseTimestamp=signatureTimestamp,signatureFreshness=signatureFreshness,signatureMaintenance=maintenance,signatureSchedule=signatureSchedule,lastSuccessfulSignatureUpdateUtc=maintenance.updatedUtc,lastSuccessfulSignatureRefreshUtc=maintenance.checkedUtc,lastReportedSignatureUpdateUtc=reportedUpdateUtc,signatureUpdateLogRecognized=signatureLogReadable,lastSignatureCheckUtc=lastSignatureCheck==0?null:Telemetry.Utc(lastSignatureCheck),cleanChecks=cleanChecks,infectedChecks=infectedChecks,heuristicChecks=heuristicChecks,excludedChecks=excludedChecks,failedChecks=failedChecks,quarantinedChecks=quarantinedChecks,scanActivityLimit=100,scanActivity=db.Rows("SELECT utc,path,source,result,durationMs,detail FROM scan_activity ORDER BY seq DESC LIMIT 100").Select(x=>new {utc=Telemetry.Utc(Convert.ToInt64(x[0])),path=x[1],source=x[2],result=x[3],durationMs=x[4],detail=x[5]}).ToArray(),canaries=c.CanaryPaths.Select(path=>{var baseline=db.Rows("SELECT hash FROM canaries WHERE path=?",path).FirstOrDefault();var issue=db.Rows("SELECT change,severity,last FROM findings WHERE path=? COLLATE NOCASE AND active=1 AND change IN ('Canary integrity violation','File scan error','File scan limited') ORDER BY CASE severity WHEN 'critical' THEN 0 ELSE 1 END LIMIT 1",path).FirstOrDefault();return new {path=path,expectedHash=CanaryTemplates.ExpectedForPath(path)??(baseline==null?null:(string)baseline[0]),status=issue!=null?(string)issue[1]:baseline==null?"Pending baseline":"Enrolled",detail=issue==null?"No active canary finding recorded":(string)issue[0]};}).ToArray(),mode=c.Mode,responseEngineStatus=responseEngineStatus,responseEngineDetail=responseEngineDetail,responseCheckedUtc=lastResponseCheck==0?null:Telemetry.Utc(lastResponseCheck),responsePathsReadiness=responsePathsReadiness,realTime=c.RealTime,watcherCount=watchers.Count,queueDepth=queued+deferred.Count,overflowCount=seenOverflow,scanRunning=running,scanStartedUtc=scanId==0?null:new DateTime(scanId,DateTimeKind.Utc).ToString("o"),realTimeChecked=realTimeChecked,lastFileScanUtc=lastFileScan==0?null:Telemetry.Utc(lastFileScan),lastRealTimeScanUtc=lastRealTimeScan==0?null:Telemetry.Utc(lastRealTimeScan),lastScannedPath=lastScannedPath,lastScanUtc=lastScan==0?null:Telemetry.Utc(lastScan),nextScanUtc=running?null:Telemetry.Utc(nextScan),scannedFiles=scanned,excludedEntries=excluded,sizeLimitedFiles=limited,changedFiles=changes.Count,entropyChanges=highEntropy.Count,canaryCount=c.CanaryPaths.Length,processCorrelation=auditStatus,violations=Convert.ToInt64(db.Rows("SELECT COUNT(*) FROM findings WHERE active=1 AND severity IN ('critical','warning')")[0][0]),protectedPaths=c.Paths,truncated=active.Count>200,historyLimit=100,activeMalware=Convert.ToInt64(db.Rows("SELECT COUNT(*) FROM findings WHERE active=1 AND change='Malware signature detected'")[0][0]),activeHeuristic=Convert.ToInt64(db.Rows("SELECT COUNT(*) FROM findings WHERE active=1 AND change='Heuristic signature finding'")[0][0]),activeScanIssues=Convert.ToInt64(db.Rows("SELECT COUNT(*) FROM findings WHERE active=1 AND change IN ('File scan error','File scan limited','Engine scan incomplete','Scan incomplete','Protected path unavailable','Engine unavailable','Watcher coverage incomplete','Real-time queue overflow')")[0][0]),quarantineCount=vaultAvailable?(long?)vaultItems.Length:null,quarantineDeletedCount=Convert.ToInt64(db.Rows("SELECT COUNT(*) FROM quarantine_deletions WHERE completed IS NOT NULL")[0][0]),quarantineItems=vaultItems.Take(100).ToArray(),quarantineDeletions=DeletionHistory(db),pendingAlertDelivery=Convert.ToInt64(db.Rows("SELECT COUNT(*) FROM endpoint_outbox")[0][0]),items=active.Take(200).Select(x=>new {id=x[0],path=x[1],change=x[2],severity=x[3],status=x[3],detail=x[4],actualHash=x[5],firstUtc=Telemetry.Utc(Convert.ToInt64(x[6])),lastUtc=Telemetry.Utc(Convert.ToInt64(x[7]))}).ToArray(),recentIncidents=history.Select(x=>new {utc=Telemetry.Utc(Convert.ToInt64(x[0])),path=x[1],change=x[2],severity=x[3],detail=x[4],hash=x[5]}).ToArray()};}}
  public void Dispose(){CloseWatchers();}
 }
}
