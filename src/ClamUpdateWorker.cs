using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

using System.Security.Cryptography;
namespace LinkScope {
    // Only the installed, administrator-owned executable runs the scheduled maintenance worker.
    // No browser inputs, configuration parameters, executable paths or URLs cross this boundary.
    internal sealed class ClamUpdateState {
        public string status {get;set;}
        public string attemptUtc {get;set;}
        public string checkedUtc {get;set;}
        public string updatedUtc {get;set;}
        public string detail {get;set;}
        internal const string DefinitionReview="FreshClam completed; loaded official definitions are stale, unknown, or awaiting reload. Review official download and reload logs.";
        internal const string ReloadReview="A newer daily archive may be on disk, but ClamD has not confirmed the expected loaded version. Review reload status.";
        internal bool DefinitionOnlyWarning {get{return status=="Warning"&&detail==DefinitionReview;}}
        internal bool CanReconcileDefinitionWarning(bool online,string freshness,long checkedEpoch,long now){
            DateTime attempt,download;
            if(!DefinitionOnlyWarning||!online||freshness!="Current"||checkedEpoch<=0||checkedEpoch>now||now-checkedEpoch>90)return false;
            if(!DateTime.TryParseExact(attemptUtc,"o",CultureInfo.InvariantCulture,DateTimeStyles.RoundtripKind,out attempt)||!DateTime.TryParseExact(checkedUtc,"o",CultureInfo.InvariantCulture,DateTimeStyles.RoundtripKind,out download)||attempt.Kind!=DateTimeKind.Utc||download.Kind!=DateTimeKind.Utc||download<attempt)return false;
            return checkedEpoch>new DateTimeOffset(download).ToUnixTimeSeconds();
        }
        const string Key=@"SOFTWARE\IBSoft\LinkScope\SignatureMaintenance";
        static string Now(){return DateTime.UtcNow.ToString("o",CultureInfo.InvariantCulture);}
        static bool Trusted(SecurityIdentifier sid){return sid!=null&&(sid.IsWellKnown(WellKnownSidType.LocalSystemSid)||sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)||sid.Value=="S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");}
        static void ValidateKey(RegistryKey key){var acl=key.GetAccessControl();if(!Trusted(acl.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier))throw new UnauthorizedAccessException("Signature maintenance registry owner is not trusted.");var mask=RegistryRights.SetValue|RegistryRights.CreateSubKey|RegistryRights.Delete|RegistryRights.ChangePermissions|RegistryRights.TakeOwnership;foreach(RegistryAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier)))if(rule.AccessControlType==AccessControlType.Allow&&(rule.PropagationFlags&PropagationFlags.InheritOnly)==0&&(rule.RegistryRights&mask)!=0&&!Trusted(rule.IdentityReference as SecurityIdentifier))throw new UnauthorizedAccessException("Signature maintenance registry permissions are not trusted.");}
        internal static ClamUpdateState Read(){try{using(var hive=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64))using(var key=hive.OpenSubKey(Key)){if(key==null)return new ClamUpdateState{status="Not recorded"};ValidateKey(key);string[] values=Convert.ToString(key.GetValue("State","")).Split('|');if(values.Length!=5)return new ClamUpdateState{status="Not recorded"};var s=new ClamUpdateState{status=values[0],attemptUtc=values[1],checkedUtc=values[2],updatedUtc=values[3],detail=values[4]};if(s.status=="Running"&&s.AttemptAge.TotalMinutes>35){s.status="Interrupted";s.detail="Previous update did not report completion. Check the FreshClam service and logs.";}return s;}}catch{return new ClamUpdateState{status="Unavailable",detail="Cannot read trusted maintenance status."};}}
        internal TimeSpan AttemptAge {get{DateTime stamp;return DateTime.TryParse(attemptUtc,CultureInfo.InvariantCulture,DateTimeStyles.RoundtripKind,out stamp)?DateTime.UtcNow-stamp.ToUniversalTime():TimeSpan.MaxValue;}}
        internal bool Busy {get{return status=="Running"&&AttemptAge.TotalMinutes<=35;}}
        internal bool CoolingDown {get{return AttemptAge.TotalMinutes<60;}}
        void Save(){using(var hive=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64)){
            // Protected state is never writable by the monitoring service or ordinary users.
            var admin=new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null);var sec=new RegistrySecurity();sec.SetOwner(admin);sec.SetAccessRuleProtection(true,false);foreach(var sid in new[]{admin,new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null)})sec.AddAccessRule(new RegistryAccessRule(sid,RegistryRights.FullControl,AccessControlType.Allow));sec.AddAccessRule(new RegistryAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid,null),RegistryRights.ReadKey,AccessControlType.Allow));
            // Check existing ancestors before creating the child. No ACL takeover of unexpected keys.
            foreach(string parent in new[]{@"SOFTWARE\IBSoft",@"SOFTWARE\IBSoft\LinkScope",Key})using(var existing=hive.OpenSubKey(parent)){if(existing!=null)ValidateKey(existing);}
            using(var key=hive.CreateSubKey(Key,RegistryKeyPermissionCheck.ReadWriteSubTree,RegistryOptions.None,sec)){ValidateKey(key);key.SetValue("State",string.Join("|",new[]{status??"",attemptUtc??"",checkedUtc??"",updatedUtc??"",detail??""}),RegistryValueKind.String);key.Flush();}
        }}
        internal static ProviderUpdateView[] ReadProviders(){
            try{using(var hive=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64))using(var key=hive.OpenSubKey(Key)){
                if(key==null)return null;ValidateKey(key);var value=key.GetValue("ProviderSummary") as string;if(value==null||value.Length>131072)return null;
                return new System.Web.Script.Serialization.JavaScriptSerializer().Deserialize<ProviderUpdateView[]>(value);
            }}catch{return null;}
        }
        internal static void PublishProviders(ProviderUpdateView[] rows){
            // Create the trusted public status key using the existing ACL workflow.
            var state=Read();state.Save();
            using(var hive=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64))using(var key=hive.OpenSubKey(Key,true)){
                ValidateKey(key);key.SetValue("ProviderSummary",new System.Web.Script.Serialization.JavaScriptSerializer().Serialize(rows),RegistryValueKind.String);key.Flush();
            }
        }
        internal void Begin(){attemptUtc=Now();status="Running";detail="FreshClam update running.";Save();}
        internal void DownloadCompleted(bool changed){checkedUtc=Now();if(changed)updatedUtc=checkedUtc;status="Running";detail=changed?"Database contents changed; verifying engine and updater.":"FreshClam completed with no database content change.";Save();}
        internal void RecordChanged(){updatedUtc=Now();Save();}
        internal void Finish(string state,string message){status=state;detail=message;Save();}
        internal static void RecordProvisioning(bool changed){var s=Read();s.attemptUtc=Now();s.checkedUtc=s.attemptUtc;if(changed)s.updatedUtc=s.checkedUtc;s.Finish(changed?"Updated":"Checked",changed?"Setup downloaded changed signature database contents.":"Setup completed a signature check with no database content change.");}
    }
    // Host-local administrator supplies URLs. Never send URL paths or queries to telemetry.
    internal static class ClamProviderSources {
        internal static readonly string[] Extensions={".ndb",".ldb",".hdb",".hsb",".mdb",".msb",".pdb",".gdb",".wdb",".ign2",".yar",".yara"};
        internal static bool TryParse(string value,out Uri uri){
            uri=null;if(string.IsNullOrEmpty(value)||value.Length>4096||value.Any(ch=>char.IsWhiteSpace(ch)||char.IsControl(ch)||ch=='"'||ch=='\''||ch=='\\'||ch=='#'))return false;
            Uri parsed;if(!Uri.TryCreate(value,UriKind.Absolute,out parsed)||parsed.Scheme!=Uri.UriSchemeHttps||parsed.HostNameType!=UriHostNameType.Dns||parsed.IsLoopback||!parsed.IsDefaultPort||parsed.UserInfo.Length!=0||parsed.Fragment.Length!=0)return false;
            string name=Path.GetFileName(parsed.AbsolutePath);if(!Regex.IsMatch(name,@"^[A-Za-z0-9][A-Za-z0-9_.-]{0,126}$")||!Extensions.Contains(Path.GetExtension(name),StringComparer.OrdinalIgnoreCase))return false;
            // Avoid filename collisions with the official signature archives and Windows device names.
            string stem=name.Split('.')[0];if(new[]{"main","daily","bytecode","con","prn","aux","nul"}.Contains(stem,StringComparer.OrdinalIgnoreCase)||Regex.IsMatch(stem,@"^(COM|LPT)[0-9]$",RegexOptions.IgnoreCase))return false;
            uri=parsed;return true;
        }
        internal static string Name(Uri uri){return Path.GetFileName(uri.AbsolutePath);}
        internal static bool Suppresses(Uri uri){return new[]{".ign2",".wdb"}.Contains(Path.GetExtension(Name(uri)),StringComparer.OrdinalIgnoreCase);}
        internal static string Label(Uri uri){return uri.DnsSafeHost+" / "+Name(uri);}
        internal static List<string> ParseInput(string text){
            if(text==null||text.Length>262144)throw new InvalidDataException("Input exceeds the signature source size limit.");
            var result=new List<string>();var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);int number=0;
            foreach(var raw in text.Split(new[]{"\r\n","\n","\r"},StringSplitOptions.None)){
                number++;string line=raw.Trim();if(line.Length==0||line.StartsWith("#",StringComparison.Ordinal))continue;
                const string directive="DatabaseCustomURL";
                if(line.StartsWith(directive,StringComparison.OrdinalIgnoreCase)&&line.Length>directive.Length&&char.IsWhiteSpace(line[directive.Length]))line=line.Substring(directive.Length).Trim();
                Uri uri;if(!TryParse(line,out uri))throw new InvalidDataException("Invalid or unsupported HTTPS signature source on line "+number+". No URL was logged.");
                if(!names.Add(Name(uri)))throw new InvalidDataException("Duplicate database filename on line "+number+".");
                result.Add(line);if(result.Count>100)throw new InvalidDataException("At most 100 custom databases may be configured.");
            }return result;
        }
        internal static bool ValidSet(IEnumerable<string> feeds){var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);int n=0;foreach(string feed in feeds){Uri uri;if(++n>100||!TryParse(feed,out uri)||!names.Add(Name(uri)))return false;}return true;}
    }
    public sealed class ProviderUpdateView {
        public string provider {get;set;} public int files {get;set;} public int intervalHours {get;set;}
        public string nextUtc {get;set;} public string lastAttemptUtc {get;set;} public string lastSuccessUtc {get;set;} public string status {get;set;}
    }
    internal sealed class ProviderPolicyEntry {
        public ProviderPolicyEntry(){}
        public string Url {get;set;} public int Hours {get;set;} public long Next {get;set;} public long Attempt {get;set;} public long Success {get;set;} public string Status {get;set;}
    }
    internal static partial class ClamUpdateWorker {
        static readonly string ProgramFiles=Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
    const int ClamPort = 3310;
    const int ClamMissing = 3, ClamUnconfigured = 4, ClamNotReady = 5,
        ClamCustom = 6, ClamUpdaterNotReady = 7, ClamPartial = 8, ClamStale = 9;
    static readonly string ClamRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ClamAV");
    static readonly string ClamDatabase = Path.Combine(ClamRoot, "database");
    static readonly string ClamdExe = Path.Combine(ClamRoot, "clamd.exe");
    static readonly string FreshExe = Path.Combine(ClamRoot, "freshclam.exe");
    static readonly string ClamdConfig = Path.Combine(ClamRoot, "clamd.conf");
    static readonly string FreshConfig = Path.Combine(ClamRoot, "freshclam.conf");
    static bool SamePath(string a, string b) {
        try { return String.Equals(Path.GetFullPath(a).TrimEnd('\\'), Path.GetFullPath(b).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase); }
        catch (Exception) { return false; }
    }
    static bool StandardRegistryPaths(TextWriter log) {
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 }) {
            using (var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view))
            using (var key = hive.OpenSubKey(@"SOFTWARE\ClamAV")) {
                if (key == null) continue;
                foreach (var entry in new[] { new { Name="ConfDir", Path=ClamRoot }, new { Name="DataDir", Path=ClamDatabase } }) {
                    string value = Convert.ToString(key.GetValue(entry.Name));
                    if (!String.IsNullOrWhiteSpace(value) && !SamePath(value, entry.Path)) {
                        log.WriteLine("Custom ClamAV registry " + entry.Name + " detected. No changes will be made to this installation.");
                        return false;
                    }
                }
            }
        }
        // ClamAV also falls back to C:\ClamAV. Do not take over a legacy installation.
        string legacy = Path.Combine(Path.GetPathRoot(ClamRoot), "ClamAV");
        if (File.Exists(Path.Combine(legacy,"clamd.conf")) || File.Exists(Path.Combine(legacy,"freshclam.conf")) || File.Exists(Path.Combine(legacy,"clamd.exe"))) {
            log.WriteLine("Legacy/portable ClamAV installation detected. Review manually."); return false;
        }
        return true;
    }
    static string ServiceImage(string service) {
        using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + service))
            return k == null ? null : Convert.ToString(k.GetValue("ImagePath"));
    }
    static bool NativeService(string name, string exe) {
        string image = ServiceImage(name);
        if (image == null) return true; // not yet registered
        // Only the native ClamAV service command and its default config search order.
        string expected = "\"" + exe + "\" --daemon --service-mode";
        return String.Equals(image.Trim(), expected, StringComparison.OrdinalIgnoreCase) || (exe.IndexOf(' ')<0 && String.Equals(image.Trim(),exe+" --daemon --service-mode",StringComparison.OrdinalIgnoreCase));
    }
    static bool AutoService(string name) {
        using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + name))
            return k != null && Convert.ToInt32(k.GetValue("Start", 4)) == 2;
    }
    static bool Running(string name) {
        if (ServiceImage(name) == null) return false;
        try { using (var s = new ServiceController(name)) return s.Status == ServiceControllerStatus.Running; }
        catch (InvalidOperationException) { return false; }
    }
    sealed class ClamConfig {
        internal bool Missing, Sample;
        internal readonly Dictionary<string,List<string>> Values = new Dictionary<string,List<string>>(StringComparer.OrdinalIgnoreCase);
        internal string One(string key) { List<string> v; return Values.TryGetValue(key,out v) && v.Count == 1 ? v[0] : null; }
        internal bool Has(string key) { return Values.ContainsKey(key); }
    }
    static ClamConfig ReadClamConfig(string file) {
        var config = new ClamConfig();
        if (!File.Exists(file)) { config.Missing = true; return config; }
        if (new FileInfo(file).Length > 1024*1024) throw new IOException("ClamAV configuration exceeds 1 MiB.");
        foreach (string line in File.ReadLines(file)) {
            string text = line.Trim();
            if (text.Length == 0 || text.StartsWith("#",StringComparison.Ordinal)) continue;
            string[] parts = Regex.Split(text, @"\s+", RegexOptions.None);
            string key = parts[0];
            string value = text.Substring(key.Length).Trim();
            if (value.Length >= 2 && value[0] == '"' && value[value.Length-1] == '"') value=value.Substring(1,value.Length-2);
            List<string> values;
            if (!config.Values.TryGetValue(key,out values)) config.Values[key] = values = new List<string>();
            values.Add(value);
        }
        // Only untouched examples/empty files may be replaced, with a dated backup.
        config.Sample = config.Values.Count == 0 || (config.One("Example") == "" && config.Values.Keys.All(k => k.Equals("Example",StringComparison.OrdinalIgnoreCase) || (k.Equals("DatabaseMirror",StringComparison.OrdinalIgnoreCase) && config.One(k)=="database.clamav.net")));
        return config;
    }
    static bool StandardConfig(ClamConfig c, bool updater, TextWriter log) {
        if (c.Missing || c.Sample) return true;
        // Refuse unknown directives for *automatic* configuration. Never execute user-defined updater hooks.
        string allowed = updater
            ? "DatabaseDirectory DatabaseMirror DNSDatabaseInfo TestDatabases Checks UpdateLogFile LogTime LogRotate LogFileMaxSize LogVerbose MaxAttempts ConnectTimeout ReceiveTimeout ScriptedUpdates CompressLocalDatabase NotifyClamd DatabaseCustomURL Bytecode"
            : "DatabaseDirectory TCPAddr TCPSocket StreamMaxLength MaxFileSize MaxScanSize AlertExceedsMax LogFile LogTime LogRotate LogFileMaxSize LogVerbose LogClean MaxThreads MaxQueue ReadTimeout CommandReadTimeout SendBufTimeout SelfCheck Bytecode BytecodeSecurity ConcurrentDatabaseReload";
        var keys = new HashSet<string>(allowed.Split(' '),StringComparer.OrdinalIgnoreCase);
        foreach (var pair in c.Values) {
            if (!keys.Contains(pair.Key) || (pair.Value.Count != 1 && !pair.Key.Equals("DatabaseCustomURL",StringComparison.OrdinalIgnoreCase))) {
                log.WriteLine("Custom, duplicate or unsupported configuration directive. Existing configuration preserved."); return false;
            }
        }
        if (c.Has("DatabaseDirectory") && !SamePath(c.One("DatabaseDirectory"),ClamDatabase)) { log.WriteLine("Custom database directory; preserve and review manually."); return false; }
        if (updater) {
            if (c.One("DatabaseMirror") != "database.clamav.net" || (c.Has("DNSDatabaseInfo") && c.One("DNSDatabaseInfo") != "current.cvd.clamav.net") || (c.Has("TestDatabases") && !String.Equals(c.One("TestDatabases"),"yes",StringComparison.OrdinalIgnoreCase))) {
                log.WriteLine("Updater mirror or validation policy needs manual review."); return false;
            }
            if (c.Has("NotifyClamd") && !SamePath(c.One("NotifyClamd"),ClamdConfig)) { log.WriteLine("Custom updater notification target; preserve."); return false; }
            if (c.Has("UpdateLogFile") && !SamePath(c.One("UpdateLogFile"),Path.Combine(ClamRoot,"freshclam.log")) && !SamePath(c.One("UpdateLogFile"),Path.Combine(ClamRoot,"signature-logs","freshclam.log"))) { log.WriteLine("Custom updater log path; preserve."); return false; }
            List<string> feeds;
            if (c.Values.TryGetValue("DatabaseCustomURL",out feeds) && !LinkScope.ClamProviderSources.ValidSet(feeds)) { log.WriteLine("Custom signature source requires host-local review (unsupported URL, format or duplicate database filename)."); return false; }
        } else {
            if (c.One("TCPAddr") != "127.0.0.1" || c.One("TCPSocket") != "3310") { log.WriteLine("ClamD is not configured for the standard IPv4 loopback port 3310. Existing settings preserved."); return false; }
            if (c.Has("ConcurrentDatabaseReload") && !new[]{"yes","no"}.Contains(c.One("ConcurrentDatabaseReload"),StringComparer.OrdinalIgnoreCase)) { log.WriteLine("Invalid database reload setting; preserve and review."); return false; }
            if (c.Has("BytecodeSecurity") && !String.Equals(c.One("BytecodeSecurity"),"TrustSigned",StringComparison.OrdinalIgnoreCase)) { log.WriteLine("Unsafe or custom bytecode trust setting; preserve."); return false; }
            if (c.Has("LogFile") && !SamePath(c.One("LogFile"),Path.Combine(ClamRoot,"clamd.log"))) { log.WriteLine("Custom ClamD log path; preserve."); return false; }
        }
        return true;
    }
    // ServiceController reports SCM state, not necessarily process exit. Do not kill an
    // updater or start a second one while a signature database may be being written.
    static int[] FreshClamPids() {
        var processes=Process.GetProcessesByName("freshclam");
        try { return processes.Select(p=>p.Id).OrderBy(id=>id).ToArray(); }
        finally { foreach(var p in processes)p.Dispose(); }
    }
    static void WaitForFreshClamIdle(TextWriter log,int seconds,bool serviceRunning) {
        var clock=Stopwatch.StartNew();bool announced=false;int[] busy;
        int quiet=0;
        do {
            uint servicePid=serviceRunning?ServicePid("freshclam"):0;
            if(serviceRunning&&servicePid==0)throw new IOException("FreshClam service identity changed. Review service status and retry.");
            busy=FreshClamPids().Where(pid=>!serviceRunning||(uint)pid!=servicePid).ToArray();
            if(busy.Length==0) {
                // Two consecutive observations avoid the common SCM/process-exit race.
                if(++quiet>=2)return;
            }else{
                quiet=0;
                if(!announced){log.WriteLine("Waiting for FreshClam processes to finish. PIDs: "+String.Join(", ",busy));log.Flush();announced=true;}
            }
            if(clock.Elapsed>=TimeSpan.FromSeconds(seconds))break;
            Thread.Sleep(500);
        }while(true);
        throw new IOException("FreshClam is still busy (PIDs: "+String.Join(", ",busy)+"). Let the standalone update finish, or stop its scheduler/console gracefully, then retry. No updater process was terminated.");
    }
    internal static void WaitForFreshClamServiceOnly(TextWriter log,int seconds){WaitForFreshClamIdle(log,seconds,true);}
    internal static void WaitForFreshClamExit(TextWriter log,int seconds){WaitForFreshClamIdle(log,seconds,false);}
    static bool DatabasesPresent() {
        return new[]{"main","daily"}.All(name => new[]{".cvd",".cld"}.Any(ext => File.Exists(Path.Combine(ClamDatabase,name+ext))));
    }
    static bool HasPortListener() { return IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Any(e=>e.Port==ClamPort); }
    static bool LoopbackOnly() {
        var listeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Where(e=>e.Port==ClamPort).ToArray();
        return listeners.Length>0 && listeners.All(e=>e.Address.Equals(IPAddress.Loopback));
    }
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr OpenSCManager(string machine,string database,uint access);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr OpenService(IntPtr manager,string name,uint access);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool CloseServiceHandle(IntPtr handle);
    [StructLayout(LayoutKind.Sequential)] struct ServiceStatusProcess { public uint Type,State,Controls,Win32Exit,ServiceExit,Checkpoint,WaitHint,Pid,Flags; }
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool QueryServiceStatusEx(IntPtr service,int level,out ServiceStatusProcess status,uint bytes,out uint needed);
    [DllImport("iphlpapi.dll")] static extern uint GetExtendedTcpTable(IntPtr table,ref uint size,bool order,int family,int tableClass,uint reserved);
    static uint ClamdPid(){return ServicePid("clamd");}
    // Read-only SCM identity for diagnostic counters; never used to authorize response.
    internal static uint ResourceClamdPid(){return ClamdPid();}
    // Fixed standard service only; refuse custom service registrations, untrusted on-disk paths,
    // and a listener exposed outside loopback. No provider URLs or credentials are read here.
    internal static uint StandardClamdResponsePid(){
        if(ServiceImage("clamd")==null||!File.Exists(ClamdExe)||!NativeService("clamd",ClamdExe)||!LoopbackOnly())return 0;
        VerifyClamPath(ProgramFiles);VerifyClamPath(ClamRoot);VerifyClamPath(ClamdExe);
        uint pid=ClamdPid();if(pid<=4)return 0;
        if(ClamCommand("PING")!="PONG"||ClamdPid()!=pid)return 0;
        return pid;
    }

    // Privileged scanner sends file bytes only to the actual registered standard
    // ClamD service, never to an arbitrary configured listener or client-supplied port.
    // Unprivileged service-side scanner: verify the connected TCP owner against
    // SCM before sending any bytes, without requesting process-memory access.
    internal static void VerifyScanServiceOwner(TcpClient client){
        uint pid=ClamdPid();if(pid<=4||!OwnsConnection(client,pid)||ClamdPid()!=pid)throw new IOException("ClamD connection is not owned by the running registered clamd service.");
    }
    internal static void VerifyPrivilegedScanPeer(TcpClient client){
        if(ServiceImage("clamd")==null||!NativeService("clamd",ClamdExe)||!LoopbackOnly())throw new IOException("Standard loopback ClamD service required for privileged scanning.");
        VerifyClamPath(ProgramFiles);VerifyClamPath(ClamRoot);VerifyClamPath(ClamdExe);
        uint pid=ClamdPid();if(pid<=4||!OwnsConnection(client,pid)||ClamdPid()!=pid)throw new IOException("Privileged scan peer identity mismatch.");
        using(var proc=Process.GetProcessById((int)pid)){if(proc.HasExited||!SamePath(proc.MainModule.FileName,ClamdExe)||ClamdPid()!=pid)throw new IOException("Privileged scan live ClamD image mismatch.");}
    }

    static uint ServicePid(string name) {
        IntPtr manager=OpenSCManager(null,null,1),service=IntPtr.Zero;
        if (manager==IntPtr.Zero) return 0;
        try {
            service=OpenService(manager,name,4); if(service==IntPtr.Zero)return 0;
            ServiceStatusProcess status;uint needed;
            return QueryServiceStatusEx(service,0,out status,(uint)Marshal.SizeOf(typeof(ServiceStatusProcess)),out needed)&&status.State==4?status.Pid:0;
        } finally {if(service!=IntPtr.Zero)CloseServiceHandle(service);CloseServiceHandle(manager);}
    }
    static int HostPort(int value) { return ((value&255)<<8)|((value>>8)&255); }
    static bool OwnsConnection(TcpClient client,uint pid) {
        if(pid<=4)return false;
        int local=((IPEndPoint)client.Client.LocalEndPoint).Port;
        uint size=0;GetExtendedTcpTable(IntPtr.Zero,ref size,false,2,5,0);
        for(int attempt=0;attempt<3;attempt++) {
            if(size<4 || size>16*1024*1024)return false;
            IntPtr p=Marshal.AllocHGlobal((int)size);
            try {
                uint rc=GetExtendedTcpTable(p,ref size,false,2,5,0);
                if(rc==122)continue;if(rc!=0)return false;
                int count=Marshal.ReadInt32(p);if(count<0 || 4L+24L*count>size)return false;
                for(int i=0;i<count;i++) {
                    int off=4+i*24;
                    if(Marshal.ReadInt32(p,off)==5 && Marshal.ReadInt32(p,off+4)==0x0100007f && Marshal.ReadInt32(p,off+12)==0x0100007f && HostPort(Marshal.ReadInt32(p,off+8))==ClamPort && HostPort(Marshal.ReadInt32(p,off+16))==local && (uint)Marshal.ReadInt32(p,off+20)==pid)return true;
                }
                return false;
            } finally {Marshal.FreeHGlobal(p);}
        }
        return false;
    }
    static string ClamCommand(string command) {
        uint pid=ClamdPid();if(pid==0 || !LoopbackOnly())throw new IOException("ClamD service or loopback-only listener is unavailable.");
        using(var client=new TcpClient(AddressFamily.InterNetwork)) {
            var ar=client.BeginConnect(IPAddress.Loopback,ClamPort,null,null);
            using(var wait=ar.AsyncWaitHandle){if(!wait.WaitOne(1500))throw new IOException("ClamD connection timeout.");client.EndConnect(ar);}
            if(!OwnsConnection(client,pid)||ClamdPid()!=pid)throw new IOException("Port 3310 is not owned by the expected ClamD service.");
            using(var stream=client.GetStream()) {
                stream.ReadTimeout=2500;stream.WriteTimeout=2500;
                byte[] bytes=Encoding.ASCII.GetBytes("z"+command+"\0");stream.Write(bytes,0,bytes.Length);
                if(command=="INSTREAM") {
                    byte[] sample=Encoding.ASCII.GetBytes("LinkScope harmless setup scan verification\n");
                    byte[] length=BitConverter.GetBytes(IPAddress.HostToNetworkOrder(sample.Length));
                    stream.Write(length,0,4);stream.Write(sample,0,sample.Length);stream.Write(new byte[4],0,4);
                }
                var reply=new List<byte>();int ch;
                while(reply.Count<2048 && (ch=stream.ReadByte())>0 && ch!=10)reply.Add((byte)ch);
                return Encoding.UTF8.GetString(reply.ToArray()).Trim();
            }
        }
    }
    // VERSION uses ClamD's local clock representation (ctime). Never infer freshness
    // from a successful FreshClam check, a third-party file timestamp or PING alone.
    internal static string DefinitionFreshness(string version,DateTime localNow,out long db,out DateTime stamp){
        db=0;stamp=DateTime.MinValue;
        string[] parts=(version??"").Split('/');
        if(parts.Length<3||!parts[0].StartsWith("ClamAV ",StringComparison.OrdinalIgnoreCase)||!Int64.TryParse(parts[1],NumberStyles.None,CultureInfo.InvariantCulture,out db)||db<=0)return "Unknown";
        if(!DateTime.TryParseExact(Regex.Replace(parts[2].Trim(),@"\s+"," "),"ddd MMM d HH:mm:ss yyyy",CultureInfo.InvariantCulture,DateTimeStyles.None,out stamp)||stamp>localNow.AddMinutes(5))return "Unknown";
        return (localNow-stamp).TotalHours>=72?"Stale":"Current";
    }
    // DNS is an advisory version comparison, not a signature authentication or response gate.
    // One background query per process; never wait on DNS in the endpoint scanner.
    const string OfficialDnsName="current.cvd.clamav.net";
    static readonly object dnsGate=new object();
    static Task<Tuple<string,DateTime>> dnsTask;
    static DateTime dnsStartedUtc,dnsCompletedUtc;
    static string dnsLastAnswer;
    static Task<Tuple<string,DateTime>> dnsHarvested;
    [StructLayout(LayoutKind.Sequential)]
    struct DnsTxtRecord {
        public IntPtr Next,Name;
        public ushort Type,DataLength;
        public uint Flags,Ttl,Reserved,Count;
        public IntPtr FirstString;
    }
    [DllImport("dnsapi.dll",EntryPoint="DnsQuery_W",CharSet=CharSet.Unicode,ExactSpelling=true)]
    static extern int QueryOfficialDns(string name,ushort type,uint options,IntPtr extra,out IntPtr records,IntPtr reserved);
    [DllImport("dnsapi.dll",EntryPoint="DnsFree",ExactSpelling=true)]
    static extern void FreeDnsRecords(IntPtr records,int freeType);
    static string ReadOfficialDns(){
        IntPtr records=IntPtr.Zero;
        try{
            // FQDN, no multicast, no hosts file, bypass local resolver cache. Uses configured DNS servers.
            int status=QueryOfficialDns(OfficialDnsName,16,0x1848,IntPtr.Zero,out records,IntPtr.Zero);
            if(status!=0)return "!Windows DNS status "+status.ToString(CultureInfo.InvariantCulture);
            string answer=null;IntPtr next=records;int first=(int)Marshal.OffsetOf(typeof(DnsTxtRecord),"FirstString");
            for(int i=0;i<32&&next!=IntPtr.Zero;i++){
                // Read only the fixed record header for non-TXT records.
                ushort type=(ushort)Marshal.ReadInt16(next,IntPtr.Size*2);
                IntPtr following=Marshal.ReadIntPtr(next);
                if(type==16){
                    var record=(DnsTxtRecord)Marshal.PtrToStructure(next,typeof(DnsTxtRecord));
                    string name=Marshal.PtrToStringUni(record.Name);
                    if(string.Equals((name??"").TrimEnd('.'),OfficialDnsName,StringComparison.OrdinalIgnoreCase)){
                        if(record.Count==0||record.Count>8)return "!Invalid TXT string count";
                        var text=new StringBuilder();
                        for(int n=0;n<(int)record.Count;n++){
                            IntPtr part=Marshal.ReadIntPtr(next,first+n*IntPtr.Size);
                            if(part==IntPtr.Zero)return "!Null TXT string pointer";
                            text.Append(Marshal.PtrToStringUni(part));if(text.Length>1024)return "!TXT response too large";
                        }
                        string candidate=text.ToString();if(answer!=null&&answer!=candidate)return "!Conflicting official TXT records";answer=candidate;
                    }
                }
                next=following;
            }
            return next!=IntPtr.Zero?"!DNS record limit reached":(answer??"!No matching official TXT record");
        }catch(Exception ex){return "!DNS lookup exception: "+ex.GetType().Name;}finally{if(records!=IntPtr.Zero)FreeDnsRecords(records,1);}
    }
    internal static long ParseAdvertisedDaily(string txt,DateTime utcNow){
        if(string.IsNullOrWhiteSpace(txt)||txt.Length>1024)return 0;
        string[] fields=txt.Trim().Split(':');long daily,main,seconds;
        if(fields.Length<4||!Regex.IsMatch(fields[0],@"^\d+\.\d+\.\d+(?:[.-][A-Za-z0-9.-]+)?$")||
            !Int64.TryParse(fields[1],NumberStyles.None,CultureInfo.InvariantCulture,out main)||main<=0||
            !Int64.TryParse(fields[2],NumberStyles.None,CultureInfo.InvariantCulture,out daily)||daily<=0||
            !Int64.TryParse(fields[3],NumberStyles.None,CultureInfo.InvariantCulture,out seconds)||seconds<=0)return 0;
        double age=(utcNow-new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc)).TotalSeconds-seconds;
        // FreshClam documents a three-hour DNS record age limit. Allow limited clock skew.
        return age>=-300&&age<=10800?daily:0;
    }
    // Harvest completed native lookups before replacing them. A refresh in flight must not erase a valid sample.
    static void HarvestOfficialDns(){
        if(dnsTask==null||dnsTask==dnsHarvested||!dnsTask.IsCompleted)return;
        dnsHarvested=dnsTask;
        if(dnsTask.Status==TaskStatus.RanToCompletion){dnsLastAnswer=dnsTask.Result.Item1;dnsCompletedUtc=dnsTask.Result.Item2;}
        else{dnsCompletedUtc=DateTime.UtcNow;dnsLastAnswer="!DNS worker did not complete successfully";}
    }
    static long AdvertisedDaily(bool wait,out string reason){
        reason="Official DNS comparison pending";
        Task<Tuple<string,DateTime>> task;DateTime now=DateTime.UtcNow;
        lock(dnsGate){
            HarvestOfficialDns();
            bool validCached=ParseAdvertisedDaily(dnsLastAnswer,now)>0;
            if(dnsTask==null||(dnsTask.IsCompleted&&(now-dnsCompletedUtc).TotalMinutes>=(validCached?10:2))){
                dnsStartedUtc=now;
                // Dedicated worker avoids dependence on the service request thread pool.
                dnsTask=Task.Factory.StartNew(()=>{string answer=ReadOfficialDns();return Tuple.Create(answer,DateTime.UtcNow);},CancellationToken.None,TaskCreationOptions.LongRunning|TaskCreationOptions.DenyChildAttach,TaskScheduler.Default);
            }
            task=dnsTask;
        }
        try{
            if(wait&&!task.IsCompleted)task.Wait(3000);
            string txt;DateTime sampleUtc;bool pending;DateTime started;
            lock(dnsGate){HarvestOfficialDns();txt=dnsLastAnswer;sampleUtc=dnsCompletedUtc;pending=dnsTask!=null&&!dnsTask.IsCompleted;started=dnsStartedUtc;}
            if(pending&&(string.IsNullOrEmpty(txt)||ParseAdvertisedDaily(txt,DateTime.UtcNow)<=0||(DateTime.UtcNow-sampleUtc).TotalMinutes>15)){
                reason="Official DNS query in progress; elapsed "+Math.Max(0,(DateTime.UtcNow-started).TotalSeconds).ToString("F0",CultureInfo.InvariantCulture)+" seconds; no usable completed sample";return 0;
            }
            if(string.IsNullOrEmpty(txt)){reason="Empty DNS response";return 0;}
            if((DateTime.UtcNow-sampleUtc).TotalMinutes>15){reason="Completed DNS sample expired";return 0;}
            if(txt.StartsWith("!",StringComparison.Ordinal)){reason=txt.Substring(1);return 0;}
            long daily=ParseAdvertisedDaily(txt,DateTime.UtcNow);
            if(daily<=0){
                string[] fields=txt.Trim().Split(':');long seconds;
                if(fields.Length>=4&&Int64.TryParse(fields[3],NumberStyles.None,CultureInfo.InvariantCulture,out seconds)&&seconds>0){
                    double age=(DateTime.UtcNow-new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc)).TotalSeconds-seconds;
                    if(age>10800||age< -300){reason="DNS advertisement timestamp outside accepted window (age "+age.ToString("F0",CultureInfo.InvariantCulture)+" seconds)";return 0;}
                }
                reason="Malformed official TXT version fields";return 0;
            }
            reason="Official DNS daily version "+daily.ToString(CultureInfo.InvariantCulture)+"; completed sample UTC "+sampleUtc.ToString("o")+(pending?"; refresh in progress":"");return daily;
        }catch(Exception ex){reason="DNS lookup failed: "+ex.GetType().Name;return 0;}
    }
    internal static string CompareDefinition(string ageStatus,long loaded,long advertised,out string detail){
        detail="Official daily version comparison unavailable. Publication age: "+ageStatus+" (72-hour policy).";
        if(ageStatus=="Unknown"||loaded<=0){detail="Loaded daily version or publication timestamp could not be verified. No official-version verdict.";return "Unknown";}
        if(advertised<=0)return "Unknown"; // publication age remains in detail; neither current nor outdated version is verified
        if(loaded<advertised){detail="Official daily database update available: loaded "+loaded+", advertised "+advertised+".";return "Stale";}
        if(loaded>advertised){detail="Loaded daily version is ahead of the DNS advertisement; comparison inconclusive.";return "Unknown";}
        detail="Current advertised daily version "+advertised+" is loaded."+(ageStatus=="Stale"?" Publication age exceeds 72 hours; no newer daily version is advertised.":" Publication age is within 72 hours.");
        return "Current";
    }
    internal static string CompareOfficialDefinition(string ageStatus,long loaded,bool wait,out string detail){
        string reason;long advertised=AdvertisedDaily(wait,out reason);string result=CompareDefinition(ageStatus,loaded,advertised,out detail);
        if(advertised<=0)detail+=" Reason: "+reason+". Loaded daily version: "+(loaded>0?loaded.ToString(CultureInfo.InvariantCulture):"Unknown")+". No official-version verdict.";else detail+=" "+reason+".";return result;
    }
    // Advisory only: read the documented fixed-length daily archive header, not
    // third-party files or private configuration. ClamD VERSION remains authoritative.
    internal static long LogDailyDatabaseHeaders(TextWriter log){
        long latest=0;
        foreach(string name in new[]{"daily.cvd","daily.cld"}){
            string path=Path.Combine(ClamDatabase,name);
            try{
                if(!File.Exists(path))continue;
                if(new[]{ClamRoot,ClamDatabase,path}.Any(x=>(File.GetAttributes(x)&FileAttributes.ReparsePoint)!=0)){log.WriteLine(name+": header skipped (reparse point).");continue;}
                byte[] header=new byte[512];int offset=0;
                using(var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete)){
                    while(offset<header.Length){int n=stream.Read(header,offset,header.Length-offset);if(n==0)break;offset+=n;}
                }
                string[] fields=Encoding.ASCII.GetString(header,0,offset).Split(':');long number;
                if(offset!=512||fields.Length<3||fields[0]!="ClamAV-VDB"||!Int64.TryParse(fields[2],NumberStyles.None,CultureInfo.InvariantCulture,out number)||number<=0){log.WriteLine(name+": header version unavailable.");continue;}
                latest=Math.Max(latest,number);log.WriteLine(name+" on-disk database version (advisory): "+number.ToString(CultureInfo.InvariantCulture));
            }catch(Exception ex){log.WriteLine(name+": header unavailable ("+ex.GetType().Name+").");}
        }
        return latest;
    }
    internal static bool LogDefinitionReadiness(string version,TextWriter log){
        log.WriteLine("ClamD VERSION: "+version);
        long loaded;DateTime stamp;DateTime now=DateTime.Now;
        string ageStatus=DefinitionFreshness(version,now,out loaded,out stamp);
        string comparison;string freshness=CompareOfficialDefinition(ageStatus,loaded,true,out comparison);
        log.WriteLine(comparison);
        log.WriteLine("Loaded definition publication age: "+ageStatus+" (72-hour policy)."+(ageStatus=="Unknown"?" Timestamp/version could not be verified.":" Age: "+(now-stamp).TotalHours.ToString("F1",CultureInfo.InvariantCulture)+" hours."));
        long disk=LogDailyDatabaseHeaders(log);
        if(loaded>0&&disk>loaded)log.WriteLine("A newer daily archive exists on disk. ClamD may still be loading it; inspect reload status.");
        else if(loaded>0&&disk==loaded&&freshness!="Current")log.WriteLine("Loaded and on-disk daily versions agree but are stale or age-limited without current DNS evidence. Review official FreshClam download/CDN status; a reload alone will not refresh these definitions.");
        return freshness=="Current"&&(disk==0||loaded>=disk);
    }
    static bool DailyReloadNeeded(TextWriter log){
        long loaded;DateTime stamp;
        DefinitionFreshness(ClamCommand("VERSION"),DateTime.Now,out loaded,out stamp);
        return loaded>0&&LogDailyDatabaseHeaders(log)>loaded;
    }
    static bool VersionCurrent(string version,TextWriter log){return LogDefinitionReadiness(version,log);}
    static int CheckClamAv(TextWriter log) {
        bool installed=File.Exists(ClamdExe)&&File.Exists(FreshExe);
        if(!installed) {
            if(ClamAvInstalled() || File.Exists(ClamdExe) || File.Exists(FreshExe) || File.Exists(ClamdConfig) || File.Exists(FreshConfig) || ServiceImage("clamd")!=null || ServiceImage("freshclam")!=null || !StandardRegistryPaths(log)) {
                log.WriteLine("ClamAV registration or partial/custom install detected, but standard x64 binaries are missing.");return ClamPartial;
            }
            log.WriteLine("ClamAV not installed.");return ClamMissing;
        }
        log.WriteLine("ClamAV binaries detected: "+ClamRoot);
        if(!StandardRegistryPaths(log)||!NativeService("clamd",ClamdExe)||!NativeService("freshclam",FreshExe)) {log.WriteLine("Custom configuration path or service registration; no automatic takeover.");return ClamCustom;}
        var daemon=ReadClamConfig(ClamdConfig);var updater=ReadClamConfig(FreshConfig);
        if(!StandardConfig(daemon,false,log)||!StandardConfig(updater,true,log))return ClamCustom;
        if(daemon.Missing||daemon.Sample||updater.Missing||updater.Sample){log.WriteLine("ClamAV configuration is missing or is an untouched example.");return ClamUnconfigured;}
        log.WriteLine("Standard configuration detected. Definitions present: "+DatabasesPresent()+". ClamD running: "+Running("clamd")+". FreshClam running: "+Running("freshclam"));
        if(!DatabasesPresent()||!Running("clamd"))return ClamNotReady;
        bool current;
        try {
            if(ClamCommand("PING")!="PONG")return ClamNotReady;
            current=VersionCurrent(ClamCommand("VERSION"),log);
        } catch(Exception ex){log.WriteLine("Engine readiness test: "+ex.Message);return ClamNotReady;}
        if(!Running("freshclam")||!AutoService("clamd")||!AutoService("freshclam"))return ClamUpdaterNotReady;
        return current?0:ClamStale;
    }
    static bool TrustedSid(SecurityIdentifier sid) {
        if(sid==null)return false;
        if(sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)||sid.IsWellKnown(WellKnownSidType.LocalSystemSid)||sid.Value=="S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")return true;
        using(var identity=WindowsIdentity.GetCurrent())return sid.Equals(identity.User)&&new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
    static void VerifyClamPath(string path) {
        // Refuse reparse points and non-admin write/delete/ACL access. No existing ACLs are changed.
        for(string p=path;!String.IsNullOrEmpty(p);p=Path.GetDirectoryName(p)) {
            if((File.Exists(p)||Directory.Exists(p)) && (File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse point in ClamAV path: "+p);
        }
        if(!File.Exists(path)&&!Directory.Exists(path))return;
        FileSystemSecurity acl=Directory.Exists(path)?(FileSystemSecurity)Directory.GetAccessControl(path):File.GetAccessControl(path);
        if(!TrustedSid(acl.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier))throw new UnauthorizedAccessException("ClamAV path owner is not a trusted system/admin identity: "+path);
        var write=FileSystemRights.WriteData|FileSystemRights.AppendData|FileSystemRights.WriteAttributes|FileSystemRights.WriteExtendedAttributes|FileSystemRights.Delete|FileSystemRights.DeleteSubdirectoriesAndFiles|FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership;
        foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier)))
            if(rule.AccessControlType==AccessControlType.Allow && (rule.PropagationFlags&PropagationFlags.InheritOnly)==0 && (rule.FileSystemRights&write)!=0 && !TrustedSid(rule.IdentityReference as SecurityIdentifier))throw new UnauthorizedAccessException("ClamAV path has a non-admin write permission; review ACL: "+path);
    }
    static void VerifyClamTree(string root) {
        VerifyClamPath(root);int n=0;var pending=new Stack<string>();pending.Push(root);
        while(pending.Count>0) {
            foreach(string p in Directory.EnumerateFileSystemEntries(pending.Pop())) {
                if(++n>20000)throw new IOException("ClamAV installation tree exceeds safe setup inspection limit.");
                VerifyClamPath(p);if(Directory.Exists(p))pending.Push(p);
            }
        }
    }
    static void RunClamTool(string exe,string args,int timeoutMs,TextWriter log) {
        log.WriteLine("Running "+Path.GetFileName(exe)+" "+args);log.Flush();
        var start=new ProcessStartInfo(exe,args){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=ClamRoot,RedirectStandardOutput=true,RedirectStandardError=true};
        using(var child=Process.Start(start)) {
            var output=child.StandardOutput.ReadToEndAsync();var error=child.StandardError.ReadToEndAsync();
            if(!child.WaitForExit(timeoutMs)){try{child.Kill();child.WaitForExit(5000);}catch(Exception){}throw new System.TimeoutException(Path.GetFileName(exe)+" exceeded setup time limit; inspect its logs and retry after checking its state.");}
            if(!Task.WaitAll(new Task[]{output,error},10000))throw new IOException("Tool exited but its redirected output did not close.");
            if(!SamePath(exe,FreshExe)){log.WriteLine(output.Result);log.WriteLine(error.Result);}else log.WriteLine("FreshClam output omitted: provider URLs can contain credentials. Review its protected local log as administrator.");log.WriteLine("Exit code: "+child.ExitCode);log.Flush();
            if(child.ExitCode!=0)throw new IOException(Path.GetFileName(exe)+" failed (exit "+child.ExitCode+"). Review setup and ClamAV logs.");
        }
    }
    static bool ClamAvInstalled() {
        foreach(var view in new[]{RegistryView.Registry64,RegistryView.Registry32}) {
            using(var hive=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,view))
            using(var products=hive.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")) {
                if(products==null)continue;
                foreach(string key in products.GetSubKeyNames())using(var product=products.OpenSubKey(key)) {
                    if(product==null)continue;
                    string name=Convert.ToString(product.GetValue("DisplayName"));
                    if(name.Equals("ClamAV",StringComparison.OrdinalIgnoreCase)||name.StartsWith("ClamAV ",StringComparison.OrdinalIgnoreCase))return true;
                }
            }
        }
        foreach(string root in new[]{ProgramFiles,Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)}) {
            if(!String.IsNullOrEmpty(root)&&File.Exists(Path.Combine(root,"ClamAV","clamd.exe"))&&File.Exists(Path.Combine(root,"ClamAV","freshclam.exe")))return true;
        }
        return false;
    }

        // Observation only: never execute log content, disclose raw log lines, or trust a log as proof of all feeds loading.
        internal static string ReadReportedUpdate(){
            string privateLog=Path.Combine(ClamRoot,"signature-logs","freshclam.log");string path=File.Exists(privateLog)?privateLog:Path.Combine(ClamRoot,"freshclam.log");if(!File.Exists(path))return null;
            VerifyClamPath(ProgramFiles);VerifyClamPath(ClamRoot);VerifyClamPath(path);
            DateTime latest=DateTime.MinValue;
            using(var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete)){
                long start=Math.Max(0,file.Length-262144);file.Position=start;
                byte[] bytes=new byte[262144];int count=0,n;while(count<bytes.Length&&(n=file.Read(bytes,count,bytes.Length-count))>0)count+=n;
                string text=Encoding.UTF8.GetString(bytes,0,count);var lines=text.Split('\n');
                for(int i=start==0?0:1;i<lines.Length-1;i++){
                    var match=Regex.Match(lines[i].TrimEnd('\r'),@"^(?:INFO:\s*)?(?<stamp>[A-Za-z]{3} [A-Za-z]{3} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4})\s*->\s*(?:(?:main|daily|bytecode)\.(?:cvd|cld) updated \(version: [0-9]+,|Database updated \([0-9]+ signatures\))",RegexOptions.CultureInvariant,TimeSpan.FromMilliseconds(25));
                    DateTime local;if(!match.Success||!DateTime.TryParseExact(Regex.Replace(match.Groups["stamp"].Value,@"\s+"," "),"ddd MMM d HH:mm:ss yyyy",CultureInfo.InvariantCulture,DateTimeStyles.None,out local)||TimeZoneInfo.Local.IsAmbiguousTime(local)||TimeZoneInfo.Local.IsInvalidTime(local))continue;
                    DateTime utc=TimeZoneInfo.ConvertTimeToUtc(local,TimeZoneInfo.Local);if(utc>latest&&utc<=DateTime.UtcNow.AddMinutes(5))latest=utc;
                }
            }
            return latest==DateTime.MinValue?null:latest.ToString("o",CultureInfo.InvariantCulture);
        }
        // Hash the actual signature databases, not timestamps. A no-change success is a check, not a download.
        internal static string DatabaseFingerprint(){
            if(!Directory.Exists(ClamDatabase))return "missing";
            VerifyClamPath(ClamDatabase);
            var allowed=new HashSet<string>(new[]{".cvd",".cld"}.Concat(ClamProviderSources.Extensions),StringComparer.OrdinalIgnoreCase);
            var paths=Directory.EnumerateFiles(ClamDatabase).Where(p=>allowed.Contains(Path.GetExtension(p))).OrderBy(p=>p,StringComparer.OrdinalIgnoreCase).Take(1001).ToArray();
            if(paths.Length>1000)throw new IOException("Signature database file count exceeds maintenance limit.");
            long total=0;var manifest=new StringBuilder();foreach(var p in paths){VerifyClamPath(p);using(var stream=new FileStream(p,FileMode.Open,FileAccess.Read,FileShare.Read))using(var sha=SHA256.Create()){total+=stream.Length;if(total>4L*1024*1024*1024)throw new IOException("Signature database exceeds maintenance hash limit.");manifest.Append(Path.GetFileName(p).ToUpperInvariant()).Append(':').Append(Convert.ToBase64String(sha.ComputeHash(stream))).Append('\n');}}
            using(var sha=SHA256.Create())return Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes(manifest.ToString())));
        }
        // Provider policy is host-local, never accepted from the dashboard or command line.
        static string ProviderFolder {get{return Path.Combine(ClamRoot,"linkscope-provider-policy");}}
        static string ProviderFile {get{return Path.Combine(ProviderFolder,"sources.json");}}
        static string ProviderHost(string url){Uri uri;if(!ClamProviderSources.TryParse(url,out uri))throw new InvalidDataException("Invalid provider URL.");return uri.DnsSafeHost.ToLowerInvariant();}
        static string ProviderName(string url){Uri uri;if(!ClamProviderSources.TryParse(url,out uri))throw new InvalidDataException("Invalid provider URL.");return ClamProviderSources.Name(uri);}
        static SecurityIdentifier[] PrivateSids(){return new[]{new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null),new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null)};}
        static FileSecurity PrivateProviderFileAcl(){var acl=new FileSecurity();acl.SetOwner(PrivateSids()[0]);acl.SetAccessRuleProtection(true,false);foreach(var sid in PrivateSids())acl.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,AccessControlType.Allow));return acl;}
        static void VerifyPrivateProviderPath(string path){
            VerifyClamPath(path);var acl=Directory.Exists(path)?(FileSystemSecurity)Directory.GetAccessControl(path):File.GetAccessControl(path);
            foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier)))if(rule.AccessControlType==AccessControlType.Allow&&!PrivateSids().Any(x=>x.Equals(rule.IdentityReference)))throw new UnauthorizedAccessException("Provider policy must be readable only by administrators and SYSTEM.");
        }
        static void EnsureProviderFolder(){
            VerifyClamPath(ClamRoot);VerifyClamPath(ProviderFolder);
            if(!Directory.Exists(ProviderFolder)){var acl=new DirectorySecurity();acl.SetOwner(PrivateSids()[0]);acl.SetAccessRuleProtection(true,false);foreach(var sid in PrivateSids())acl.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));Directory.CreateDirectory(ProviderFolder,acl);}
            VerifyPrivateProviderPath(ProviderFolder);
        }
        static void WritePrivate(string path,string content,bool replace){
            EnsureProviderFolder();string temp=Path.Combine(ProviderFolder,Guid.NewGuid().ToString("N")+".tmp");
            try{using(var fs=new FileStream(temp,FileMode.CreateNew,FileSystemRights.FullControl,FileShare.None,4096,FileOptions.WriteThrough,PrivateProviderFileAcl()))using(var writer=new StreamWriter(fs,new UTF8Encoding(false))){writer.Write(content);writer.Flush();fs.Flush(true);}
                if(replace&&File.Exists(path)){VerifyPrivateProviderPath(path);File.Replace(temp,path,null);}else File.Move(temp,path);
                VerifyPrivateProviderPath(path);
            }finally{if(File.Exists(temp))File.Delete(temp);}
        }
        internal static List<ProviderPolicyEntry> ReadProviderPolicy(){
            if(!File.Exists(ProviderFile))return new List<ProviderPolicyEntry>();VerifyPrivateProviderPath(ProviderFolder);VerifyPrivateProviderPath(ProviderFile);
            if(new FileInfo(ProviderFile).Length>1024*1024)throw new IOException("Provider policy exceeds its limit.");
            var rows=new System.Web.Script.Serialization.JavaScriptSerializer().Deserialize<List<ProviderPolicyEntry>>(File.ReadAllText(ProviderFile));
            if(rows==null||rows.Any(x=>x==null||x.Hours<1||x.Hours>720||x.Next<=0||x.Next>DateTime.MaxValue.Ticks||x.Attempt<0||x.Attempt>DateTime.MaxValue.Ticks||x.Success<0||x.Success>DateTime.MaxValue.Ticks||!new[]{"Migration cooldown","Scheduled","Attempt reserved","Checked","Failed"}.Contains(x.Status))||!ClamProviderSources.ValidSet(rows.Select(x=>x.Url))||rows.GroupBy(x=>ProviderHost(x.Url)).Any(g=>g.Select(x=>x.Hours).Distinct().Count()!=1||g.Select(x=>x.Next).Distinct().Count()!=1))throw new InvalidDataException("Invalid provider policy; no downloads attempted.");return rows;
        }
        static string ProviderUtc(long ticks){return ticks<=0?null:new DateTime(ticks,DateTimeKind.Utc).ToString("o",CultureInfo.InvariantCulture);}
        static void SaveProviderPolicy(List<ProviderPolicyEntry> rows,bool publish=true){
            WritePrivate(ProviderFile,new System.Web.Script.Serialization.JavaScriptSerializer().Serialize(rows),true);
            if(publish)ClamUpdateState.PublishProviders(rows.GroupBy(x=>ProviderHost(x.Url)).OrderBy(g=>g.Key).Select(g=>new ProviderUpdateView{provider=g.Key,files=g.Count(),intervalHours=g.First().Hours,nextUtc=ProviderUtc(g.Max(x=>x.Next)),lastAttemptUtc=ProviderUtc(g.Max(x=>x.Attempt)),lastSuccessUtc=ProviderUtc(g.Min(x=>x.Success)),status=g.First().Status}).ToArray());
        }
        // Legacy migration reserves a full day, even if a shorter policy is selected later.
        internal static List<ProviderPolicyEntry> MergeProviderPolicy(IEnumerable<string> urls,IDictionary<string,int> hours,bool migrating){
            var rows=ReadProviderPolicy();long now=DateTime.UtcNow.Ticks;
            foreach(string url in urls){string name=ProviderName(url),host=ProviderHost(url);var old=rows.FirstOrDefault(x=>string.Equals(ProviderName(x.Url),name,StringComparison.OrdinalIgnoreCase));
                if(old!=null&&ProviderHost(old.Url)!=host)throw new InvalidDataException("Provider database filename already belongs to another host.");
                if(old==null){var same=rows.FirstOrDefault(x=>ProviderHost(x.Url)==host);int interval=same==null?24:same.Hours;rows.Add(new ProviderPolicyEntry{Url=url,Hours=interval,Next=same!=null?same.Next:now,Attempt=same==null?0:same.Attempt,Success=0,Status=same==null?"Scheduled":same.Status});}
                else old.Url=url;
            }
            if(!ClamProviderSources.ValidSet(rows.Select(x=>x.Url)))throw new InvalidDataException("Invalid or conflicting provider database filenames.");
            foreach(var group in rows.GroupBy(x=>ProviderHost(x.Url))){var g=group.ToArray();int interval; if(!hours.TryGetValue(group.Key,out interval))interval=g[0].Hours;if(interval<1||interval>720)throw new InvalidDataException("Provider interval must be 1–720 hours.");
                long next=g.Max(x=>x.Next),attempt=g.Max(x=>x.Attempt);if(attempt>0)next=Math.Max(next,new DateTime(attempt,DateTimeKind.Utc).AddHours(interval).Ticks);
                if(migrating||(g.Any(x=>x.Status=="Migration cooldown")&&interval>g[0].Hours)){next=Math.Max(next,new DateTime(now,DateTimeKind.Utc).AddHours(Math.Max(24,interval)).Ticks);}
                foreach(var e in g){e.Hours=interval;e.Next=next;if(migrating)e.Status="Migration cooldown";}
            }return rows;
        }
        internal static void SaveManagedProviders(IEnumerable<string> legacy,IEnumerable<string> entered,IDictionary<string,int> hours){
            var old=ReadProviderPolicy();var migrated=MergeProviderPolicy(legacy,new Dictionary<string,int>(),legacy.Any());
            // Persist legacy URLs before removing them from the official configuration. Never overwrite the original with an empty list.
            if(legacy.Any())SaveProviderPolicy(migrated,false);
            var rows=MergeProviderPolicy(entered,hours,false);if(rows.Count==0&&old.Count>0)throw new IOException("Provider policy would lose existing sources.");SaveProviderPolicy(rows,!legacy.Any());
        }
        internal static void SeparateStoppedUpdater(TextWriter log){
            // Caller owns maintenance mutex and has verified that no FreshClam process remains.
            WaitForFreshClamExit(log,5);VerifyClamPath(FreshConfig);var c=ReadClamConfig(FreshConfig);if(c.Missing||c.Sample||!StandardConfig(c,true,log))throw new IOException("Standard FreshClam configuration required.");
            List<string> legacy;if(!c.Values.TryGetValue("DatabaseCustomURL",out legacy))legacy=new List<string>();
            if(legacy.Count==0){if(File.Exists(ProviderFile))SaveProviderPolicy(ReadProviderPolicy());else if(ClamUpdateState.ReadProviders()==null)ClamUpdateState.PublishProviders(new ProviderUpdateView[0]);if(string.Equals(c.One("TestDatabases"),"yes",StringComparison.OrdinalIgnoreCase)&&c.One("Checks")=="24"&&SamePath(c.One("NotifyClamd"),ClamdConfig))return;}
            ClamUpdateState.PublishProviders(null);
            SaveManagedProviders(legacy,new string[0],new Dictionary<string,int>());
            // Protect the rollback copy before stripping URLs. All original signature files remain in place.
            WritePrivate(Path.Combine(ProviderFolder,"legacy-"+Guid.NewGuid().ToString("N")+".conf.bak"),File.ReadAllText(FreshConfig),false);
            string temp=Path.Combine(ProviderFolder,Guid.NewGuid().ToString("N")+".conf.tmp");
            try{var lines=File.ReadAllLines(FreshConfig).Where(x=>!Regex.IsMatch(x,@"^\s*(DatabaseCustomURL|Checks|TestDatabases|NotifyClamd)(?:\s|$)",RegexOptions.IgnoreCase)).ToList();lines.Add("Checks 24");lines.Add("TestDatabases yes");lines.Add("NotifyClamd \""+ClamdConfig+"\"");WritePrivate(temp,string.Join(Environment.NewLine,lines)+Environment.NewLine,false);
                if(!StandardConfig(ReadClamConfig(temp),true,log)||ReadClamConfig(temp).Has("DatabaseCustomURL"))throw new IOException("Official configuration validation failed.");
                File.Replace(temp,FreshConfig,null);SaveProviderPolicy(ReadProviderPolicy());log.WriteLine("Separated legacy providers; official FreshClam configuration contains no custom URLs. Existing signatures retained.");
            }finally{if(File.Exists(temp))File.Delete(temp);}
        }
        static bool NativeUpdaterSystem(){using(var key=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\freshclam")){if(key==null)return false;string account=Convert.ToString(key.GetValue("ObjectName"));return new[]{"LocalSystem",@"NT AUTHORITY\SYSTEM","S-1-5-18"}.Contains(account,StringComparer.OrdinalIgnoreCase);}}
        static bool RunDueProvider(TextWriter log){
            var rows=ReadProviderPolicy();long now=DateTime.UtcNow.Ticks;
            var due=rows.GroupBy(x=>ProviderHost(x.Url)).Where(g=>g.Max(x=>x.Next)<=now).OrderBy(g=>g.Max(x=>x.Next)).ThenBy(g=>g.Key,StringComparer.Ordinal).FirstOrDefault();
            if(due==null)return true;var group=due.ToArray();int hours=group[0].Hours;
            foreach(var x in group){x.Attempt=now;x.Next=new DateTime(now,DateTimeKind.Utc).AddMinutes(15).AddHours(hours).Ticks;x.Status="Attempt reserved";}SaveProviderPolicy(rows);
            string temp=Path.Combine(ProviderFolder,Guid.NewGuid().ToString("N")+".conf");bool success=false;
            try{
                // No provider URL appears in process arguments or LinkScope logs. Disable FreshClam retries and daemon notification for this batch.
                var lines=File.ReadAllLines(FreshConfig).Where(x=>!Regex.IsMatch(x,@"^\s*(DatabaseCustomURL|UpdateLogFile|NotifyClamd|MaxAttempts|TestDatabases)(?:\s|$)",RegexOptions.IgnoreCase)).ToList();
                lines.Add("TestDatabases yes");lines.Add("MaxAttempts 1");lines.Add("UpdateLogFile \""+Path.Combine(ProviderFolder,"provider-update.log")+"\"");foreach(var x in group)lines.Add("DatabaseCustomURL "+x.Url);
                WritePrivate(temp,string.Join(Environment.NewLine,lines)+Environment.NewLine,false);WaitForFreshClamExit(log,5);RunClamTool(FreshExe,"--config-file=\""+temp+"\" --update-db=custom",600000,log);success=true;
            }catch(Exception ex){log.WriteLine("Third-party batch failed ("+ex.GetType().Name+"); see administrator-only provider log.");}
            finally{long finished=DateTime.UtcNow.Ticks;foreach(var x in group){x.Next=Math.Max(x.Next,new DateTime(finished,DateTimeKind.Utc).AddHours(hours).Ticks);x.Status=success?"Checked":"Failed";if(success)x.Success=finished;}SaveProviderPolicy(rows);if(File.Exists(temp))File.Delete(temp);}
            return success;
        }
        internal static int Update(TextWriter log,bool enforceCooldown){
            using(var identity=WindowsIdentity.GetCurrent())if(!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))throw new UnauthorizedAccessException("Windows administrator required.");
            using(var mutex=new Mutex(false,@"Global\LinkScopeClamProvision")){
                bool locked=false,started=false,changed=false,officialFailed=false;ClamUpdateState state=null;string stage="starting";
                try{
                    try{locked=mutex.WaitOne(0);}catch(AbandonedMutexException){locked=true;}
                    if(!locked){log.WriteLine("Another ClamAV maintenance operation is running.");return 10;}
                    state=ClamUpdateState.Read();if(enforceCooldown&&(state.Busy||state.CoolingDown)){log.WriteLine("Signature update already active or rate limited (60 minutes).");return 10;}
                    state.Begin();started=true;
                    stage="checking installation";int before=CheckClamAv(log);if(before!=0&&before!=ClamStale)throw new IOException("Standard ClamAV installation is not ready ("+before+"). Repair in Setup first.");
                    stage="verifying installation permissions";VerifyClamPath(ProgramFiles);VerifyClamPath(ClamRoot);VerifyClamPath(FreshExe);VerifyClamPath(FreshConfig);
                    var updater=ReadClamConfig(FreshConfig);
                    if(updater.Missing||updater.Sample||!StandardConfig(updater,true,log)||!NativeService("freshclam",FreshExe)||!NativeUpdaterSystem()||!Running("freshclam"))throw new IOException("Repair the standard updater and enable TestDatabases before updating.");
                    using(var svc=new ServiceController("freshclam")){
                        try{
                            stage="waiting for other FreshClam updates";WaitForFreshClamServiceOnly(log,120);
                            stage="stopping automatic updater";svc.Stop();svc.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(60));
                            stage="waiting for FreshClam process exit";WaitForFreshClamExit(log,120);
                            VerifyClamTree(ClamRoot);
                            stage="separating signature sources";SeparateStoppedUpdater(log);
                            stage="hashing existing databases";string original=DatabaseFingerprint();
                            bool officialOk=true;
                            stage="running official FreshClam";WaitForFreshClamExit(log,5);
                            try{RunClamTool(FreshExe,"--config-file=\""+FreshConfig+"\"",600000,log);}catch(Exception ex){officialOk=false;officialFailed=true;log.WriteLine("Official update failed ("+ex.GetType().Name+").");}
                            stage="running due third-party batch";RunDueProvider(log);
                            stage="verifying changed database contents";changed=!string.Equals(original,DatabaseFingerprint(),StringComparison.Ordinal);
                            if(officialOk)state.DownloadCompleted(changed);else if(changed)state.RecordChanged();
                            // RELOAD is asynchronous. Do not claim that every third-party database is loaded.
                            stage="requesting ClamD reload";if(changed||DailyReloadNeeded(log)){string reply=ClamCommand("RELOAD");log.WriteLine("ClamD reload: "+reply);if(!reply.StartsWith("RELOADING",StringComparison.OrdinalIgnoreCase))throw new IOException("ClamD reload not accepted.");}
                        }finally{svc.Refresh();if(svc.Status==ServiceControllerStatus.StopPending)svc.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(60));if(svc.Status==ServiceControllerStatus.Stopped){if(ReadClamConfig(FreshConfig).Has("DatabaseCustomURL"))throw new IOException("Migration incomplete; updater left stopped to avoid unscheduled downloads. Retry provider setup.");try{WaitForFreshClamExit(log,5);}catch(IOException ex){throw new IOException("Automatic updater remains stopped to avoid concurrent updates. Start the FreshClam service after the other updater exits.",ex);}svc.Start();}svc.WaitForStatus(ServiceControllerStatus.Running,TimeSpan.FromMinutes(2));}
                    }
                    stage="verifying service readiness";int result=ClamStale;
                    long expectedDaily=LogDailyDatabaseHeaders(log);bool loadedExpected=expectedDaily==0;
                    var verification=Stopwatch.StartNew();
                    do{
                        result=CheckClamAv(log);
                        if(result==0||result==ClamStale){
                            try{long loaded;DateTime stamp;DefinitionFreshness(ClamCommand("VERSION"),DateTime.Now,out loaded,out stamp);loadedExpected=expectedDaily==0||loaded>=expectedDaily;}
                            catch(Exception){loadedExpected=false;}
                            if(loadedExpected)break; // an unchanged stale database needs a download, not more waiting
                        }
                        if(result==ClamCustom||result==ClamMissing||result==ClamPartial||result==ClamUnconfigured)break;
                        if(verification.Elapsed>=TimeSpan.FromSeconds(120))break;
                        Thread.Sleep(2000);
                    }while(verification.Elapsed<TimeSpan.FromSeconds(120));
                    if(officialFailed){state.Finish("Warning","Official FreshClam update failed; third-party status is reported separately.");return 1;}
                    if(!loadedExpected&&(result==0||result==ClamStale)){state.Finish("Warning",ClamUpdateState.ReloadReview);return ClamStale;}
                    if(result!=0){state.Finish("Warning",result==ClamStale?ClamUpdateState.DefinitionReview:"FreshClam completed, but engine or updater readiness still needs review.");return result;}
                    state.Finish(changed?"Updated":"Checked",changed?"Signature database contents changed; ClamD reload requested and engine responding.":"FreshClam completed; database contents unchanged; engine responding.");return 0;
                }catch(Exception ex){log.WriteLine("Signature maintenance failure: "+stage+" ("+ex.GetType().Name+").");if(started)try{state.Finish("Failed","Signature maintenance failed while "+stage+" ("+ex.GetType().Name+"). Review FreshClam logs and Windows service status.");}catch(Exception e){log.WriteLine(e);}return 1;}
                finally{if(locked)mutex.ReleaseMutex();}
            }
        }
    }
}
