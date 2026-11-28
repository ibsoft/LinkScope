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
using System.Windows.Forms;
using Microsoft.Win32;

// Standard, local Windows ClamAV provisioning. Existing custom installations are read-only.
internal static partial class Setup {
    // Explicit removal only: never execute arbitrary registry UninstallString commands.
    static List<Guid> ClamMsiProducts() {
        var result=new List<Guid>();
        foreach(var view in new[]{RegistryView.Registry64,RegistryView.Registry32})
            using(var hive=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,view))
            using(var products=hive.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")) {
                if(products==null)continue;
                foreach(string key in products.GetSubKeyNames())using(var product=products.OpenSubKey(key)) {
                    if(product==null)continue;
                    string name=Convert.ToString(product.GetValue("DisplayName")); Guid id;
                    if((name.Equals("ClamAV",StringComparison.OrdinalIgnoreCase)||name.StartsWith("ClamAV ",StringComparison.OrdinalIgnoreCase)) &&
                        Convert.ToString(product.GetValue("WindowsInstaller"))=="1" && Guid.TryParse(key,out id) && !result.Contains(id))result.Add(id);
                }
            }
        return result;
    }
    static bool IsRemovableClamService(string name) {
        string image=ServiceImage(name);if(String.IsNullOrWhiteSpace(image))return false;
        image=Environment.ExpandEnvironmentVariables(image.Trim());
        string path;
        if(image.StartsWith("\"")){int end=image.IndexOf('"',1);if(end<0)return false;path=image.Substring(1,end-1);}
        else {int end=image.IndexOf(".exe",StringComparison.OrdinalIgnoreCase);if(end<0)return false;path=image.Substring(0,end+4);}
        foreach(string root in new[]{ClamRoot,Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),"ClamAV")})
            foreach(string file in new[]{"clamd.exe","freshclam.exe"})if(SamePath(path,Path.Combine(root,file)))return true;
        return false;
    }
    static List<string> ClamServices() {
        var names=new List<string>();
        using(var key=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
            if(key!=null)foreach(string name in key.GetSubKeyNames())if(IsRemovableClamService(name))names.Add(name);
        return names;
    }
    static int UninstallClamAv(TextWriter log,string logPath) {
        using(var mutex=new Mutex(false,@"Global\LinkScopeClamProvision")) {
            bool locked=false;
            try {
                try{locked=mutex.WaitOne(0);}catch(AbandonedMutexException){locked=true;}
                if(!locked){log.WriteLine("ClamAV maintenance is active; retry later.");return 10;}
                var services=ClamServices();var products=ClamMsiProducts();
                if(MessageBox.Show("Remove registered ClamAV MSI packages and their native Windows services? Other applications using ClamAV may lose antivirus scanning. Custom installations and remaining configuration/database files are not manually deleted.","Confirm ClamAV removal",MessageBoxButtons.YesNo,MessageBoxIcon.Warning,MessageBoxDefaultButton.Button2)!=DialogResult.Yes)return 1602;
                // Stop only services whose registered executable points to standard ClamAV paths.
                foreach(string name in services) {
                    if(!IsRemovableClamService(name))throw new IOException("Service identity changed: "+name);
                    log.WriteLine("Stopping ClamAV service: "+name);log.Flush();
                    using(var svc=new ServiceController(name)) {
                        if(svc.Status==ServiceControllerStatus.StartPending)svc.WaitForStatus(ServiceControllerStatus.Running,TimeSpan.FromSeconds(60));
                        svc.Refresh();
                        if(svc.Status!=ServiceControllerStatus.Stopped && svc.Status!=ServiceControllerStatus.StopPending) {
                            foreach(var dependent in svc.DependentServices)using(dependent)if(dependent.Status!=ServiceControllerStatus.Stopped)throw new IOException("Active dependent service: "+dependent.ServiceName+". Stop it explicitly before removing ClamAV.");
                            svc.Stop();
                        }
                        svc.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(90));
                    }
                }
                int reboot=0;
                foreach(Guid id in products) {
                    string msiLog=Path.ChangeExtension(logPath,id.ToString("N")+".msi.log");
                    int rc=RunHidden(Path.Combine(Environment.SystemDirectory,"msiexec.exe"),"/x "+id.ToString("B")+" /qn /norestart /L*v \""+msiLog+"\"",LogDirectory,log);
                    if(rc==3010||rc==1641)reboot=3010;
                    else if(rc!=0&&rc!=1605&&rc!=1614)return rc;
                }
                // MSI may already have removed the services; delete only verified leftovers.
                foreach(string name in ClamServices()) {
                    if(!IsRemovableClamService(name))throw new IOException("Service identity changed: "+name);
                    if(name.IndexOf('"')>=0)throw new IOException("Unsupported service name: "+name);
                    int rc=RunHidden(Path.Combine(Environment.SystemDirectory,"sc.exe"),"delete \""+name+"\"",LogDirectory,log);
                    if(rc!=0&&rc!=1060&&rc!=1072)return rc;
                }
                if(ClamServices().Count!=0){log.WriteLine("ClamAV service deletion pending; restart Windows.");reboot=3010;}
                if(ClamMsiProducts().Count!=0&&reboot==0){log.WriteLine("ClamAV MSI registration remains.");return 1;}
                if((ClamAvInstalled()||File.Exists(ClamdExe)||File.Exists(FreshExe)||ServiceImage("clamd")!=null||ServiceImage("freshclam")!=null)&&products.Count==0){log.WriteLine("No registered MSI product; non-MSI installation retained. Remove manually.");return 4;}
                if(reboot==0 && CheckClamAv(log)!=ClamMissing){log.WriteLine("Residual ClamAV files or configuration detected; removal incomplete.");return 4;}
                log.WriteLine("ClamAV removal completed; unmanaged residual files, if any, are preserved.");return reboot;
            } finally {if(locked)mutex.ReleaseMutex();}
        }
    }
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
    static bool FreshClamProcessPresent() {
        var processes=Process.GetProcessesByName("freshclam");
        try { return processes.Length>0; } finally { foreach(var p in processes)p.Dispose(); }
    }
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
    static uint ClamdPid() {
        IntPtr manager=OpenSCManager(null,null,1),service=IntPtr.Zero;
        if (manager==IntPtr.Zero) return 0;
        try {
            service=OpenService(manager,"clamd",4); if(service==IntPtr.Zero)return 0;
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
    static bool VersionCurrent(string version,TextWriter log){return LinkScope.ClamUpdateWorker.LogDefinitionReadiness(version,log);}
    static int CheckClamAv(TextWriter log) {
        bool installed=File.Exists(ClamdExe)&&File.Exists(FreshExe);
        if(!installed) {
            if(!StandardRegistryPaths(log)||!NativeService("clamd",ClamdExe)||!NativeService("freshclam",FreshExe)){log.WriteLine("Custom ClamAV installation detected.");return ClamCustom;}
            if(ClamAvInstalled() || File.Exists(ClamdExe) || File.Exists(FreshExe) || ClamServices().Count!=0 || ServiceImage("clamd")!=null || ServiceImage("freshclam")!=null || !StandardRegistryPaths(log)) {
                log.WriteLine("ClamAV registration or partial/custom install detected, but standard x64 binaries are missing.");return ClamPartial;
            }
            log.WriteLine("ClamAV not installed. Existing configuration/database files, if any, are retained for reinstall.");return ClamMissing;
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
            if(rule.AccessControlType==AccessControlType.Allow && (rule.PropagationFlags&PropagationFlags.InheritOnly)==0 && (rule.FileSystemRights&write)!=0 && !TrustedSid(rule.IdentityReference as SecurityIdentifier))throw new UnauthorizedAccessException("ClamAV path has a non-admin write permission; review ACL: "+path+" (SID "+rule.IdentityReference.Value+")");
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
    static string QuotedConfigPath(string path) {return "\""+path+"\"";}
    static void WriteMissingConfig(string path,bool updater,TextWriter log) {
        var current=ReadClamConfig(path);if(!current.Missing&&!current.Sample)return;
        string[] lines=updater?new[]{"# LinkScope setup - approved local ClamAV configuration", "DatabaseDirectory "+QuotedConfigPath(ClamDatabase), "DatabaseMirror database.clamav.net", "TestDatabases yes", "Checks 24", "NotifyClamd "+QuotedConfigPath(ClamdConfig), "UpdateLogFile "+QuotedConfigPath(Path.Combine(ClamRoot,"freshclam.log")), "LogTime yes", "LogFileMaxSize 10M", "LogRotate yes"}
            :new[]{"# LinkScope setup - IPv4 loopback only", "DatabaseDirectory "+QuotedConfigPath(ClamDatabase), "TCPAddr 127.0.0.1", "TCPSocket 3310", "StreamMaxLength 100M", "MaxFileSize 100M", "MaxScanSize 200M", "AlertExceedsMax yes", "BytecodeSecurity TrustSigned", "LogFile "+QuotedConfigPath(Path.Combine(ClamRoot,"clamd.log")), "LogTime yes", "LogFileMaxSize 10M", "LogRotate yes"};
        string temp=path+"."+Guid.NewGuid().ToString("N")+".tmp";
        try {
            using(var fs=new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.None))using(var writer=new StreamWriter(fs,new UTF8Encoding(false)))foreach(string line in lines)writer.WriteLine(line);
            if(current.Missing)File.Move(temp,path);
            else {string backup=path+".example-"+Guid.NewGuid().ToString("N")+".bak";File.Replace(temp,path,backup);log.WriteLine("Original example backed up: "+backup);}
            log.WriteLine("Configuration created: "+path);
        } finally {if(File.Exists(temp))File.Delete(temp);}
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
    static void EnsureService(string name,string exe,TextWriter log) {
        if(ServiceImage(name)==null)RunClamTool(exe,"--install-service",120000,log);
        if(ServiceImage(name)==null||!NativeService(name,exe))throw new IOException("Service registration not verified: "+name);
        // Native install uses demand start. Explicit user consent covers making standard services automatic.
        if(!AutoService(name))RunClamTool(Path.Combine(Environment.SystemDirectory,"sc.exe"),"config "+name+" start= auto",30000,log);
        using(var svc=new ServiceController(name)) {
            if(svc.Status==ServiceControllerStatus.Stopped)svc.Start();
            svc.WaitForStatus(ServiceControllerStatus.Running,TimeSpan.FromMinutes(3));
        }
        if(!AutoService(name)||!Running(name))throw new IOException("Service startup not confirmed: "+name);
        log.WriteLine(name+" is running with automatic startup.");log.Flush();
    }
    // The web service deliberately cannot change provider URLs. Only this elevated local UI can.
    static bool LocalSystemUpdater(){
        using(var key=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\freshclam")){
            if(key==null)return false;
            string account=Convert.ToString(key.GetValue("ObjectName"));
            if(String.Equals(account,"LocalSystem",StringComparison.OrdinalIgnoreCase)||String.Equals(account,@"NT AUTHORITY\SYSTEM",StringComparison.OrdinalIgnoreCase)||String.Equals(account,"S-1-5-18",StringComparison.OrdinalIgnoreCase))return true;
            try{return !String.IsNullOrWhiteSpace(account)&&((SecurityIdentifier)new NTAccount(account).Translate(typeof(SecurityIdentifier))).IsWellKnown(WellKnownSidType.LocalSystemSid);}
            catch(IdentityNotMappedException){return false;}
        }
    }
    // Match the actual LinkScope service SID, not TrustedInstaller's SID.
    static SecurityIdentifier SignatureLogReader(){
        using(var sha=System.Security.Cryptography.SHA1.Create()){
            byte[] hash=sha.ComputeHash(Encoding.Unicode.GetBytes("LINKSCOPE"));
            return new SecurityIdentifier("S-1-5-80-"+String.Join("-",Enumerable.Range(0,5).Select(i=>BitConverter.ToUInt32(hash,i*4).ToString(CultureInfo.InvariantCulture))));
        }
    }
    static string providerStage="starting provider configuration";
    static void ProviderStep(TextWriter log,string step){providerStage=step;log.WriteLine("Provider step: "+step);log.Flush();}
    static string ProviderFailureDetail(Exception ex){
        // Never expose raw exception messages: FreshClam errors can contain subscription URLs.
        var parts=new List<string>();for(Exception e=ex;e!=null&&parts.Count<4;e=e.InnerException){
            var native=e as System.ComponentModel.Win32Exception;
            string code=e.GetType().Name+" (0x"+e.HResult.ToString("X8",CultureInfo.InvariantCulture)+(native==null?"":", Win32 "+native.NativeErrorCode)+")";
            // These exceptions are authored by our path/policy checks. Display only the known safe prefix and path/ACL details after redaction.
            string message=e.Message??"";
            message=Regex.Replace(message,@"(?i)https?://[^\s<>]+","[redacted URL]");
            message=Regex.Replace(message,@"(?i)[0-9a-f]{40,}","[redacted token]");
            if(message.Length>360)message=message.Substring(0,360)+"…";
            parts.Add(code+": "+message);
        }return String.Join(Environment.NewLine,parts);
    }
    static void ProviderPreflight(TextWriter log){
        ProviderStep(log,"locating the installed FreshClam configuration");
        if(!File.Exists(FreshConfig)||!File.Exists(FreshExe))throw new IOException("FreshClam executable or configuration file is missing. Configure / repair ClamAV first.");
        ProviderStep(log,"checking standard ClamAV registry paths");
        if(!StandardRegistryPaths(log))throw new IOException("A custom ClamAV configuration or database directory was detected. Review it locally.");
        ProviderStep(log,"checking FreshClam service executable and account");
        if(!NativeService("freshclam",FreshExe)||!LocalSystemUpdater())throw new IOException("FreshClam must be registered as the standard native LocalSystem service. Custom service registrations are not changed.");
        ProviderStep(log,"checking configuration and executable permissions");
        VerifyClamPath(ProgramFiles);VerifyClamPath(ClamRoot);VerifyClamPath(FreshExe);VerifyClamPath(FreshConfig);
    }
    static bool IsElevated(){using(var id=WindowsIdentity.GetCurrent())return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);}
    static int CheckClamAvForWizard(){
        // A normal wizard cannot inspect a configuration containing private subscription URLs.
        if(!IsElevated()&&Directory.Exists(Path.Combine(ClamRoot,"signature-logs")))return 13;
        try {
            if(IsElevated())using(var log=new StreamWriter(NewLogPath("check-clamav"))){try{return CheckClamAv(log);}catch(Exception ex){log.WriteLine(ex);throw;}}
            return CheckClamAv(TextWriter.Null);
        }catch(UnauthorizedAccessException){return 13;}catch(System.Security.SecurityException){return 13;}catch(Exception){return 14;}
    }
    static FileSecurity PrivateFeedFileAcl(bool serviceRead){
        var security=new FileSecurity();security.SetAccessRuleProtection(true,false);
        var admin=new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null);security.SetOwner(admin);
        foreach(var sid in new[]{admin,new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null)})security.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,AccessControlType.Allow));
        if(serviceRead)security.AddAccessRule(new FileSystemAccessRule(SignatureLogReader(),FileSystemRights.ReadAndExecute,AccessControlType.Allow));
        return security;
    }
    static string SecureSignatureLogs(){
        string folder=Path.Combine(ClamRoot,"signature-logs");VerifyClamPath(folder);
        var security=new DirectorySecurity();security.SetAccessRuleProtection(true,false);
        var admin=new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null);security.SetOwner(admin);
        foreach(var sid in new[]{admin,new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null)})security.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        // LinkScope reads only the recognized update timestamps, never native log lines into the API.
        security.AddAccessRule(new FileSystemAccessRule(SignatureLogReader(),FileSystemRights.ReadAndExecute,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        var dir=Directory.CreateDirectory(folder,security);dir.SetAccessControl(security);
        foreach(string p in Directory.EnumerateFiles(folder,"freshclam.log*")){VerifyClamPath(p);File.SetAccessControl(p,PrivateFeedFileAcl(true));}
        // Previously configured providers might already have put credentials in legacy native logs.
        foreach(string p in Directory.EnumerateFiles(ClamRoot,"freshclam.log*")){VerifyClamPath(p);File.SetAccessControl(p,PrivateFeedFileAcl(true));}
        return Path.Combine(folder,"freshclam.log");
    }
    static List<string> MergeProviderSources(List<string> previous,List<string> entered){
        var result=new List<string>(previous);
        foreach(string feed in entered){
            Uri newUri;if(!LinkScope.ClamProviderSources.TryParse(feed,out newUri))throw new InvalidDataException("Invalid signature source.");
            int index=result.FindIndex(old=>{Uri oldUri;return LinkScope.ClamProviderSources.TryParse(old,out oldUri)&&String.Equals(LinkScope.ClamProviderSources.Name(oldUri),LinkScope.ClamProviderSources.Name(newUri),StringComparison.OrdinalIgnoreCase);});
            if(index<0)result.Add(feed);
            else {Uri oldUri;LinkScope.ClamProviderSources.TryParse(result[index],out oldUri);if(!String.Equals(oldUri.DnsSafeHost,newUri.DnsSafeHost,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("A database filename is already assigned to a different provider. Review locally before changing it.");result[index]=feed;}
        }
        if(!LinkScope.ClamProviderSources.ValidSet(result))throw new InvalidDataException("Provider list exceeds the limit or contains duplicate filenames.");
        return result;
    }
    // Before deploying an upgrade, separate already configured standard feeds without downloading anything.
    // Custom installations are not taken over; the administrator must migrate those locally.
    static void PrepareProviderUpgrade(TextWriter log){
        if(!File.Exists(FreshConfig)||!File.Exists(FreshExe)||!Running("freshclam"))return;
        using(var mutex=new Mutex(false,@"Global\LinkScopeClamProvision")){
            bool locked=false;
            try{
                try{locked=mutex.WaitOne(0);}catch(AbandonedMutexException){locked=true;}
                if(!locked)throw new IOException("ClamAV maintenance is active. Retry the upgrade when it completes.");
                var cfg=ReadClamConfig(FreshConfig);
                if(!StandardRegistryPaths(log)||!NativeService("freshclam",FreshExe)||!LocalSystemUpdater()||cfg.Missing||cfg.Sample||!StandardConfig(cfg,true,log)){log.WriteLine("Non-standard updater preserved; review provider configuration locally.");return;}
                if(!cfg.Has("DatabaseCustomURL")&&cfg.One("Checks")=="24"&&String.Equals(cfg.One("TestDatabases"),"yes",StringComparison.OrdinalIgnoreCase)&&SamePath(cfg.One("NotifyClamd"),ClamdConfig))return;
                ProviderPreflight(log);
                using(var updater=new ServiceController("freshclam")){
                    LinkScope.ClamUpdateWorker.WaitForFreshClamServiceOnly(log,120);
                    try{
                        updater.Stop();updater.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(60));
                        LinkScope.ClamUpdateWorker.WaitForFreshClamExit(log,120);VerifyClamTree(ClamRoot);
                        if(cfg.Has("DatabaseCustomURL"))SecureSignatureLogs();
                        LinkScope.ClamUpdateWorker.SeparateStoppedUpdater(log);
                    }finally{
                        updater.Refresh();if(updater.Status==ServiceControllerStatus.StopPending)updater.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(60));
                        if(updater.Status==ServiceControllerStatus.Stopped){
                            if(ReadClamConfig(FreshConfig).Has("DatabaseCustomURL"))throw new IOException("Provider migration incomplete; updater remains stopped. Use Configure / repair ClamAV before retrying.");
                            LinkScope.ClamUpdateWorker.WaitForFreshClamExit(log,5);updater.Start();updater.WaitForStatus(ServiceControllerStatus.Running,TimeSpan.FromMinutes(2));
                        }
                    }
                }
                log.WriteLine("Official and third-party updater configurations separated; no provider download requested.");
            }finally{if(locked)mutex.ReleaseMutex();}
        }
    }
    static int EditProviderSources(TextWriter log){
        RequireAdmin();ProviderPreflight(log);
        ProviderStep(log,"validating existing FreshClam configuration");
        var config=ReadClamConfig(FreshConfig);
        if(config.Missing||config.Sample||!StandardConfig(config,true,log))throw new IOException("The existing FreshClam configuration needs review. See the preceding setup log entries; unsafe or custom settings are preserved.");
        if(!Running("freshclam"))throw new IOException("FreshClam is stopped. Use Configure / repair ClamAV first.");
        // StandardConfig refuses explicit TestDatabases no; an omitted directive is made explicit after consent.
        string originalConfig=File.ReadAllText(FreshConfig);
        ProviderStep(log,"opening the provider editor");
        List<string> legacy;if(!config.Values.TryGetValue("DatabaseCustomURL",out legacy))legacy=new List<string>();
        var managed=LinkScope.ClamUpdateWorker.ReadProviderPolicy();
        var previous=MergeProviderSources(managed.Select(x=>x.Url).ToList(),legacy);
        var shown=new List<string>();foreach(string feed in previous){Uri uri;if(LinkScope.ClamProviderSources.TryParse(feed,out uri))shown.Add(LinkScope.ClamProviderSources.Label(uri)+(LinkScope.ClamProviderSources.Suppresses(uri)?" (allow/ignore list)":""));}
        // The user pastes credentials into an elevated local-only editor, not browser settings.
        List<string> next=null;var intervals=new Dictionary<string,int>(StringComparer.OrdinalIgnoreCase);
        using(var form=new Form{Text="LinkScope Setup | Third-party signature sources",StartPosition=FormStartPosition.CenterScreen,ClientSize=new System.Drawing.Size(760,680),MinimumSize=new System.Drawing.Size(660,560),Font=new System.Drawing.Font("Segoe UI",10),AutoScaleMode=AutoScaleMode.Dpi}){
            var layout=new TableLayoutPanel{Dock=DockStyle.Fill,Padding=new Padding(16),ColumnCount=1,RowCount=8};
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));layout.RowStyles.Add(new RowStyle(SizeType.Percent,25));layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));layout.RowStyles.Add(new RowStyle(SizeType.Percent,45));layout.RowStyles.Add(new RowStyle(SizeType.Percent,30));layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            var title=new Label{Text="Configured custom databases (credentials hidden)",AutoSize=true};layout.Controls.Add(title,0,0);
            var current=new TextBox{Dock=DockStyle.Fill,Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.Vertical,Text=shown.Count==0?"No third-party sources configured.":String.Join(Environment.NewLine,shown.ToArray())};layout.Controls.Add(current,0,1);
            var hint=new Label{Text="Paste HTTPS URLs or DatabaseCustomURL lines (one per line), or leave blank to migrate existing sources. Set provider intervals in the second box: hostname=hours. Default 24; allowed 1–720 hours.",AutoSize=true,MaximumSize=new System.Drawing.Size(650,0)};layout.Controls.Add(hint,0,2);
            var input=new TextBox{Dock=DockStyle.Fill,Multiline=true,ScrollBars=ScrollBars.Both,WordWrap=false,MaxLength=262144,Font=new System.Drawing.Font("Consolas",10)};layout.Controls.Add(input,0,3);
            var schedule=new TextBox{Dock=DockStyle.Fill,Multiline=true,ScrollBars=ScrollBars.Vertical,MaxLength=32768,Font=new System.Drawing.Font("Consolas",10),Text=String.Join(Environment.NewLine,previous.Select(x=>new Uri(x).DnsSafeHost.ToLowerInvariant()).Distinct().Select(host=>host+"="+(managed.FirstOrDefault(x=>new Uri(x.Url).DnsSafeHost.Equals(host,StringComparison.OrdinalIgnoreCase))??new LinkScope.ProviderPolicyEntry{Hours=24}).Hours).ToArray())};layout.Controls.Add(schedule,0,4);
            var allow=new CheckBox{AutoSize=true,Text="I explicitly trust .ign2 / .wdb feeds, which may suppress detections."};layout.Controls.Add(allow,0,5);
            var caution=new Label{AutoSize=true,MaximumSize=new System.Drawing.Size(650,0),Text="Trust your provider and test in Monitor mode before enabling automatic responses. FreshClam validates database syntax, not the publisher of unsigned custom feeds. Saving separates custom sources from the official updater. Existing source cooldowns are never shortened. New hosts default to 24 hours between attempts."};layout.Controls.Add(caution,0,6);
            var buttons=new FlowLayoutPanel{AutoSize=true,Dock=DockStyle.Fill,FlowDirection=FlowDirection.RightToLeft};var cancel=new Button{Text="Cancel",AutoSize=true,DialogResult=DialogResult.Cancel};var save=new Button{Text="Save sources",AutoSize=true};buttons.Controls.Add(save);buttons.Controls.Add(cancel);layout.Controls.Add(buttons,0,7);
            form.Controls.Add(layout);form.CancelButton=cancel;
            save.Click+=(sender,args)=>{try{
                var entered=LinkScope.ClamProviderSources.ParseInput(input.Text);
                foreach(string feed in entered){Uri uri;LinkScope.ClamProviderSources.TryParse(feed,out uri);if(LinkScope.ClamProviderSources.Suppresses(uri)&&!allow.Checked)throw new InvalidDataException("Explicit approval is required for ignore-list and phishing allow-list databases.");}
                var candidate=MergeProviderSources(previous,entered);
                var hosts=new HashSet<string>(candidate.Select(x=>new Uri(x).DnsSafeHost),StringComparer.OrdinalIgnoreCase);intervals.Clear();
                foreach(string line in schedule.Lines){if(String.IsNullOrWhiteSpace(line))continue;var parts=line.Split('=');int hours;if(parts.Length!=2||!hosts.Contains(parts[0].Trim())||!Int32.TryParse(parts[1].Trim(),out hours)||hours<1||hours>720||intervals.ContainsKey(parts[0].Trim()))throw new InvalidDataException("Use one configured hostname=hours per line, from 1 to 720 hours.");intervals.Add(parts[0].Trim(),hours);}
                if(MessageBox.Show(form,"Save provider schedules and separate third-party downloads from the official updater? Existing databases are retained; migrated providers wait at least 24 hours. URLs are kept in administrator-only storage. No download is triggered by saving.","Confirm signature sources",MessageBoxButtons.YesNo,MessageBoxIcon.Warning,MessageBoxDefaultButton.Button2)!=DialogResult.Yes)return;
                next=entered;input.Clear();form.DialogResult=DialogResult.OK;form.Close();
            }catch(InvalidDataException ex){MessageBox.Show(form,ex.Message,"Invalid signature sources",MessageBoxButtons.OK,MessageBoxIcon.Warning);}catch(Exception){MessageBox.Show(form,"Unable to validate the supplied source list. No changes made.","Third-party signatures",MessageBoxButtons.OK,MessageBoxIcon.Error);}};
            if(form.ShowDialog()!=DialogResult.OK||next==null)return 1602;
        }
        // No plaintext URLs are written to application or setup logs, or passed on command lines.
        using(var mutex=new Mutex(false,@"Global\LinkScopeClamProvision")){
            bool locked=false;
            try{
                ProviderStep(log,"acquiring the ClamAV maintenance lock");
                try{locked=mutex.WaitOne(0);}catch(AbandonedMutexException){locked=true;}
                if(!locked)throw new IOException("Another ClamAV maintenance operation is active. Retry when finished.");
                ProviderPreflight(log);ProviderStep(log,"checking for configuration changes");
                if(!Running("freshclam"))throw new IOException("Updater state changed. Review Setup.");
                var current=ReadClamConfig(FreshConfig);List<string> existing;if(!current.Values.TryGetValue("DatabaseCustomURL",out existing))existing=new List<string>();
                if(!StandardConfig(current,true,log)||!existing.SequenceEqual(legacy,StringComparer.Ordinal)||!String.Equals(File.ReadAllText(FreshConfig),originalConfig,StringComparison.Ordinal))throw new IOException("Configuration changed since the editor was opened. Reopen the editor.");
                using(var updater=new ServiceController("freshclam")){
                    bool stopped=false;
                    try{
                        ProviderStep(log,"waiting for other FreshClam updates");LinkScope.ClamUpdateWorker.WaitForFreshClamServiceOnly(log,120);
                        ProviderStep(log,"stopping the FreshClam updater");updater.Stop();updater.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(60));stopped=true;
                        LinkScope.ClamUpdateWorker.WaitForFreshClamExit(log,120);VerifyClamTree(ClamRoot);
                        if(!NativeService("freshclam",FreshExe)||!LocalSystemUpdater()||!String.Equals(File.ReadAllText(FreshConfig),originalConfig,StringComparison.Ordinal))throw new IOException("Updater identity or configuration changed during maintenance.");
                        SecureSignatureLogs();
                        ProviderStep(log,"separating the official updater from provider sources");LinkScope.ClamUpdateWorker.SeparateStoppedUpdater(log);
                        ProviderStep(log,"saving provider intervals");LinkScope.ClamUpdateWorker.SaveManagedProviders(new string[0],next,intervals);
                    }finally{
                        updater.Refresh();if(updater.Status==ServiceControllerStatus.StopPending)updater.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(60));
                        if(stopped||updater.Status==ServiceControllerStatus.Stopped){
                            if(ReadClamConfig(FreshConfig).Has("DatabaseCustomURL"))throw new IOException("Migration incomplete; updater left stopped to prevent unscheduled provider downloads. Retry provider setup as administrator.");
                            LinkScope.ClamUpdateWorker.WaitForFreshClamExit(log,5);updater.Refresh();if(updater.Status==ServiceControllerStatus.Stopped)updater.Start();updater.WaitForStatus(ServiceControllerStatus.Running,TimeSpan.FromMinutes(2));
                        }
                    }
                }
                log.WriteLine("Provider schedules saved; official FreshClam restarted without third-party URLs. No provider download requested by the editor.");return 0;
            }finally{if(locked)mutex.ReleaseMutex();}
        }
    }
    static int UpdateClamSignatures(TextWriter log) {
        if(MessageBox.Show("Run an immediate signature update using the installed FreshClam and its approved local configuration? The FreshClam updater will briefly stop and restart. The ClamD scanner remains running.","LinkScope | Update signatures",MessageBoxButtons.YesNo,MessageBoxIcon.Question,MessageBoxDefaultButton.Button2)!=DialogResult.Yes)return 1602;
        return LinkScope.ClamUpdateWorker.Update(log,true);
    }
    static int ConfigureClamAv(TextWriter log) {
        int initial=CheckClamAv(log);
        if(initial==0){log.WriteLine("ClamAV already configured and responding; no changes.");return 0;}
        if(initial==ClamMissing||initial==ClamCustom||initial==ClamPartial)return initial;
        if(MessageBox.Show("Configure or repair the standard ClamAV installation?\r\n\r\nSetup will create missing configurations (backing up untouched examples), download official signatures if needed, install missing native services, set both to automatic startup and test 127.0.0.1:3310. Existing custom configurations are preserved.\r\n\r\nFreshClam requires Internet access or already provisioned definitions. Existing approved custom feeds are migrated into the separate provider policy before starting a stopped updater. Continue only if you trust this installed engine and its configuration. LinkScope protection modes and settings will not be changed.","LinkScope Setup | Configure ClamAV",MessageBoxButtons.YesNo,MessageBoxIcon.Question,MessageBoxDefaultButton.Button2)!=DialogResult.Yes)return 1602;
        // Recheck after consent and refuse concurrent provisioning or changed/custom paths.
        using(var mutex=new Mutex(false,@"Global\LinkScopeClamProvision")) {
            bool locked=false;
            try {
                try{locked=mutex.WaitOne(0);}catch(AbandonedMutexException){locked=true;}
                if(!locked)throw new IOException("Another ClamAV configuration operation is in progress.");
                initial=CheckClamAv(log);if(initial==0)return 0;if(initial==ClamMissing||initial==ClamCustom||initial==ClamPartial)return initial;
                VerifyClamPath(ProgramFiles);VerifyClamTree(ClamRoot);
                if(HasPortListener()) {
                    if(!Running("clamd")||!LoopbackOnly()||ClamCommand("PING")!="PONG")throw new IOException("Port 3310 already in use or exposed beyond loopback; no services or configuration will be changed.");
                }
                var daemon=ReadClamConfig(ClamdConfig);var updater=ReadClamConfig(FreshConfig);
                if(((daemon.Missing||daemon.Sample)&&Running("clamd"))||((updater.Missing||updater.Sample)&&Running("freshclam")))throw new IOException("A ClamAV service is running with missing/default configuration; review it manually before repair.");
                Directory.CreateDirectory(ClamDatabase);VerifyClamPath(ClamDatabase);
                WriteMissingConfig(ClamdConfig,false,log);WriteMissingConfig(FreshConfig,true,log);
                VerifyClamPath(ClamdConfig);VerifyClamPath(FreshConfig);
                if(!StandardConfig(ReadClamConfig(ClamdConfig),false,log)||!StandardConfig(ReadClamConfig(FreshConfig),true,log))throw new IOException("Configuration changed unexpectedly; setup stopped.");
                if(!Running("freshclam")){LinkScope.ClamUpdateWorker.WaitForFreshClamExit(log,120);LinkScope.ClamUpdateWorker.SeparateStoppedUpdater(log);}
                if(!DatabasesPresent()||initial==ClamStale) {
                    if(!Running("freshclam")&&!FreshClamProcessPresent()){
                        string previous=null;try{previous=LinkScope.ClamUpdateWorker.DatabaseFingerprint();}catch(Exception ex){log.WriteLine("Previous database fingerprint unavailable: "+ex.Message);}
                        RunClamTool(FreshExe,"--config-file=\""+FreshConfig+"\"",900000,log);
                        try{LinkScope.ClamUpdateState.RecordProvisioning(previous!=null&&previous!=LinkScope.ClamUpdateWorker.DatabaseFingerprint());}catch(Exception ex){log.WriteLine("Signature timestamp recording failed: "+ex.Message);}
                    }
                    else log.WriteLine("FreshClam already running (service or standalone); no concurrent updater started.");
                }
                if(!DatabasesPresent())throw new IOException("Required main and daily signature files are missing. Check FreshClam logs / network access, then retry.");
                EnsureService("clamd",ClamdExe,log);
                // Wait for definitions to finish loading, not just for an open TCP socket.
                string version=null;var clock=Stopwatch.StartNew();
                while(clock.Elapsed<TimeSpan.FromMinutes(2)) {
                    try{if(ClamCommand("PING")=="PONG"){version=ClamCommand("VERSION");if(version.StartsWith("ClamAV",StringComparison.OrdinalIgnoreCase))break;}}catch(Exception){}
                    version=null;Thread.Sleep(1000);
                }
                if(version==null)throw new IOException("ClamD did not respond to PING and VERSION on 127.0.0.1:3310.");
                string scan=ClamCommand("INSTREAM");log.WriteLine("Harmless scan test: "+scan);
                if(!scan.EndsWith(": OK",StringComparison.Ordinal))throw new IOException("Harmless ClamD scan test failed.");
                if(!Running("freshclam"))LinkScope.ClamUpdateWorker.WaitForFreshClamExit(log,120);
                EnsureService("freshclam",FreshExe,log);
                int final=CheckClamAv(log);
                log.WriteLine("Final readiness status: "+final+" (0 = ready). No LinkScope monitoring policy changed.");return final;
            } finally {if(locked)mutex.ReleaseMutex();}
        }
    }
}
