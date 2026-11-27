using System;
using System.Diagnostics;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace LinkScope {
    internal sealed class MonitorHost : IDisposable {
        FileStream instance;
        Collector collector;
        Web web;
        AlertDelivery outputs;
        AppJournal journal;
        internal void Start() {
            System.Net.ServicePointManager.SecurityProtocol=System.Net.SecurityProtocolType.SystemDefault;
            var c=Config.Load();
            instance=new FileStream(Path.Combine(Config.Data,"collector.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);
            try {
                journal=new AppJournal(AppJournal.Filename,c.Logging,true,c.Siem,c.DatabaseMaintenance);journal.Start();AppJournal.Current=journal;
                AppJournal.Event(LogLevel.Info,"Service","start","Starting monitor.");
                AppJournal.Event(LogLevel.Debug,"Settings","load","Configuration loaded.");
                var alerts=new Alerts();
                outputs=new AlertDelivery(alerts,Config.Db,c.Delivery);
                outputs.Start();
                collector=new Collector(c,alerts);
                collector.Start();
                web=new Web(c,collector,alerts,outputs);
                web.Start();
                AppJournal.Event(LogLevel.Info,"Service","ready","Monitoring service is ready.");
            } catch(Exception ex) {AppJournal.Fault("Service","start",ex);Dispose();throw;}
        }
        public void Dispose() {
            if(web!=null) { web.Dispose(); web=null; }
            if(collector!=null) { collector.Dispose(); collector=null; }
            if(outputs!=null) { outputs.Dispose(); outputs=null; }
            if(journal!=null){AppJournal.Event(LogLevel.Info,"Service","stop","Monitor stopped.");journal.Dispose();journal=null;}
            if(instance!=null) { instance.Dispose(); instance=null; }
        }
    }
    internal sealed class MonitorService : ServiceBase {
        readonly MonitorHost host=new MonitorHost();
        internal MonitorService() { ServiceName=Program.Name; CanShutdown=true; }
        protected override void OnStart(string[] args) {
            try { host.Start(); } catch(Exception ex) { Program.Log(ex); throw; }
        }
        protected override void OnStop() { RequestAdditionalTime(60000); host.Dispose(); }
        protected override void OnShutdown() { host.Dispose(); }
    }
    internal static class Program {
        internal const string Name="LinkScope";
        static readonly object LogLock=new object();
        static SecurityIdentifier Sid(WellKnownSidType t) { return new SecurityIdentifier(t,null); }
        internal static byte[] Resource(string name) {
            using(var s=Assembly.GetExecutingAssembly().GetManifestResourceStream(name)) {
                if(s==null) throw new InvalidDataException("Missing embedded resource "+name);
                using(var m=new MemoryStream()) { s.CopyTo(m); return m.ToArray(); }
            }
        }
        internal static void Log(Exception ex) {
            if(AppJournal.Current!=null){AppJournal.Fault("Service","runtime",ex);return;}
            BootstrapError(ex.GetBaseException().GetType().Name+" (HRESULT "+ex.GetBaseException().HResult.ToString("X8")+").");
        }
        internal static void BootstrapError(string message){
            try {
                lock(LogLock) {
                    string path=Path.Combine(Config.Data,"service.log");
                    if(File.Exists(path) && new FileInfo(path).Length>1024*1024) {
                        if(File.Exists(path+".1")) File.Delete(path+".1");
                        File.Move(path,path+".1");
                    }
                    File.AppendAllText(path,DateTime.UtcNow.ToString("o")+" "+message+Environment.NewLine);
                }
            } catch(IOException) { } catch(UnauthorizedAccessException) { }
        }
        static void RequireAdmin() {
            using(var id=WindowsIdentity.GetCurrent()) {
                if(!new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator))
                    throw new UnauthorizedAccessException("Open PowerShell as Administrator and retry.");
            }
        }
        static void SecureDir(string path,bool writable,bool acceptInstallingOwner=false) {
            var admin=Sid(WellKnownSidType.BuiltinAdministratorsSid);
            var system=Sid(WellKnownSidType.LocalSystemSid);
            var local=ServiceSid();
            var sec=new DirectorySecurity();
            sec.SetAccessRuleProtection(true,false);
            sec.SetOwner(admin);
            var inheritance=InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit;
            foreach(var sid in new[]{admin,system,local})
                sec.AddAccessRule(new FileSystemAccessRule(sid,sid.Equals(local) ?
                    (writable ? FileSystemRights.Modify : FileSystemRights.ReadAndExecute) : FileSystemRights.FullControl,
                    inheritance,PropagationFlags.None,AccessControlType.Allow));
            var info=Directory.CreateDirectory(path,sec);
            if((info.Attributes&FileAttributes.ReparsePoint)!=0)
                throw new IOException("Unexpected directory link: "+path);
            var owner=info.GetAccessControl().GetOwner(typeof(SecurityIdentifier));
            bool ownedByInstaller=false;
            if(acceptInstallingOwner) {
                using(var id=WindowsIdentity.GetCurrent()) ownedByInstaller=id.User.Equals(owner);
            }
            if(!admin.Equals(owner) && !system.Equals(owner) && !ownedByInstaller)
                throw new UnauthorizedAccessException("Unexpected owner of "+path+". Verify that directory before installing.");
            Console.WriteLine("Checking directory permissions: "+path);
            var sections=AccessControlSections.Access|AccessControlSections.Owner;
            if(info.GetAccessControl(sections).GetSecurityDescriptorSddlForm(sections)!=sec.GetSecurityDescriptorSddlForm(sections)){
                Console.WriteLine("Applying directory permissions: "+path);
                info.SetAccessControl(sec);
            }
            Console.WriteLine("Directory permissions ready: "+path);
        }
        internal static SecurityIdentifier ServiceSid() {
            // Service SID is deterministic and available before the first SCM registration.
            using(var sha=System.Security.Cryptography.SHA1.Create()){
                var hash=sha.ComputeHash(Encoding.Unicode.GetBytes(Name.ToUpperInvariant()));
                return new SecurityIdentifier("S-1-5-80-"+string.Join("-",Enumerable.Range(0,5).Select(i=>BitConverter.ToUInt32(hash,i*4).ToString(System.Globalization.CultureInfo.InvariantCulture))));
            }
        }
        static void PrepareCertificate(){RunSetupScript("certificate.ps1","");}
        static void RunSetupScript(string resource,string action){
            RequireAdmin(); var info=Telemetry.PowerShell(Encoding.UTF8.GetString(Resource(resource)));
            info.EnvironmentVariables["LINKSCOPE_TASK_ACTION"]=action;
            using(var p=Process.Start(info)){
                var output=p.StandardOutput.ReadToEndAsync();var errors=p.StandardError.ReadToEndAsync();
                if(!p.WaitForExit(60000)){p.Kill();throw new System.TimeoutException("Windows setup operation timed out.");}
                if(p.ExitCode!=0)throw new InvalidOperationException("Windows setup operation failed. "+errors.Result);
                output.Wait();
            }
        }
        static void InitConfig() {
            RequireAdmin();
            SecureDir(Config.Root,false);
            SecureDir(Config.Data,true);
            SecureDir(Config.SettingsDir,true);
            AdminPasswords.Installed.Initialize();
            if(!File.Exists(Config.FilePath)) {
                string legacy=Path.Combine(Config.Root,"config.json");
                var c=Config.Json().Deserialize<Config>(File.Exists(legacy)?File.ReadAllText(legacy):Encoding.UTF8.GetString(Resource("default.json")));
                c.BindAddress="127.0.0.1";c.HostName="localhost";c.UseHttps=false;c.RequireLogin=true;
                Config.Save(Config.FilePath,Config.Validate(c));
            }
            Console.WriteLine("Configuration: "+Config.FilePath);
        }
        // Quote arguments according to the Windows command-line rules, including embedded quotes.
        static string Quote(string arg) {
            var b=new StringBuilder("\""); int slashes=0;
            foreach(char c in arg) {
                if(c=='\\') { slashes++; continue; }
                if(c=='"') { b.Append('\\',2*slashes+1); b.Append('"'); }
                else { b.Append('\\',slashes); b.Append(c); }
                slashes=0;
            }
            b.Append('\\',2*slashes); b.Append('"');
            return b.ToString();
        }
        static void Sc(params string[] args) {
            string exe=Path.Combine(Environment.SystemDirectory,"sc.exe");
            var info=new ProcessStartInfo(exe,string.Join(" ",args.Select(Quote))) {UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
            using(var p=Process.Start(info)) {
                var output=p.StandardOutput.ReadToEndAsync();var errors=p.StandardError.ReadToEndAsync();
                if(!p.WaitForExit(30000)){try{p.Kill();}catch{}throw new System.TimeoutException("sc.exe "+args[0]+" timed out.");}Console.WriteLine(output.Result);Console.Error.WriteLine(errors.Result);
                if(p.ExitCode!=0) throw new InvalidOperationException("sc.exe "+args[0]+" failed ("+p.ExitCode+").");
            }
        }
        static readonly string InstallDir=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),Name);
        static readonly string ServiceExe=Path.Combine(InstallDir,Name+".exe");
        static string ServiceCommand(string exe) { return "\""+exe+"\" --service"; }
        static bool Same(string a,string b) { return string.Equals(a,b,StringComparison.OrdinalIgnoreCase); }

        // Accept the service signature created by both installer versions. A broken legacy
        // executable can be inaccessible or missing, so only inspect SCM metadata here.
        static string RegisteredCommand() {
            using(var key=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\"+Name)) {
                if(key==null) return null;
                string command=Convert.ToString(key.GetValue("ImagePath"));
                string suffix="\" --service";
                if(command.StartsWith("\"",StringComparison.Ordinal) && command.EndsWith(suffix,StringComparison.OrdinalIgnoreCase)
                    && command.Length>1+suffix.Length) {
                    string file=command.Substring(1,command.Length-1-suffix.Length);
                    if(file.IndexOf('"')<0 && Path.IsPathRooted(file) && Same(Path.GetFileName(file),Name+".exe")
                        && Same(Convert.ToString(key.GetValue("DisplayName")),"LinkScope Network Monitor")
                        && Same(Convert.ToString(key.GetValue("ObjectName")),@"NT AUTHORITY\LocalService")
                        && Convert.ToInt32(key.GetValue("Type"))==16) return command;
                }
                throw new InvalidOperationException("A different registration uses the name LinkScope. Inspect it with sc.exe qc LinkScope.");
            }
        }
        static string UsnCommand(){return "\""+ServiceExe+"\" --usn-service";}
        static bool UsnRegistered(){
            using(var key=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\"+UsnJournalService.Name)){
                if(key==null)return false;
                if(!Same(Convert.ToString(key.GetValue("ImagePath")),UsnCommand())||!Same(Convert.ToString(key.GetValue("ObjectName")),"LocalSystem")||Convert.ToInt32(key.GetValue("Type"))!=16)
                    throw new InvalidOperationException("Unexpected LinkScopeUsn service registration; inspect sc.exe qc LinkScopeUsn.");
                return true;
            }
        }
        static void StopUsn(){if(!UsnRegistered())return;using(var svc=new ServiceController(UsnJournalService.Name)){
            if(svc.Status==ServiceControllerStatus.StartPending)svc.WaitForStatus(ServiceControllerStatus.Running,TimeSpan.FromSeconds(20));
            svc.Refresh();if(svc.Status!=ServiceControllerStatus.Stopped){if(svc.Status!=ServiceControllerStatus.StopPending)svc.Stop();svc.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(20));}
        }}
        static void InstallUsn(){
            if(!UsnRegistered())Sc("create",UsnJournalService.Name,"binPath=",UsnCommand(),"start=","auto","obj=","LocalSystem","DisplayName=","LinkScope NTFS Journal Reader");
            using(var svc=new ServiceController(UsnJournalService.Name)){if(svc.Status==ServiceControllerStatus.Stopped)svc.Start();svc.WaitForStatus(ServiceControllerStatus.Running,TimeSpan.FromSeconds(20));}
        }
        static void RemoveUsn(){if(!UsnRegistered())return;StopUsn();Sc("delete",UsnJournalService.Name);}
        static void DeployExecutable() {
            SecureDir(InstallDir,false,true);
            string source=Assembly.GetExecutingAssembly().Location;
            if(File.Exists(ServiceExe) && (File.GetAttributes(ServiceExe)&FileAttributes.ReparsePoint)!=0)
                throw new IOException("Unexpected executable link at "+ServiceExe);
            if(!Same(source,ServiceExe)) {
                string stage=Path.Combine(InstallDir,Guid.NewGuid().ToString("N")+".tmp");
                try {
                    // Creating a new stream here inherits the installation directory ACL,
                    // including when the source file lives inside a private user profile.
                    using(var input=File.OpenRead(source))
                    using(var output=new FileStream(stage,FileMode.CreateNew,FileAccess.Write,FileShare.None))
                        input.CopyTo(output);
                    if(File.Exists(ServiceExe)) File.Replace(stage,ServiceExe,null);
                    else File.Move(stage,ServiceExe);
                } finally { if(File.Exists(stage)) File.Delete(stage); }
            }
            // ReplaceFile can retain a pre-existing executable's protected ACL.
            var acl=new FileSecurity();
            acl.SetAccessRuleProtection(true,false);
            acl.AddAccessRule(new FileSystemAccessRule(Sid(WellKnownSidType.BuiltinAdministratorsSid),FileSystemRights.FullControl,AccessControlType.Allow));
            acl.AddAccessRule(new FileSystemAccessRule(Sid(WellKnownSidType.LocalSystemSid),FileSystemRights.FullControl,AccessControlType.Allow));
            acl.AddAccessRule(new FileSystemAccessRule(ServiceSid(),FileSystemRights.ReadAndExecute,AccessControlType.Allow));
            File.SetAccessControl(ServiceExe,acl);
        }
        static void StartAndWait() {
            using(var svc=new ServiceController(Name)) {
                if(svc.Status==ServiceControllerStatus.Stopped) svc.Start();
                var timer=Stopwatch.StartNew();
                do {
                    svc.Refresh();
                    if(svc.Status==ServiceControllerStatus.Running) return;
                    if(svc.Status==ServiceControllerStatus.Stopped)
                        throw new InvalidOperationException("The service process stopped during startup.");
                    Thread.Sleep(250);
                } while(timer.Elapsed<TimeSpan.FromSeconds(60));
                throw new System.TimeoutException("Windows did not report Running within 60 seconds.");
            }
        }
        internal static bool ServiceMode { get; private set; }
        internal static void QueueServiceRestart(){
            var command=new ProcessStartInfo(Path.Combine(Environment.SystemDirectory,"schtasks.exe"),
                "/Run /TN "+Quote(@"\Unixfor LinkScope Restart")){UseShellExecute=false,CreateNoWindow=true};
            using(var child=Process.Start(command)){
                if(!child.WaitForExit(5000)||child.ExitCode!=0)
                    throw new HttpError(503,"Windows could not confirm the restart task. Check Task Scheduler or run Restart-Service LinkScope on the host.");
            }
        }
        static readonly object signatureQueueGate=new object();
        static long lastQueuedSignature;
        internal static void QueueSignatureUpdate(){lock(signatureQueueGate){
            if(!ServiceMode)throw new HttpError(409,"Install LinkScope as a Windows service to use dashboard signature updates.");
            if(History.Now()-lastQueuedSignature<60)throw new HttpError(409,"A signature update was just requested; wait for task status.");
            var state=ClamUpdateState.Read();if(state.status=="Unavailable")throw new HttpError(503,"Trusted signature status is unavailable. Review registry permissions in Setup.");if(state.Busy||state.CoolingDown)throw new HttpError(409,"A signature update is running or was attempted within the last 60 minutes.");
            var command=new ProcessStartInfo(Path.Combine(Environment.SystemDirectory,"schtasks.exe"),"/Run /TN "+Quote(@"\Unixfor LinkScope Signature Update")){UseShellExecute=false,CreateNoWindow=true};
            using(var child=Process.Start(command)){if(!child.WaitForExit(5000)||child.ExitCode!=0)throw new HttpError(503,"Signature task unavailable. Upgrade LinkScope using Setup and verify the ClamAV services.");}
            lastQueuedSignature=History.Now();
        }}
        static int RefreshInstalledClamPeerAccess(){
            using(var id=WindowsIdentity.GetCurrent())if(!id.IsSystem)throw new UnauthorizedAccessException("Only the installed SYSTEM task may refresh ClamD query access.");
            if(!Same(Assembly.GetExecutingAssembly().Location,ServiceExe)||!Same(RegisteredCommand(),ServiceCommand(ServiceExe)))throw new UnauthorizedAccessException("Unexpected installed service path.");
            using(var gate=new FileStream(Path.Combine(Config.Root,"maintenance.lock"),FileMode.Open,FileAccess.ReadWrite,FileShare.None)){
                var policy=Config.Load().Endpoint;
                if(!policy.Enabled||policy.Mode=="monitor")return 0;
                string standard=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"ClamAV","clamd.exe");
                if(policy.Port!=3310||!Same(policy.TrustedEnginePath,standard))return 3;
                return EndpointResponse.RefreshClamPeerAccess(ServiceSid())?0:3;
            }
        }
        static int UpdateInstalledSignatures(){
            using(var id=WindowsIdentity.GetCurrent())if(!id.IsSystem)throw new UnauthorizedAccessException("Only the installed SYSTEM task may run this operation.");
            if(!Same(Assembly.GetExecutingAssembly().Location,ServiceExe)||!Same(RegisteredCommand(),ServiceCommand(ServiceExe)))throw new UnauthorizedAccessException("Unexpected installed service path.");
            // The worker and setup share a cross-process mutex. Hold the same maintenance lock used by install/uninstall.
            using(var maintenance=new FileStream(Path.Combine(Config.Root,"maintenance.lock"),FileMode.Open,FileAccess.ReadWrite,FileShare.None)){
                // The endpoint scanner publishes failed updates through the normal alert pipeline, including Event Viewer only when enabled.
                return ClamUpdateWorker.Update(Console.Out,true);
            }
        }
        static void RestartInstalledService(){
            using(var id=WindowsIdentity.GetCurrent())if(!id.IsSystem)throw new UnauthorizedAccessException("The installed restart task runs this operation.");
            using(var maintenance=new FileStream(Path.Combine(Config.Root,"maintenance.lock"),FileMode.Open,FileAccess.ReadWrite,FileShare.None))
            using(var svc=new ServiceController(Name)){
                if(!Same(RegisteredCommand(),ServiceCommand(ServiceExe)))throw new InvalidOperationException("Unexpected service registration.");
                if(svc.Status!=ServiceControllerStatus.Running)throw new InvalidOperationException("LinkScope is not running.");
                Sc("stop",Name);
                svc.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(90));
                StartAndWait();
            }
        }
        static bool canarySetupWarning;
        // Enrollment runs before starting the service, under the existing maintenance lock.
        static void EnrollSetupCanaries(string token) {
            if(string.IsNullOrEmpty(token))return;
            var parts=Encoding.UTF8.GetString(Convert.FromBase64String(token)).Split('|');
            if(parts.Length!=2)throw new InvalidDataException("Invalid canary enrollment request.");
            string folder=parts[0],sid=new SecurityIdentifier(parts[1]).Value;
            string registered=CanaryTemplates.RegisteredFolder(sid);
            if(registered!=null&&!string.Equals(registered,folder,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Registered canary folder differs from recovery request.");
            Console.WriteLine("Canary enrollment: verify originals");
            CanaryTemplates.Verify(folder);
            var cfg=Config.Load();var ep=cfg.Endpoint;
            var files=CanaryTemplates.Names.Select(name=>Path.Combine(folder,name)).ToArray();
            // Monitor only the three decoys, never the entire Documents directory.
            if(files.Any(path=>EndpointProtection.Excluded(ep,path)))throw new InvalidDataException("Canary paths conflict with existing exclusions. Review Endpoint Protection settings.");
            ep.Paths=ep.Paths.Concat(files.Where(path=>!ep.Paths.Any(root=>EndpointProtection.Under(path,root)))).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            ep.CanaryPaths=ep.CanaryPaths.Concat(files).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            if(!ep.Enabled&&ep.Mode=="monitor")ep.Enabled=true;
            ep.Validate();
            Console.WriteLine("Canary enrollment: seed immutable baselines");
            using(var endpoint=new EndpointProtection())endpoint.SeedSetupCanaries(folder);
            Console.WriteLine("Canary enrollment: save policy");
            Config.Save(Config.FilePath,Config.Validate(cfg));
            Console.WriteLine("Canary enrollment: register owner");
            CanaryTemplates.Register(sid,folder);
            try{UserAudit.Init();UserAudit.Write("setup","local","Registered three synthetic canaries for "+sid+" in "+folder,200,"Success");}catch(Exception ex){Console.Error.WriteLine("Canary audit: "+ex.Message);}
            Console.WriteLine("Canary files enrolled: "+folder+(ep.Enabled?" (monitoring enabled).":" (existing disabled response policy preserved; enable monitoring manually)."));
        }
        // SID comes from the unelevated wizard, not the account used to approve UAC.
        static string SetupProfileRoot(string sid) {
            if(string.IsNullOrEmpty(sid))return null;
            sid=new SecurityIdentifier(sid).Value;
            if((!sid.StartsWith("S-1-5-21-",StringComparison.Ordinal)&&!sid.StartsWith("S-1-12-1-",StringComparison.Ordinal))||sid.Length>184)return null;
            using(var key=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\"+sid)){
                string raw=key==null?null:key.GetValue("ProfileImagePath") as string;
                if(string.IsNullOrWhiteSpace(raw)||raw.Length<3||raw[1]!=':'||raw[2]!='\\')return null;
                string path=Path.GetFullPath(raw).TrimEnd('\\');string root=Path.GetPathRoot(path);
                if(root==null||root.Length!=3||path.Length<=3||path.Substring(2).Contains(":")||new DriveInfo(root).DriveType!=DriveType.Fixed||!Directory.Exists(path))return null;
                if(EndpointProtection.Under(path,Environment.GetFolderPath(Environment.SpecialFolder.Windows))||EndpointProtection.Under(path,Config.Root)||EndpointProtection.Under(Config.Root,path))return null;
                EndpointProtection.SafePath(path);return path;
            }
        }
        internal static void ApplyProfileDefaults(EndpointSettings ep,string profile,bool fresh) {
            if(ep.ProfileDefaultsApplied||string.IsNullOrEmpty(profile))return;
            // Preserve a deliberate disabled policy on upgrade, including its scope and exclusions.
            if(!fresh&&!ep.Enabled&&ep.Paths.Length>0){ep.ProfileDefaultsApplied=true;return;}
            bool unconfigured=!ep.Enabled&&ep.Paths.Length==0;
            if(!ep.Paths.Any(root=>EndpointProtection.Under(profile,root)))ep.Paths=ep.Paths.Concat(new[]{profile}).ToArray();
            // Existing explicit exclusions are preserved. Only narrowly scoped, background-only caches are seeded.
            var relative=new[]{@"AppData\Local\Microsoft\Windows\INetCache",@"AppData\Local\Google\Chrome\User Data\Default\Cache",@"AppData\Local\Google\Chrome\User Data\Default\Code Cache",@"AppData\Local\Google\Chrome\User Data\Default\GPUCache",@"AppData\Local\Microsoft\Edge\User Data\Default\Cache",@"AppData\Local\Microsoft\Edge\User Data\Default\Code Cache",@"AppData\Local\Microsoft\Edge\User Data\Default\GPUCache","NTUSER.DAT","NTUSER.DAT.LOG1","NTUSER.DAT.LOG2",@"AppData\Local\Microsoft\Windows\UsrClass.dat",@"AppData\Local\Microsoft\Windows\UsrClass.dat.LOG1",@"AppData\Local\Microsoft\Windows\UsrClass.dat.LOG2"};
            var defaults=relative.Select(p=>Path.Combine(profile,p)).ToList();
            // Firefox names profiles dynamically. Enumerate only immediate profile directories, never their contents.
            string firefox=Path.Combine(profile,@"AppData\Local\Mozilla\Firefox\Profiles");
            try{if(Directory.Exists(firefox)){EndpointProtection.SafePath(firefox);foreach(var sub in Directory.EnumerateDirectories(firefox).Take(20)){if((File.GetAttributes(sub)&FileAttributes.ReparsePoint)!=0)continue;defaults.Add(Path.Combine(sub,"cache2"));defaults.Add(Path.Combine(sub,"startupCache"));}}}
            catch(IOException){}catch(UnauthorizedAccessException){}
            ep.BackgroundExcludedPaths=(ep.BackgroundExcludedPaths??new string[0]).Concat(defaults).Distinct(StringComparer.OrdinalIgnoreCase).Take(100).ToArray();
            if(fresh||unconfigured){ep.Enabled=true;ep.RealTime=true;ep.Mode="monitor";ep.IntervalSeconds=86400;ep.MaxFileMiB=100;}
            ep.ProfileDefaultsApplied=true;ep.Validate();
        }
        static void Install(bool upgrade=false,string canaryToken=null) {
            string profileSid=null;
            if(!string.IsNullOrEmpty(canaryToken)){
                var payload=Encoding.UTF8.GetString(Convert.FromBase64String(canaryToken)).Split('|');
                if(payload.Length==3&&payload[0]=="profile-v1"){
                    profileSid=new SecurityIdentifier(payload[1]).Value;
                    canaryToken=string.IsNullOrEmpty(payload[2])?null:payload[2];
                }else if(payload.Length==2)profileSid=new SecurityIdentifier(payload[1]).Value;
            }
            // CLI fallback is the invoking interactive account; never select a service profile.
            if(profileSid==null&&Environment.UserInteractive&&Process.GetCurrentProcess().SessionId!=0)profileSid=WindowsIdentity.GetCurrent().User.Value;
            bool fresh=!File.Exists(Config.FilePath)&&!File.Exists(Path.Combine(Config.Root,"config.json"));
            Console.WriteLine("Setup: self-check");
            SelfCheck.Run();
            Console.WriteLine("Setup: initialize configuration");
            InitConfig();
            Config.Load();
            using(var gate=new FileStream(Path.Combine(Config.Root,"maintenance.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None)) {
                string old=RegisteredCommand(), command=ServiceCommand(ServiceExe);
                UsnRegistered(); // validate ownership before stopping the existing monitor
                Console.WriteLine("Service executable: "+ServiceExe);
                Console.WriteLine("Service account: NT AUTHORITY\\LocalService");
                bool active=false;
                if(old!=null) {
                    Console.WriteLine("Current registration: "+old);
                    using(var svc=new ServiceController(Name)) {
                        if(svc.Status==ServiceControllerStatus.StartPending)
                            svc.WaitForStatus(ServiceControllerStatus.Running,TimeSpan.FromSeconds(60));
                        if(svc.Status==ServiceControllerStatus.StopPending)
                            svc.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(65));
                        svc.Refresh();
                        active=svc.Status!=ServiceControllerStatus.Stopped;
                        if(upgrade && Same(old,command) && svc.Status==ServiceControllerStatus.Running) {
                            svc.Stop(); svc.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(90)); active=false;
                        }
                        else if(Same(old,command) && svc.Status==ServiceControllerStatus.Running) {
                            Console.WriteLine("LinkScope is already running from the installed path. To deploy this build, stop LinkScope in elevated PowerShell, then run this installer again."); return;
                        }
                    }
                }
                if(active && Same(old,command)) {
                    throw new InvalidOperationException("The installed service is busy or paused. Check sc.exe queryex LinkScope.");
                }
                Console.WriteLine("Setup: stop NTFS journal reader before deployment");
                StopUsn();
                Console.WriteLine("Setup: deploy service executable");
                DeployExecutable();
                if(old==null) Sc("create",Name,"binPath=",command,"start=","auto","obj=","NT AUTHORITY\\LocalService","DisplayName=","LinkScope Network Monitor");
                else if(!Same(old,command)) {
                    Sc("config",Name,"binPath=",command);
                    if(active) {
                        using(var svc=new ServiceController(Name)) {
                            svc.Stop(); svc.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(65));
                        }
                    }
                }
                Sc("sidtype",Name,"unrestricted");
                if(!EventLog.SourceExists("Unixfor LinkScope")) EventLog.CreateEventSource("Unixfor LinkScope","Application");
                Console.WriteLine("Setup: prepare certificate");
                try { PrepareCertificate(); }
                catch(Exception ex) {
                    if(Config.Load().UseHttps && Config.Load().CertificateThumbprint.Length==0)throw;
                    Console.Error.WriteLine("Self-signed certificate unavailable: "+ex.Message+" Run --prepare-certificate before selecting it.");
                }
                Console.WriteLine("Setup: register hardware task");
                RunSetupScript("hardware-task.ps1","install");
                var profileConfig=Config.Load();
                if(!profileConfig.Endpoint.ProfileDefaultsApplied){
                    try {
                        string profile=SetupProfileRoot(profileSid);
                        if(profile!=null){ApplyProfileDefaults(profileConfig.Endpoint,profile,fresh);Config.Save(Config.FilePath,Config.Validate(profileConfig));Console.WriteLine("Setup: user profile default evaluated: "+profile);}
                        else Console.Error.WriteLine("Setup: no verified interactive profile found. Configure Endpoint Protection paths manually.");
                    }catch(Exception ex){Console.Error.WriteLine("Setup: profile defaults not applied; saved policy retained. Configure Endpoint Protection paths manually. "+ex.Message);}
                }
                if(canaryToken!=null)try{
                    Console.WriteLine("Setup: enroll canaries");
                    using(var lockFile=new FileStream(Path.Combine(Config.Data,"collector.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None))EnrollSetupCanaries(canaryToken);
                }catch(Exception ex){canarySetupWarning=true;Console.Error.WriteLine("Canary enrollment failed; service installation continues: "+ex.Message);}
                Console.WriteLine("Setup: register NTFS journal reader");
                try{InstallUsn();}catch(Exception ex){Console.Error.WriteLine("USN reader unavailable; watcher fallback remains enabled: "+ex.Message);}
                Console.WriteLine("Setup: start service");
                try { StartAndWait(); }
                catch(Exception ex) {
                    Console.Error.WriteLine("Windows could not start LinkScope. Checking service exit codes:");
                    try { Sc("queryex",Name); } catch(Exception queryError) { Console.Error.WriteLine(queryError.Message); }
                    throw new InvalidOperationException("Check the System log (Service Control Manager) and "+Path.Combine(Config.Data,"service.log")+".",ex);
                }
            }
            Console.WriteLine("LinkScope is running. History: "+Config.Db);
        }
        static void Uninstall() {
            RequireAdmin();
            if(!Directory.Exists(Config.Root)) { UninstallRegistered(); return; }
            using(var gate=new FileStream(Path.Combine(Config.Root,"maintenance.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None))
                UninstallRegistered();
        }
        static void UninstallRegistered() {
            string registered=RegisteredCommand();
            if(registered==null) { RemoveUsn(); Console.WriteLine("Service is already removed."); return; }
            using(var svc=new ServiceController(Name)) {
                if(svc.Status==ServiceControllerStatus.StartPending)
                    svc.WaitForStatus(ServiceControllerStatus.Running,TimeSpan.FromSeconds(60));
                svc.Refresh();
                if(svc.Status!=ServiceControllerStatus.Stopped) {
                    if(svc.Status!=ServiceControllerStatus.StopPending) svc.Stop();
                    svc.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(65));
                }
            }
            RemoveUsn();
            RunSetupScript("hardware-task.ps1","remove");
            Sc("delete",Name);
            Console.WriteLine("Service removed. History and configuration retained in "+Config.Root);
        }
        [STAThread]
        static int Main(string[] args) {
            string verb=args.Length>=1&&args.Length<=2 ? args[0].ToLowerInvariant() : "";
            string canaryToken=args.Length==2?args[1]:null;
            if(verb=="--endpoint-scan-file"){try{RequireAdmin();if(args.Length!=2)throw new ArgumentException("Supply one absolute file path.");return EndpointProtection.RequestFileProbe(args[1]);}catch(Exception ex){Console.Error.WriteLine(ex.Message);return 1;}}
            if(verb=="--endpoint-file-status"){try{RequireAdmin();if(args.Length!=2)throw new ArgumentException("Supply one absolute file path.");EndpointProtection.DiagnoseFile(args[1]);return 0;}catch(Exception ex){Console.Error.WriteLine(ex.Message);return 1;}}
            if(canaryToken!=null&&(!(verb=="--install"||verb=="--upgrade"||verb=="--upgrade-pwa")||canaryToken.Length>8192))return 2;
            try {
                switch(verb) {
                    case "--install": case "-install": Install(false,canaryToken); DesktopApp.Provision(false); break;
                    case "--upgrade": Install(true,canaryToken); DesktopApp.Provision(false); break;
                    case "--upgrade-pwa": Install(true,canaryToken); DesktopApp.Provision(true); break;
                    case "--desktop-app": RequireAdmin(); DesktopApp.Provision(false); break;
                    case "--register-pwa": RequireAdmin(); DesktopApp.Provision(true); break;
                    case "--uninstall": case "-uninstall": Uninstall(); DesktopApp.Remove(); break;
                    case "--init-config": InitConfig(); break;
                    case "--endpoint-engine-self-test": RequireAdmin(); return EndpointProtection.TestEngineSignature();
                    case "--self-test": SelfCheck.Run(true); break;
                    case "--smart-once": RequireAdmin(); try{SmartDisk.Capture();}finally{SecurityPosture.Capture();} break;
                    case "--set-admin": RequireAdmin(); Access.SetPassword(); break;
                    case "--reset-admin-mfa":
                        RequireAdmin();
                        using(var service=new ServiceController(Name)){if(service.Status!=ServiceControllerStatus.Stopped)throw new InvalidOperationException("Stop the LinkScope service before resetting MFA.");}
                        Console.Write("Type RESET to disable MFA for the built-in admin: ");
                        if(Console.ReadLine()!="RESET")return 2;
                        new UserAccounts(Path.Combine(Config.SettingsDir,"users.json"),AdminPasswords.Installed).ResetBuiltinMfa();
                        UserAudit.Init();UserAudit.Write("Windows administrator","localhost","Offline built-in admin MFA recovery",200,"Success");
                        Console.WriteLine("Admin MFA disabled. Restart LinkScope and enroll again.");break;
                    case "--prepare-certificate": PrepareCertificate(); break;
                    case "--check-config": Config.Load(); Console.WriteLine("Configuration is valid."); break;
                    case "--restart-installed": RestartInstalledService();break;
                    case "--signature-update-installed": return UpdateInstalledSignatures();
                    case "--clam-peer-access-installed": return RefreshInstalledClamPeerAccess();
                    case "--usn-self-test": UsnJournalService.SelfTest();return 0;
                    case "--usn-service": RequireAdmin();ServiceBase.Run(new UsnJournalService());return 0;
                    case "--service": ServiceMode=true;ServiceBase.Run(new MonitorService()); break;
                    case "--console":
                        using(var done=new ManualResetEvent(false))
                        using(var host=new MonitorHost()) {
                            ConsoleCancelEventHandler cancel=delegate(object sender,ConsoleCancelEventArgs e){ e.Cancel=true; done.Set(); };
                            Console.CancelKeyPress+=cancel;
                            try { host.Start(); Console.WriteLine("Collecting. Press Ctrl+C to stop."); done.WaitOne(); }
                            finally { Console.CancelKeyPress-=cancel; }
                        }
                        break;
                    default:
                        Console.WriteLine("LinkScope.exe --install | --upgrade | --upgrade-pwa | --desktop-app | --register-pwa | --uninstall | --init-config | --check-config | --set-admin | --reset-admin-mfa | --prepare-certificate | --console");
                        return verb=="--help" || args.Length==0 ? 0 : 2;
                }
                MaintenanceEvents.Command(verb,true);return canarySetupWarning?11:0;
            } catch(Exception ex) {
                MaintenanceEvents.Command(verb,false);
                for(Exception cause=ex;cause!=null;cause=cause.InnerException) {
                    var native=cause as Win32Exception;
                    Console.Error.WriteLine(native==null ? cause.Message : "Win32 "+native.NativeErrorCode+": "+cause.Message);
                }
                return 1;
            }
        }
    }
}
