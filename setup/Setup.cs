using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Windows.Forms;
using Microsoft.Win32;

internal static partial class Setup {
    static readonly string Self = Assembly.GetExecutingAssembly().Location;
    static readonly string ProgramFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
    static readonly string LogDirectory = Path.Combine(ProgramFiles, "LinkScope Setup Logs");
    static readonly string MsiPath = Path.Combine(Path.GetDirectoryName(Self), "deploy", "clamav-latest.msi");
    static Stream Resource(string name) {
        Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream(name);
        if (s == null) throw new InvalidOperationException("Missing installer resource: " + name);
        return s;
    }
    static int Wizard() {
        // A short -File invocation avoids CreateProcess's 32767-character limit.
        string folder=Path.Combine(Path.GetTempPath(),"LinkScopeWizard-"+Guid.NewGuid().ToString("N"));
        string script=Path.Combine(folder,"wizard.ps1");
        using(var identity=WindowsIdentity.GetCurrent()) {
            if(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))SecureDirectory(folder);
            else Directory.CreateDirectory(folder);
        }
        try {
            using(var input=Resource("wizard.ps1"))using(var output=new FileStream(script,FileMode.CreateNew,FileAccess.Write,FileShare.None))input.CopyTo(output);
            // Hold a read-only sharing lock for the entire wizard lifetime.
            using(var guard=new FileStream(script,FileMode.Open,FileAccess.Read,FileShare.Read)) {
                string ps=Path.Combine(Environment.SystemDirectory,@"WindowsPowerShell\v1.0\powershell.exe");
                var start=new ProcessStartInfo(ps,"-NoLogo -NoProfile -NonInteractive -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File \""+script+"\"");
                start.UseShellExecute=false;start.CreateNoWindow=true;start.WorkingDirectory=Environment.SystemDirectory;
                start.EnvironmentVariables["LINKSCOPE_SETUP_EXE"]=Self;
                using(var child=Process.Start(start)) {child.WaitForExit();return child.ExitCode;}
            }
        } finally {try{File.Delete(script);Directory.Delete(folder);}catch(IOException){}catch(UnauthorizedAccessException){}}
    }
    static void RequireAdmin() {
        using (var identity = WindowsIdentity.GetCurrent())
            if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                throw new UnauthorizedAccessException("Run this operation from an elevated Administrator terminal, or open the setup wizard.");
    }
    static DirectorySecurity PrivateAcl() {
        var acl = new DirectorySecurity();
        acl.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { WellKnownSidType.BuiltinAdministratorsSid, WellKnownSidType.LocalSystemSid })
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        return acl;
    }
    static void SecureDirectory(string path) {
        var acl=PrivateAcl();
        var dir=Directory.CreateDirectory(path,acl);
        if ((dir.Attributes & FileAttributes.ReparsePoint)!=0) throw new IOException("Setup directory is a reparse point: "+path);
        var owner=dir.GetAccessControl().GetOwner(typeof(SecurityIdentifier));
        using(var identity=WindowsIdentity.GetCurrent()) {
            if(!owner.Equals(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null)) &&
               !owner.Equals(new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null)) && !owner.Equals(identity.User))
                throw new UnauthorizedAccessException("Unexpected setup directory owner: "+path);
        }
        // Do not reapply inheritable ACLs to an already secured directory.
        if(dir.GetAccessControl(AccessControlSections.Access).GetSecurityDescriptorSddlForm(AccessControlSections.Access)!=acl.GetSecurityDescriptorSddlForm(AccessControlSections.Access))
            dir.SetAccessControl(acl);
    }
    static string NewLogPath(string action) {
        SecureDirectory(LogDirectory);
        return Path.Combine(LogDirectory, DateTime.UtcNow.ToString("yyyyMMdd-HHmmss")+"-"+action+"-"+Guid.NewGuid().ToString("N")+".log");
    }
    static int RunHidden(string exe,string arguments,string workingDirectory,TextWriter log) {
        var start=new ProcessStartInfo(exe,arguments) {UseShellExecute=false,CreateNoWindow=true,
            WorkingDirectory=workingDirectory,RedirectStandardOutput=true,RedirectStandardError=true};
        using(var child=Process.Start(start)) {
            // Drain both pipes concurrently and persist each line immediately.
            object sync=new object();
            DataReceivedEventHandler write=(sender,e)=>{if(e.Data!=null)lock(sync){log.WriteLine(DateTime.UtcNow.ToString("o")+" "+e.Data);log.Flush();}};
            child.OutputDataReceived+=write;child.ErrorDataReceived+=write;
            log.WriteLine("Started worker PID="+child.Id+" executable="+Path.GetFileName(exe));log.Flush();
            child.BeginOutputReadLine();child.BeginErrorReadLine();
            child.WaitForExit(); // never kill an active MSI/service mutation automatically
            log.WriteLine("Exit code: "+child.ExitCode);log.Flush();return child.ExitCode;
        }
    }
    // No Win32_Product WMI query (which can trigger MSI repairs); no execution of discovered binaries.
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
    [DllImport("msi.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern uint MsiOpenDatabaseW(string path,IntPtr mode,out uint database);
    [DllImport("msi.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern uint MsiDatabaseOpenViewW(uint database,string query,out uint view);
    [DllImport("msi.dll",ExactSpelling=true)] static extern uint MsiViewExecute(uint view,uint record);
    [DllImport("msi.dll",ExactSpelling=true)] static extern uint MsiViewFetch(uint view,out uint record);
    [DllImport("msi.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern uint MsiRecordGetStringW(uint record,uint field,StringBuilder value,ref uint length);
    [DllImport("msi.dll",ExactSpelling=true)] static extern uint MsiCloseHandle(uint handle);
    static string ProductName(string path) {
        uint db=0,view=0,record=0;
        try {
            if(MsiOpenDatabaseW(path,IntPtr.Zero,out db)!=0 || MsiDatabaseOpenViewW(db,"SELECT `Value` FROM `Property` WHERE `Property` = 'ProductName'",out view)!=0 || MsiViewExecute(view,0)!=0 || MsiViewFetch(view,out record)!=0)
                throw new InvalidDataException("Could not read the MSI product name.");
            var name=new StringBuilder(512);uint size=(uint)name.Capacity;
            if(MsiRecordGetStringW(record,1,name,ref size)!=0)throw new InvalidDataException("Invalid MSI product name.");
            return name.ToString();
        }finally{if(record!=0)MsiCloseHandle(record);if(view!=0)MsiCloseHandle(view);if(db!=0)MsiCloseHandle(db);}
    }
    static int InstallClamAv(string stage,TextWriter log,string logPath,bool repair=false) {
        if(!repair && File.Exists(ClamdExe) && File.Exists(FreshExe)){log.WriteLine("ClamAV binaries already detected; skipped.");return 0;}
        if(!File.Exists(MsiPath))throw new FileNotFoundException("Place clamav-latest.msi in the deploy folder beside setup.",MsiPath);
        string package=Path.Combine(stage,"clamav-latest.msi");
        // Stage the exact bytes in an administrator-only directory before inspection/installation.
        using(var input=new FileStream(MsiPath,FileMode.Open,FileAccess.Read,FileShare.Read))
        using(var output=new FileStream(package,FileMode.CreateNew,FileAccess.Write,FileShare.None))input.CopyTo(output);
        string hash;using(var sha=SHA256.Create())using(var input=File.OpenRead(package))hash=BitConverter.ToString(sha.ComputeHash(input)).Replace("-","");
        log.WriteLine("Local package: "+MsiPath+"\r\nSHA-256: "+hash);log.Flush();
        // Authenticate the exact staged bytes before parsing MSI metadata or calling Windows Installer.
        try{VerifyClamPackage(stage,package,log);}
        catch(Exception ex){log.WriteLine("BLOCKED: ClamAV package signature verification failed. "+ex);log.Flush();
            MessageBox.Show("ClamAV installation blocked.\r\n\r\n"+ex.Message+"\r\n\r\nNo MSI was executed. See the setup log for details.","LinkScope Setup | Signature verification",MessageBoxButtons.OK,MessageBoxIcon.Error);
            return ClamSignatureRejected;
        }
        string product=ProductName(package);
        if(!product.Equals("ClamAV",StringComparison.OrdinalIgnoreCase)&&!product.StartsWith("ClamAV ",StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("The local MSI does not identify itself as ClamAV.");
        log.WriteLine("Product: "+product);log.Flush();
        if(MessageBox.Show("ClamAV release signature: VERIFIED\r\n\r\nPublisher key: Cisco Talos\r\nFingerprint: "+TalosFingerprint+"\r\nSHA-256: "+hash+
            "\r\n\r\nConfirm this is the intended official x64 package and version. Install ClamAV?",
            "LinkScope Setup | ClamAV",MessageBoxButtons.YesNo,MessageBoxIcon.Information,MessageBoxDefaultButton.Button2)!=DialogResult.Yes){log.WriteLine("ClamAV installation declined.");return 1602;}
        string msiLog=Path.ChangeExtension(logPath,"msi.log");
        int result=RunHidden(Path.Combine(Environment.SystemDirectory,"msiexec.exe"),"/i \""+package+"\" "+(repair?"REINSTALL=ALL REINSTALLMODE=omus ":"")+"/qn /norestart /L*v \""+msiLog+"\"",stage,log);
        if(result==0&&(!File.Exists(ClamdExe)||!File.Exists(FreshExe))){log.WriteLine("Windows Installer returned success, but ClamAV installation was not detected. Verify the installation.");return 4;}
        return result;
    }
    static int Execute(string verb,string canaryToken=null) {
        RequireAdmin();
        string logPath=NewLogPath(verb.TrimStart('-'));
        using(var log=new StreamWriter(new FileStream(logPath,FileMode.CreateNew,FileAccess.Write,FileShare.Read),Encoding.UTF8)) {
            string stage=Path.Combine(ProgramFiles,"LinkScope-setup-"+Guid.NewGuid().ToString("N"));
            try {
                log.WriteLine("Preparing secure staging directory: "+stage);log.Flush();
                SecureDirectory(stage);
                log.WriteLine(DateTime.UtcNow.ToString("o")+" "+verb);log.Flush();
                if(verb=="--install-clamav") {
                    int before=CheckClamAv(log);
                    if(before!=ClamMissing && before!=ClamPartial)return ConfigureClamAv(log);
                    bool repair=before==ClamPartial;
                    if(repair && (!StandardRegistryPaths(log)||!NativeService("clamd",ClamdExe)||!NativeService("freshclam",FreshExe)))throw new IOException("Custom installation detected. Automatic MSI repair is unsafe; inspect the installation first.");
                    if(repair && ClamMsiProducts().Count==0 && ClamAvInstalled())throw new IOException("Unmanaged ClamAV installation detected; automatic MSI repair is unsafe.");
                    int installed=InstallClamAv(stage,log,logPath,repair && ClamMsiProducts().Count!=0);
                    if(installed!=0)return installed; // Includes reboot-required; configure after restart.
                    return ConfigureClamAv(log);
                }
                if(verb=="--uninstall-clamav")return UninstallClamAv(log,logPath);
                if(verb=="--configure-clamav")return ConfigureClamAv(log);
                if(verb=="--update-clamav")return UpdateClamSignatures(log);
                if(verb=="--clamav-providers")return EditProviderSources(log);
                string exe=Path.Combine(stage,"LinkScope.exe");
                using(var input=Resource("LinkScope.exe"))using(var output=new FileStream(exe,FileMode.CreateNew,FileAccess.Write,FileShare.None))input.CopyTo(output);
                return RunHidden(exe,verb+(canaryToken==null?"":" "+canaryToken),stage,log);
            }catch(Exception ex){if(verb=="--clamav-providers"){string detail=ProviderFailureDetail(ex);log.WriteLine("Provider configuration failed during: "+providerStage+Environment.NewLine+detail);log.Flush();MessageBox.Show("Could not complete provider configuration.\r\n\r\nStep: "+providerStage+"\r\n"+detail+"\r\n\r\nSetup log: "+logPath,"LinkScope | Third-party signatures",MessageBoxButtons.OK,MessageBoxIcon.Error);}else {log.WriteLine(ex);log.Flush();MessageBox.Show(ex.Message+"\r\n\r\nSetup log: "+logPath,"LinkScope Setup",MessageBoxButtons.OK,MessageBoxIcon.Error);}return 1;}
            finally {
                try{foreach(string file in new[]{"LinkScope.exe","clamav-latest.msi","clamav-latest.msi.sig","cisco-talos.gpg"})File.Delete(Path.Combine(stage,file));string home=Path.Combine(stage,"gnupg");if(Directory.Exists(home))Directory.Delete(home,true);Directory.Delete(stage);}
                catch(Exception ex){log.WriteLine("Could not clean installer staging directory: "+ex.Message);}
            }
        }
    }
    [STAThread]
    static int Main(string[] args) {
        try {
            if(args.Length==0){int rc=Wizard();if(rc!=0)MessageBox.Show("Setup wizard failed (exit "+rc+"). Check Windows Application event logs and PowerShell policy.","LinkScope Setup",MessageBoxButtons.OK,MessageBoxIcon.Error);return rc;}
            if(args.Length==2){
                string verb=args[0].ToLowerInvariant();
                if((verb=="--upgrade"||verb=="--upgrade-pwa"||verb=="--install")&&args[1].Length<=8192){
                    // Permit only a base64 payload; never interpolate arbitrary command arguments.
                    Convert.FromBase64String(args[1]);
                    if(!System.Text.RegularExpressions.Regex.IsMatch(args[1],"^[A-Za-z0-9+/]+={0,2}$"))return 2;
                    return Execute(verb,args[1]);
                }
                return 2;
            }
            if(args.Length==1) {
                string verb=args[0].ToLowerInvariant();
                if(verb=="--prepare-canaries"||verb=="--repair-canaries"){try{LinkScope.CanaryTemplates.Trace("Worker entered; PID="+Process.GetCurrentProcess().Id);int rc=LinkScope.CanaryTemplates.Prepare(verb=="--repair-canaries");LinkScope.CanaryTemplates.Trace("Worker completed; exit="+rc);return rc;}catch(Exception ex){LinkScope.CanaryTemplates.Trace("Worker failed; LinkScope-Canary-errors.log: "+ex);return 1;}}
                if(verb=="--check-clamav")return CheckClamAvForWizard();
                if(verb=="-install")verb="--install";
                if(verb=="--install"||verb=="--upgrade"||verb=="--upgrade-pwa"||verb=="--desktop-app"||verb=="--register-pwa"||verb=="--uninstall"||verb=="--uninstall-clamav"||verb=="--install-clamav"||verb=="--configure-clamav"||verb=="--update-clamav"||verb=="--clamav-providers")return Execute(verb);
            }
            return 2;
        }catch(Exception ex){
            if(args.Length==0 || (args.Length>0 && args[0]!="--check-clamav"))MessageBox.Show(ex.Message,"LinkScope Setup",MessageBoxButtons.OK,MessageBoxIcon.Error);
            return 1;
        }
    }
}
