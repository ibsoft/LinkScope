using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Win32;

internal static partial class Setup {
    // Local elevated setup only. No web request, service elevation or unapproved policy mutation.
    static readonly string PermissionStore=Path.Combine(ProgramFiles,"LinkScope Permission Backups");
    public sealed class PermissionChange {
        public PermissionChange() {}
        public string Kind {get;set;} public string Path {get;set;} public string Before {get;set;} public string After {get;set;}
        public string Utc {get;set;} public string Sid {get;set;} public string State {get;set;} public string DirectoryIdentity {get;set;}
    }
    static SecurityIdentifier EndpointServiceSid() {
        using(var key=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\LinkScope")) {
            if(key==null || !string.Equals(Convert.ToString(key.GetValue("ObjectName")),@"NT AUTHORITY\LocalService",StringComparison.OrdinalIgnoreCase) || Convert.ToInt32(key.GetValue("ServiceSidType",0))!=1)
                throw new InvalidOperationException("Install or repair LinkScope first: LocalService with unrestricted service SID is required.");
        }
        return (SecurityIdentifier)new NTAccount("NT SERVICE","LinkScope").Translate(typeof(SecurityIdentifier));
    }
    static bool Within(string p,string root) { return p.Equals(root,StringComparison.OrdinalIgnoreCase)||p.StartsWith(root.TrimEnd('\\')+"\\",StringComparison.OrdinalIgnoreCase); }
    static string LocalDirectory(string path) {
        if(string.IsNullOrWhiteSpace(path)||path.Length<4||path[1]!=':'||path[2]!='\\'||path.Substring(2).IndexOf(':')>=0||path.IndexOfAny(new[]{'*','?'})>=0)throw new IOException("Select a literal local directory.");
        string full=Path.GetFullPath(path).TrimEnd('\\');
        if(full.Length<4||!string.Equals(full,path.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase))throw new IOException("Noncanonical or root path refused.");
        var drive=new DriveInfo(Path.GetPathRoot(full));if(drive.DriveType!=DriveType.Fixed||!drive.DriveFormat.Equals("NTFS",StringComparison.OrdinalIgnoreCase))throw new IOException("Only fixed NTFS directories are supported.");
        for(var d=new DirectoryInfo(full);d!=null;d=d.Parent)if(!d.Exists||(d.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("Missing or reparse directory refused: "+d.FullName);
        return full;
    }
    [StructLayout(LayoutKind.Sequential)] struct PermissionFileInfo {
        public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation,Access,Write;
        public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;
    }
    [DllImport("kernel32.dll",EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle PermissionOpen(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
    [DllImport("kernel32.dll",EntryPoint="GetFileInformationByHandle",SetLastError=true)] static extern bool PermissionInfo(SafeFileHandle h,out PermissionFileInfo info);
    [DllImport("kernel32.dll",EntryPoint="GetFinalPathNameByHandleW",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint PermissionFinalPath(SafeFileHandle h,StringBuilder name,uint size,uint flags);
    // Retain non-delete-sharing handles to the directory and its ancestors during local ACL operations.
    sealed class DirectoryPin : IDisposable {
        readonly List<SafeFileHandle> handles=new List<SafeFileHandle>();
        internal string Identity {get;private set;}
        internal DirectoryPin(string path) {
            if(string.IsNullOrEmpty(path))return;
            LocalDirectory(path);var chain=new Stack<string>();for(var d=new DirectoryInfo(path);d!=null&&d.Parent!=null;d=d.Parent)chain.Push(d.FullName);
            try{while(chain.Count>0){string current=chain.Pop();var h=PermissionOpen(current,0x80,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);handles.Add(h);
                PermissionFileInfo info;var final=new StringBuilder(32768);uint length;
                if(h.IsInvalid||!PermissionInfo(h,out info)||(info.Attributes&0x410)!=0x10||(length=PermissionFinalPath(h,final,(uint)final.Capacity,0))==0||length>=final.Capacity||!string.Equals(final.ToString(),@"\\?\"+current,StringComparison.OrdinalIgnoreCase))throw new IOException("Cannot pin directory safely: "+current);
                Identity=info.Volume.ToString("X8")+":"+info.IndexHigh.ToString("X8")+info.IndexLow.ToString("X8");
            }}catch{Dispose();throw;}
        }
        public void Dispose(){foreach(var h in handles)h.Dispose();handles.Clear();}
    }
    static void CheckResponseDirectory(string path) {
        LocalDirectory(path);
        foreach(var folder in new[]{Environment.SpecialFolder.Windows,Environment.SpecialFolder.ProgramFiles,Environment.SpecialFolder.ProgramFilesX86,Environment.SpecialFolder.CommonApplicationData}) {
            string root=Environment.GetFolderPath(folder);if(!string.IsNullOrEmpty(root)&&(Within(path,root)||Within(root,path)))throw new IOException("System or application infrastructure directory refused.");
        }
        using(var key=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList")) {
            if(key==null)throw new IOException("Cannot verify registered profile roots.");
            foreach(string name in key.GetSubKeyNames())using(var profile=key.OpenSubKey(name)) {
                string raw=Convert.ToString(profile.GetValue("ProfileImagePath",""));if(raw.Length==0)continue;
                string p=Path.GetFullPath(Environment.ExpandEnvironmentVariables(raw)).TrimEnd('\\');if(Within(p,path))throw new IOException("Whole user profile or profile parent refused. Select a dedicated subfolder.");
            }
        }
        string cfg=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),@"LinkScope\settings\config.json");
        LocalDirectory(Path.GetDirectoryName(cfg));if((File.GetAttributes(cfg)&FileAttributes.ReparsePoint)!=0)throw new IOException("Settings reparse point refused.");
        var data=new JavaScriptSerializer{MaxJsonLength=64*1024*1024,RecursionLimit=32}.Deserialize<Dictionary<string,object>>(File.ReadAllText(cfg));
        var ep=(Dictionary<string,object>)data["Endpoint"];
        if(!Convert.ToBoolean(ep["Enabled"]))throw new IOException("Endpoint Protection is disabled.");
        if(!Values(ep,"ResponsePaths").Any(x=>path.Equals(x.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase)))throw new IOException("Directory is not an exact saved response path. Select and save it in Settings first.");
        if(!Values(ep,"Paths").Any(x=>Within(path,x)))throw new IOException("Directory is outside the saved protected scope.");
        string excluded=Values(ep,"ExcludedPaths").FirstOrDefault(x=>Within(path,x)||Within(x,path));
        if(excluded!=null)throw new IOException("Directory overlaps an excluded path: "+excluded+". Choose a narrower dedicated response directory.");
        if(Values(ep,"CanaryPaths").Any(x=>Within(path,x)))throw new IOException("A canary-file target cannot be used as a response directory.");
        // A pattern exclusion cannot safely be represented by an inherited ACL. Require a dedicated scope and warn that child ACLs are advisory.
    }
    static string[] Values(Dictionary<string,object> d,string key) {object v;if(!d.TryGetValue(key,out v)||v==null)return new string[0];var a=v as System.Collections.IEnumerable;if(a==null||v is string)return new string[0];return a.Cast<object>().Select(x=>Convert.ToString(x)).Where(x=>!string.IsNullOrWhiteSpace(x)).ToArray();}
    static string[] SavedResponseDirectories() {
        string cfg=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),@"LinkScope\settings\config.json");
        LocalDirectory(Path.GetDirectoryName(cfg));if((File.GetAttributes(cfg)&FileAttributes.ReparsePoint)!=0)throw new IOException("Settings reparse point refused.");
        var data=new JavaScriptSerializer{MaxJsonLength=64*1024*1024,RecursionLimit=32}.Deserialize<Dictionary<string,object>>(File.ReadAllText(cfg));var ep=(Dictionary<string,object>)data["Endpoint"];
        return Values(ep,"ResponsePaths").Where(x=>Directory.Exists(x)).Select(x=>x.TrimEnd('\\')).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }
    static string ReadPermission(string kind,string path) {
        if(kind=="channel")using(var log=new EventLogConfiguration("Security")){return new RawSecurityDescriptor(log.SecurityDescriptor).GetSddlForm(AccessControlSections.All);}
        LocalDirectory(path);var section=kind=="audit"?AccessControlSections.Audit:AccessControlSections.Access;
        var descriptor=Directory.GetAccessControl(path,section).GetSecurityDescriptorSddlForm(section);
        return kind=="audit"&&string.IsNullOrEmpty(descriptor)?"S:":descriptor;
    }
    static void WritePermission(string kind,string path,string sddl) {
        if(kind=="channel") {using(var log=new EventLogConfiguration("Security")){log.SecurityDescriptor=sddl;log.SaveChanges();}return;}
        LocalDirectory(path);if(kind!="audit"&&kind!="access")throw new IOException("Unknown permission section.");
        var section=kind=="audit"?AccessControlSections.Audit:AccessControlSections.Access;
        var acl=new DirectorySecurity();acl.SetSecurityDescriptorSddlForm(sddl,section);Directory.SetAccessControl(path,acl);
    }
    static string PlanPermission(string kind,string path,string before,SecurityIdentifier sid) {
        if(kind=="channel") {
            var raw=new RawSecurityDescriptor(before);var acl=raw.DiscretionaryAcl;if(acl==null)throw new IOException("Null Security log DACL refused.");
            foreach(GenericAce item in acl){var a=item as CommonAce;if(a!=null&&a.SecurityIdentifier.Equals(sid)&&a.AceQualifier==AceQualifier.AccessAllowed&&(a.AccessMask&1)!=0)return before;}
            int index=acl.Count;for(int i=0;i<acl.Count;i++)if((acl[i].AceFlags&AceFlags.Inherited)!=0){index=i;break;}
            acl.InsertAce(index,new CommonAce(AceFlags.None,AceQualifier.AccessAllowed,1,sid,false,null));return raw.GetSddlForm(AccessControlSections.All);
        }
        var section=kind=="audit"?AccessControlSections.Audit:AccessControlSections.Access;
        var d=Directory.GetAccessControl(path,section);
        string observed=d.GetSecurityDescriptorSddlForm(section);if(kind=="audit"&&string.IsNullOrEmpty(observed))observed="S:";
        if(observed!=before)throw new IOException("Permission changed while planning; retry.");
        if(kind=="audit")d.AddAuditRule(new FileSystemAuditRule(new SecurityIdentifier(WellKnownSidType.WorldSid,null),(FileSystemRights)0x10046,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AuditFlags.Success));
        else {
            // Directory listing/traversal and DELETE_CHILD; files read and DELETE. No write or ACL ownership grant.
            d.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.ReadAndExecute|FileSystemRights.DeleteSubdirectoriesAndFiles,InheritanceFlags.ContainerInherit,PropagationFlags.None,AccessControlType.Allow));
            d.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.Read|FileSystemRights.Delete,InheritanceFlags.ObjectInherit,PropagationFlags.InheritOnly,AccessControlType.Allow));
        }
        return d.GetSecurityDescriptorSddlForm(section);
    }
    static void SavePermissionRecord(string file,PermissionChange record) {
        // Atomic replacement with a flushed temporary file; initial intent survives interrupted changes.
        string temp=file+"."+Guid.NewGuid().ToString("N")+".tmp";byte[] bytes=Encoding.UTF8.GetBytes(new JavaScriptSerializer().Serialize(record));
        using(var f=new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.None)){f.Write(bytes,0,bytes.Length);f.Flush(true);}
        if(File.Exists(file))File.Replace(temp,file,null);else File.Move(temp,file);
    }
    static string ApplyPermission(string kind,string path,SecurityIdentifier sid,PermissionChange approved=null) {
        using(var pin=new DirectoryPin(kind=="channel"?null:path)){
        if(kind!="channel")CheckResponseDirectory(path);
        string before=ReadPermission(kind,path),after=PlanPermission(kind,path,before,sid);
        if(approved!=null&&(approved.Kind!=kind||approved.Path!=path||approved.Sid!=sid.Value||approved.DirectoryIdentity!=pin.Identity||approved.Before!=before||approved.After!=after))throw new IOException("Permission or directory identity changed after approval. No change applied; rerun Setup.");
        if(before==after)return kind+": requested rule already present (effective access still needs service verification).";
        var r=new PermissionChange{Kind=kind,Path=path,Before=before,After=after,Utc=DateTime.UtcNow.ToString("o"),Sid=sid.Value,State="planned",DirectoryIdentity=pin.Identity};
        string file=Path.Combine(PermissionStore,DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fffffff")+"-"+Guid.NewGuid().ToString("N")+".json");
        SavePermissionRecord(file,r);
        if(ReadPermission(kind,path)!=before)throw new IOException("Permissions changed after planning. No change applied; backup: "+file);
        if(kind!="channel")CheckResponseDirectory(path);
        WritePermission(kind,path,after);string observed=ReadPermission(kind,path);
        if(observed!=after){r.State="review";SavePermissionRecord(file,r);throw new IOException("Permission readback differs from planned descriptor; inspect backup before manual recovery: "+file);}
        r.State="applied";SavePermissionRecord(file,r);
        return kind+": applied; backup "+Path.GetFileName(file)+". Verify using Test Center.";
        }
    }
    static string RollbackPermission(string file,SecurityIdentifier sid) {
        if(!string.Equals(Path.GetDirectoryName(Path.GetFullPath(file)),PermissionStore,StringComparison.OrdinalIgnoreCase)||(File.GetAttributes(file)&FileAttributes.ReparsePoint)!=0)throw new IOException("Select a local permission backup from the managed folder.");
        var r=new JavaScriptSerializer().Deserialize<PermissionChange>(File.ReadAllText(file));
        if(r==null||r.Sid!=sid.Value||!new[]{"channel","audit","access"}.Contains(r.Kind)||r.State=="rolled back")throw new IOException("Invalid or already restored backup.");
        using(var pin=new DirectoryPin(r.Kind=="channel"?null:r.Path)){
        if(r.Kind!="channel"&&pin.Identity!=r.DirectoryIdentity)throw new IOException("Directory identity changed; manual review required.");
        string current=ReadPermission(r.Kind,r.Path);
        if(current!=r.Before){if(current!=r.After)throw new IOException("Permission changed since repair. Automatic rollback refused; review the saved descriptor with an administrator.");WritePermission(r.Kind,r.Path,r.Before);if(ReadPermission(r.Kind,r.Path)!=r.Before)throw new IOException("Rollback readback differs; manual review required.");}
        r.State="rolled back";SavePermissionRecord(file,r);return "Restored "+r.Kind+" from "+Path.GetFileName(file)+". Recheck service access.";
        }
    }
    static string AuditPolicyReport() {
        var p=new ProcessStartInfo(Path.Combine(Environment.SystemDirectory,"auditpol.exe"),"/get /subcategory:{0CCE921D-69AE-11D9-BED3-505054503030}"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true};
        using(var child=Process.Start(p)){string output=child.StandardOutput.ReadToEnd();child.WaitForExit();return "File System audit policy (exit "+child.ExitCode+"):\r\n"+output;}
    }
    // Exit code for a successful install with permission provisioning still requiring review.
    const int EndpointPermissionReview=21;
    static Dictionary<string,object> ReadInstallEndpointPolicy() {
        string cfg=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),@"LinkScope\settings\config.json");
        LocalDirectory(Path.GetDirectoryName(cfg));
        if((File.GetAttributes(cfg)&FileAttributes.ReparsePoint)!=0)throw new IOException("Settings reparse point refused.");
        var data=new JavaScriptSerializer{MaxJsonLength=64*1024*1024,RecursionLimit=32}.Deserialize<Dictionary<string,object>>(File.ReadAllText(cfg));
        return (Dictionary<string,object>)data["Endpoint"];
    }
    static bool PolicyFlag(Dictionary<string,object> ep,string key) {object v;return ep.TryGetValue(key,out v)&&v is bool&&(bool)v;}
    static bool AutomaticResponseEnabled(Dictionary<string,object> ep) {
        string mode=Convert.ToString(ep["Mode"]);
        return PolicyFlag(ep,"Enabled")&&(mode=="protect"||mode=="contain");
    }
    static string PermissionPolicyStamp(Dictionary<string,object> ep) {
        return new JavaScriptSerializer().Serialize(new object[]{PolicyFlag(ep,"Enabled"),Convert.ToString(ep["Mode"]),PolicyFlag(ep,"ProcessCorrelation"),Values(ep,"Paths"),Values(ep,"ResponsePaths"),Values(ep,"ExcludedPaths"),Values(ep,"ExcludedPatterns"),Values(ep,"CanaryPaths")});
    }
    static void CheckInstallPermissionStep(string kind,string path,string stamp) {
        var current=ReadInstallEndpointPolicy();
        if(!AutomaticResponseEnabled(current)||PermissionPolicyStamp(current)!=stamp)throw new IOException("Saved endpoint policy changed after review. Run Setup again.");
        if((kind=="channel"||kind=="audit")&&!PolicyFlag(current,"ProcessCorrelation"))throw new IOException("Process correlation is not enabled.");
        if(kind!="channel")CheckResponseDirectory(path);
    }
    static bool ConfirmInstallPermissions(string summary) {
        using(var form=new Form{Text="LinkScope Setup | Automatic endpoint permissions",StartPosition=FormStartPosition.CenterScreen,Size=new Size(780,570),MinimumSize=new Size(560,440),Font=new Font("Segoe UI",10),AutoScaleMode=AutoScaleMode.Dpi}) {
            var layout=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,RowCount=4,Padding=new Padding(16)};form.Controls.Add(layout);
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));layout.RowStyles.Add(new RowStyle(SizeType.Percent,100));layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.Controls.Add(new Label{Text="Application protection permissions",Font=new Font("Segoe UI",18,FontStyle.Bold),AutoSize=true},0,0);
            layout.Controls.Add(new Label{Text="Setup has installed the service. Approve only the listed eligible changes. Read access covers the entire Security log; folder permissions include inherited file deletion and DELETE_CHILD. Auditing can increase log volume. Descendants, including filename exclusions, may inherit permissions. A brief LinkScope restart is included. Changes persist until rolled back.",MaximumSize=new Size(680,0),AutoSize=true},0,1);
            layout.Controls.Add(new TextBox{Text=summary,Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.Vertical,Dock=DockStyle.Fill,WordWrap=true},0,2);
            var buttons=new FlowLayoutPanel{Dock=DockStyle.Fill,AutoSize=true,FlowDirection=FlowDirection.RightToLeft};layout.Controls.Add(buttons,0,3);
            var skip=new Button{Text="Skip permissions",AutoSize=true,DialogResult=DialogResult.No};
            var approve=new Button{Text="Approve and apply",AutoSize=true,DialogResult=DialogResult.Yes};buttons.Controls.Add(skip);buttons.Controls.Add(approve);
            form.CancelButton=skip;form.ActiveControl=skip;
            return form.ShowDialog()==DialogResult.Yes;
        }
    }
    static void RestartAfterInstallPermissionChanges(TextWriter log) {
        // Only the local elevated installation process may restart the known service.
        EndpointServiceSid();
        using(var service=new ServiceController("LinkScope")) {
            service.Refresh();
            if(service.Status!=ServiceControllerStatus.Running)throw new IOException("LinkScope is not running. Inspect the Service Control Manager; automatic restart was not attempted.");
            log.WriteLine("Endpoint permissions: restarting LinkScope after approved changes.");log.Flush();
            service.Stop();service.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(90));
            service.Start();service.WaitForStatus(ServiceControllerStatus.Running,TimeSpan.FromSeconds(90));
            log.WriteLine("Endpoint permissions: service restart completed. Effective access requires live Test Center diagnostics.");log.Flush();
        }
    }
    static int ProvisionEndpointPermissionsAfterInstall(TextWriter log,string logPath) {
        RequireAdmin();
        Action<string> write=x=>{log.WriteLine("Endpoint permissions: "+x);log.Flush();};
        write("Automatic setup provisioning started.");
        try {
            var ep=ReadInstallEndpointPolicy();
            if(!AutomaticResponseEnabled(ep)){write("Skipped: Endpoint Protection is disabled or not in Protect/Contain mode. No permissions changed.");return 0;}
            string stamp=PermissionPolicyStamp(ep);bool correlate=PolicyFlag(ep,"ProcessCorrelation");var sid=EndpointServiceSid();
            write("Verified LocalService SID: "+sid.Value);
            if(Directory.Exists(PermissionStore))LocalDirectory(PermissionStore);SecureDirectory(PermissionStore);LocalDirectory(PermissionStore);
            using(var storePin=new DirectoryPin(PermissionStore))
            using(var gate=new FileStream(Path.Combine(PermissionStore,"repair.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None)) {
                var steps=new List<PermissionChange>();var preview=new List<string>();int blocked=0,unchanged=0;
                Action<string,string> plan=(kind,path)=>{
                    string label=kind+(kind=="channel"?" (Security log)":" | "+path);
                    try {
                        CheckInstallPermissionStep(kind,path,stamp);
                        using(var pin=new DirectoryPin(kind=="channel"?null:path)) {
                            string before=ReadPermission(kind,path),after=PlanPermission(kind,path,before,sid);
                            if(before==after){unchanged++;preview.Add(label+": rule already present");return;}
                            steps.Add(new PermissionChange{Kind=kind,Path=path,Sid=sid.Value,Before=before,After=after,DirectoryIdentity=pin.Identity});
                            preview.Add(label+": eligible change");
                        }
                    }catch(Exception ex){blocked++;preview.Add(label+": BLOCKED — "+ex.Message);write("Preflight "+label+": "+ex);}
                };
                if(correlate){try{write(AuditPolicyReport());}catch(Exception ex){write("Audit policy query failed: "+ex);}plan("channel","");}
                string[] paths=Values(ep,"ResponsePaths").Select(x=>x.TrimEnd('\\')).Distinct(StringComparer.OrdinalIgnoreCase).OrderByDescending(x=>x.Length).ToArray();
                // Process nested scopes before their parents so inherited ACL changes do not invalidate approved child snapshots.
                // No automatically invented paths. Overlap is shown explicitly; parent ACL inheritance can affect children.
                foreach(string path in paths){if(correlate)plan("audit",path);plan("access",path);}
                if(paths.Length==0){blocked++;preview.Add("No saved response directories.");}
                string summary="Mode: "+Convert.ToString(ep["Mode"])+"\r\nService SID: "+sid.Value+"\r\n\r\n"+string.Join("\r\n",preview);
                write("Preflight:\r\n"+summary);
                if(steps.Count==0){write("No new rules to apply. Existing descriptors do not prove effective service access. Run Test center > Run live audit test after sign-in.");if(blocked>0)MessageBox.Show("LinkScope installed, but one or more endpoint permission checks were blocked.\r\n\r\nSee: "+logPath,"LinkScope Setup",MessageBoxButtons.OK,MessageBoxIcon.Warning);return blocked>0?EndpointPermissionReview:0;}
                if(!ConfirmInstallPermissions(summary)){write("Permission changes declined. No new ACL rules applied.");return EndpointPermissionReview;}
                int completed=0,failed=0,attempted=0;
                foreach(var step in steps){try{
                    CheckInstallPermissionStep(step.Kind,step.Path,stamp);
                    if(!EndpointServiceSid().Equals(sid))throw new IOException("Service identity changed.");
                    attempted++;write("Applying "+step.Kind+" | "+step.Path);write(ApplyPermission(step.Kind,step.Path,sid,step));completed++;
                }catch(Exception ex){failed++;write("Apply "+step.Kind+" | "+step.Path+" failed: "+ex);}}
                if(attempted>0){try{RestartAfterInstallPermissionChanges(log);}catch(Exception ex){failed++;write("Service restart failed: "+ex);}}
                write("Result: "+completed+" applied; "+unchanged+" already present; "+blocked+" preflight blocked; "+failed+" failures. No effective-access or containment verdict inferred.");
                bool review=blocked>0||failed>0;
                MessageBox.Show("LinkScope installation completed.\r\n\r\nPermission changes applied: "+completed+"\r\nAlready present: "+unchanged+"\r\nBlocked: "+blocked+"\r\nFailures: "+failed+"\r\n\r\nRun Endpoint Protection > Test center to verify effective access. Use Run live audit test with a disposable saved response directory to verify event delivery.\r\nLog: "+logPath,"LinkScope Setup | Endpoint permissions",MessageBoxButtons.OK,review?MessageBoxIcon.Warning:MessageBoxIcon.Information);
                return review?EndpointPermissionReview:0;
            }
        }catch(Exception ex){write("Provisioning failed: "+ex);MessageBox.Show("LinkScope installation completed, but permission provisioning requires review.\r\n\r\n"+ex.Message+"\r\n\r\nLog: "+logPath,"LinkScope Setup",MessageBoxButtons.OK,MessageBoxIcon.Warning);return EndpointPermissionReview;}
    }
    static int EndpointPermissionWizard(TextWriter log) {
        RequireAdmin();var sid=EndpointServiceSid();if(Directory.Exists(PermissionStore))LocalDirectory(PermissionStore);SecureDirectory(PermissionStore);LocalDirectory(PermissionStore);
        // Keep concurrent instances from changing the same descriptors. No elevated background worker.
        using(var storePin=new DirectoryPin(PermissionStore))
        using(var gate=new FileStream(Path.Combine(PermissionStore,"repair.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None))
        using(var form=new Form{Text="LinkScope | Endpoint permission repair",StartPosition=FormStartPosition.CenterScreen,Size=new Size(780,660),MinimumSize=new Size(650,520),Font=new Font("Segoe UI",10)}) {
            var layout=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,RowCount=8,Padding=new Padding(16),AutoScroll=true};form.Controls.Add(layout);
            for(int i=0;i<8;i++)layout.RowStyles.Add(new RowStyle(i==6?SizeType.Percent:SizeType.AutoSize,i==6?100:0));
            layout.Controls.Add(new Label{Text="Containment prerequisites",Font=new Font("Segoe UI",18,FontStyle.Bold),AutoSize=true},0,0);
            layout.Controls.Add(new Label{Text="Select an exact saved response directory for folder repairs. Security log access can be repaired independently. Automatic repair applies only eligible steps after confirmation. No service elevation or audit-policy changes.",AutoSize=true,MaximumSize=new Size(680,0)},0,1);
            var paths=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList,Dock=DockStyle.Top};string listError="";try{paths.Items.AddRange(SavedResponseDirectories());}catch(Exception e){listError=e.Message;}layout.Controls.Add(paths,0,2);
            var channel=new CheckBox{Text="Grant LinkScope service SID read-only Security log access",AutoSize=true};layout.Controls.Add(channel,0,3);
            var audit=new CheckBox{Text="Audit successful file writes/deletes under selected folder (inherited)",AutoSize=true};layout.Controls.Add(audit,0,4);
            var access=new CheckBox{Text="Grant scoped read/delete rights for quarantine (inherited; sensitive)",AutoSize=true};layout.Controls.Add(access,0,5);
            var report=new TextBox{Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.Vertical,Dock=DockStyle.Fill,MinimumSize=new Size(0,120),Text="Service SID: "+sid.Value+"\r\n"+listError+"\r\n"};layout.Controls.Add(report,0,6);
            Action<string> write=s=>{report.AppendText(s+"\r\n");log.WriteLine(s);log.Flush();};
            write("Permission wizard opened for service SID "+sid.Value+". Saved response directories: "+paths.Items.Count);
            if(!string.IsNullOrEmpty(listError))write("Response directory discovery failed: "+listError);
            var buttons=new FlowLayoutPanel{AutoSize=true,Dock=DockStyle.Fill,WrapContents=true};layout.Controls.Add(buttons,0,7);
            var inspect=new Button{Text="Inspect policy",AutoSize=true};var apply=new Button{Text="Review & apply",AutoSize=true};var automatic=new Button{Text="Automatic repair…",AutoSize=true};var rollback=new Button{Text="Rollback…",AutoSize=true};var close=new Button{Text="Close",AutoSize=true};buttons.Controls.AddRange(new Control[]{automatic,inspect,apply,rollback,close});
            // The channel repair is independent of directory policy and SACL access.
            automatic.Enabled=true;
            if(paths.Items.Count==1)paths.SelectedIndex=0;
            automatic.Click+=(o,e)=>{
                string path=Convert.ToString(paths.SelectedItem);
                var kinds=new[]{"channel","audit","access"};
                var preview=new List<string>();var eligible=new List<string>();
                write("Automatic repair started. Selected directory: "+(string.IsNullOrEmpty(path)?"(none)":path));
                try{write(AuditPolicyReport());}catch(Exception ex){write("Audit policy inspection failed: "+ex);}
                foreach(string kind in kinds){
                    string target=kind=="channel"?"":path;
                    try{
                        if(kind!="channel")CheckResponseDirectory(path);
                        using(var pin=new DirectoryPin(kind=="channel"?null:path)){
                            string before=ReadPermission(kind,target);
                            string after=PlanPermission(kind,target,before,sid);
                            preview.Add(kind+": "+(before==after?"rule already present":"change required"));
                            eligible.Add(kind);
                        }
                    }catch(Exception ex){preview.Add(kind+": BLOCKED — "+ex.Message);write("Preflight "+kind+" failed: "+ex);}
                }
                string summary=string.Join("\r\n",preview);write("Automatic repair preview:\r\n"+summary);
                if(eligible.Count==0){write("No eligible repairs. No permission changes made.");return;}
                if(MessageBox.Show(form,"Apply only the eligible repairs listed below?\r\n\r\nDirectory: "+(string.IsNullOrEmpty(path)?"(none)":path)+"\r\n\r\n"+summary+"\r\n\r\nEligible channel repair grants read-only access to the entire Security log. Eligible directory repairs can grant inherited read/delete rights including DELETE_CHILD and audit successful writes/deletes. Descendants, including name-pattern exclusions, may inherit permissions. Existing denies and protected child ACLs may block access. Changes persist until rolled back. Global audit policy is not changed. Continue?","Confirm automatic endpoint repair",MessageBoxButtons.YesNo,MessageBoxIcon.Warning,MessageBoxDefaultButton.Button2)!=DialogResult.Yes){write("Automatic repair cancelled; no permission changes made.");return;}
                int completed=0,failed=0;
                foreach(string kind in eligible){
                    try{write("Applying "+kind+"...");write(ApplyPermission(kind,kind=="channel"?"":path,sid));completed++;}
                    catch(Exception ex){failed++;write("Apply "+kind+" failed: "+ex+". Inspect any backup created for this step before retrying.");}
                }
                write("Automatic repair result: "+completed+" descriptor checks completed; "+failed+" apply failures; "+(kinds.Length-eligible.Count)+" blocked in preflight. Earlier successful changes can be rolled back individually. Effective service access is not yet proven. Restart LinkScope during an appropriate maintenance window, then rerun Test Center diagnostics. No readiness success inferred. No termination privileges granted.");
            };
            inspect.Click+=(o,e)=>{try{write(AuditPolicyReport());write("Security channel descriptor: "+ReadPermission("channel",""));if(paths.SelectedItem!=null){string path=Convert.ToString(paths.SelectedItem);CheckResponseDirectory(path);write("Selected directory is eligible for scoped repair. Effective service access is checked in Test Center.");}}catch(Exception ex){write("Review: "+ex.Message);}};
            apply.Click+=(o,e)=>{try{string path=Convert.ToString(paths.SelectedItem);if(!channel.Checked&&!audit.Checked&&!access.Checked){write("Select at least one repair.");return;}
                string message=(channel.Checked?"Security log: read-only access to the entire channel for the service SID.\r\n":"")+(audit.Checked?"Audit successful writes/deletes by users under "+path+". May increase Security log volume.\r\n":"")+(access.Checked?"Grant read/delete rights including directory DELETE_CHILD under "+path+". This allows removal of files/subdirectories; only choose a dedicated authorized response scope.\r\n":"")+"Inheritance affects descendants, including files excluded by name patterns; protected child ACLs can still block access. Existing ACEs are preserved. Changes persist until rolled back. Continue?";
                if(MessageBox.Show(form,message,"Confirm endpoint permission changes",MessageBoxButtons.YesNo,MessageBoxIcon.Warning,MessageBoxDefaultButton.Button2)!=DialogResult.Yes)return;
                int completed=0,failed=0;
                foreach(string kind in new[]{"channel","audit","access"}){
                    if((kind=="channel"&&!channel.Checked)||(kind=="audit"&&!audit.Checked)||(kind=="access"&&!access.Checked))continue;
                    try{write("Applying "+kind+"...");write(ApplyPermission(kind,kind=="channel"?"":path,sid));completed++;}catch(Exception ex){failed++;write("Apply "+kind+" failed: "+ex);}
                }
                write("Manual repair: "+completed+" descriptor checks completed; "+failed+" failed. Restart LinkScope if necessary, then run Test Center diagnostics. No process termination permission was granted.");
            }catch(Exception ex){write("Repair stopped: "+ex.Message+". Earlier successful changes can be rolled back individually.");}};
            rollback.Click+=(o,e)=>{try{using(var dialog=new OpenFileDialog{InitialDirectory=PermissionStore,Filter="Permission backup (*.json)|*.json",CheckFileExists=true,Multiselect=false})if(dialog.ShowDialog(form)==DialogResult.OK&&MessageBox.Show(form,"Restore this recorded permission section if it has not changed since repair?","Confirm rollback",MessageBoxButtons.YesNo,MessageBoxIcon.Warning,MessageBoxDefaultButton.Button2)==DialogResult.Yes)write(RollbackPermission(dialog.FileName,sid));}catch(Exception ex){write("Rollback stopped: "+ex.Message);}};
            close.Click+=(o,e)=>form.Close();form.ShowDialog();return 0;
        }
    }
}
