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
using System.Security.AccessControl;
using System.Security.Principal;
using System.ComponentModel;
using System.Text.RegularExpressions;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using System.Xml;
using Microsoft.Win32.SafeHandles;
namespace LinkScope {
 internal sealed class EndpointWriter {internal int Pid; internal string Image; internal long Record; internal long Mask; internal DateTime Utc;}
 internal sealed class EndpointResponsePathCheck {public string path {get;set;} public string status {get;set;} public string detail {get;set;}}
 internal static class EndpointResponse {
  internal static bool SafeScope(string p){if(string.IsNullOrEmpty(p)||p.TrimEnd('\\').Length<=2||EndpointProtection.Under(p,Config.Root))return false;foreach(string root in new[]{Environment.GetFolderPath(Environment.SpecialFolder.Windows),Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),AppDomain.CurrentDomain.BaseDirectory})if(!string.IsNullOrEmpty(root)&&(EndpointProtection.Under(p,root)||EndpointProtection.Under(root,p)))return false;return true;}
  // Suggestions only: never grant response permissions or modify the saved policy.
  internal static object SuggestedTargets(EndpointSettings c){
   var paths=new List<string>();var executables=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
   foreach(string path in c.Paths){
    if(!SafeScope(path)||EndpointProtection.Excluded(c,path)||c.CanaryPaths.Contains(path,StringComparer.OrdinalIgnoreCase))continue;
    try{
     EndpointProtection.SafePath(path);
     if(Directory.Exists(path)){
      if(string.Equals(Path.GetFileName(path.TrimEnd('\\')),CanaryTemplates.FolderName,StringComparison.OrdinalIgnoreCase))continue;
      paths.Add(path);
      // Bounded, top-level discovery; no recursive searches or changes to permissions.
      foreach(string file in Directory.EnumerateFiles(path,"*.exe",SearchOption.TopDirectoryOnly).Take(64)){
       if(executables.Count>=200)break;
       if(!SafeScope(file)||EndpointProtection.Excluded(c,file)||!file.EndsWith(".exe",StringComparison.OrdinalIgnoreCase))continue;
       try{EndpointProtection.SafePath(file);executables.Add(file);}catch(IOException){}catch(UnauthorizedAccessException){}catch(System.Security.SecurityException){}
      }
     }else if(File.Exists(path)&&path.EndsWith(".exe",StringComparison.OrdinalIgnoreCase)){paths.Add(path);if(executables.Count<200)executables.Add(path);}
    }catch(IOException){}catch(UnauthorizedAccessException){}catch(System.Security.SecurityException){}
   }
   return new {paths=paths.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),executables=executables.OrderBy(x=>x,StringComparer.OrdinalIgnoreCase).ToArray(),engine=SuggestedEngine(c)};
  }
  // Observe the standard installed binary, not its authenticity. Never replace a saved pin.
  static object SuggestedEngine(EndpointSettings c){
   if(!string.IsNullOrWhiteSpace(c.TrustedEngineSha256))return null;
   string root=Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
   if(string.IsNullOrEmpty(root))return null;
   string path=Path.Combine(root,"ClamAV","clamd.exe");
   if(!string.IsNullOrWhiteSpace(c.TrustedEnginePath)&&!string.Equals(c.TrustedEnginePath,path,StringComparison.OrdinalIgnoreCase))return null;
   try{
    if(!TrustedEngineLocation(path)||!File.Exists(path))return null;
    EndpointProtection.SafePath(path);
    using(var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)){
     VerifyHandle(file.SafeFileHandle,path);
     if(file.Length<=0||file.Length>64L*1024*1024)return null;
     return new {path=path,sha256=EndpointProtection.FileHash(file)};
    }
   }catch(IOException){return null;}catch(UnauthorizedAccessException){return null;}catch(System.Security.SecurityException){return null;}
  }
  internal static EndpointWriter FindWriter(string path){if(string.IsNullOrEmpty(path))return null;var query=new EventLogQuery("Security",PathType.LogName,"*[System[(EventID=4663) and TimeCreated[timediff(@SystemTime) <= 30000]]]"){ReverseDirection=true};using(var reader=new EventLogReader(query)){var timer=Stopwatch.StartNew();for(int i=0;i<512&&timer.ElapsedMilliseconds<1500;i++){using(var ev=reader.ReadEvent(TimeSpan.FromMilliseconds(100))){if(ev==null)break;var doc=new XmlDocument{XmlResolver=null};doc.LoadXml(ev.ToXml());var ns=new XmlNamespaceManager(doc.NameTable);ns.AddNamespace("e","http://schemas.microsoft.com/win/2004/08/events/event");Func<string,string> field=name=>{var node=doc.SelectSingleNode("/e:Event/e:EventData/e:Data[@Name='"+name+"']",ns);return node==null?"":node.InnerText;};if(!string.Equals(field("ObjectType"),"File",StringComparison.OrdinalIgnoreCase)||!string.Equals(field("ObjectName"),path,StringComparison.OrdinalIgnoreCase))continue;long mask,pid;if(!Hex(field("AccessMask"),out mask)||!Hex(field("ProcessId"),out pid)||(mask&0x10046)==0||pid<=4||pid>int.MaxValue||!ev.TimeCreated.HasValue)continue;return new EndpointWriter{Pid=(int)pid,Image=field("ProcessName"),Record=ev.RecordId??0,Utc=ev.TimeCreated.Value.ToUniversalTime()};}}}return null;}
  // Read-only attribution uses the proven reverse channel reader. Do not select one
  // of several different writers, and do not use this observational result to authorize termination.
  internal static EndpointWriter FindIncidentWriter(string path,long minRecord=0){
   if(string.IsNullOrEmpty(path))return null;
   var cutoff=DateTime.UtcNow.AddSeconds(-30);var timer=Stopwatch.StartNew();EndpointWriter found=null;bool boundary=false;
   using(var reader=new EventLogReader(new EventLogQuery("Security",PathType.LogName,"*"){ReverseDirection=true})){
    reader.BatchSize=1;
    for(int i=0;i<512&&timer.ElapsedMilliseconds<1800;i++){
     using(var ev=reader.ReadEvent(TimeSpan.FromMilliseconds(500))){
      if(ev==null){boundary=true;break;}if(minRecord>0&&ev.RecordId.HasValue&&ev.RecordId.Value<=minRecord){boundary=true;break;}if(!ev.TimeCreated.HasValue)continue;var utc=ev.TimeCreated.Value.ToUniversalTime();if(utc<cutoff){boundary=true;break;}if(ev.Id!=4663||utc>DateTime.UtcNow.AddSeconds(2)||!ev.RecordId.HasValue||ev.RecordId.Value<=0)continue;
      var doc=new XmlDocument{XmlResolver=null};doc.LoadXml(ev.ToXml());var ns=new XmlNamespaceManager(doc.NameTable);ns.AddNamespace("e","http://schemas.microsoft.com/win/2004/08/events/event");Func<string,string> field=name=>{var node=doc.SelectSingleNode("/e:Event/e:EventData/e:Data[@Name='"+name+"']",ns);return node==null?"":node.InnerText;};
      long mask,pid;string image=field("ProcessName");if(!string.Equals(field("ObjectType"),"File",StringComparison.OrdinalIgnoreCase)||!string.Equals(field("ObjectName"),path,StringComparison.OrdinalIgnoreCase)||!Hex(field("AccessMask"),out mask)||(mask&0x6)==0||!Hex(field("ProcessId"),out pid)||pid<=4||pid>int.MaxValue||string.IsNullOrWhiteSpace(image))continue;
      if(found!=null&&(found.Pid!=(int)pid||!string.Equals(found.Image,image,StringComparison.OrdinalIgnoreCase)))return null;
      if(found==null)found=new EndpointWriter{Pid=(int)pid,Image=image,Record=ev.RecordId.Value,Mask=mask,Utc=utc};
     }
    }
   }
   return boundary?found:null;
  }
  internal static long SecurityWatermark(){using(var reader=new EventLogReader(new EventLogQuery("Security",PathType.LogName,"*"){ReverseDirection=true})){reader.BatchSize=1;using(var ev=reader.ReadEvent(TimeSpan.FromMilliseconds(1000))){if(ev==null||!ev.RecordId.HasValue||ev.RecordId.Value<=0)throw new IOException("No verified Security record watermark.");return ev.RecordId.Value;}}}
  static bool Hex(string value,out long n){return long.TryParse(value.StartsWith("0x",StringComparison.OrdinalIgnoreCase)?value.Substring(2):value,System.Globalization.NumberStyles.HexNumber,System.Globalization.CultureInfo.InvariantCulture,out n);}
  [StructLayout(LayoutKind.Sequential)] struct FileInfoNative {public uint Attributes;public System.Runtime.InteropServices.ComTypes.FILETIME Creation,Access,Write;public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;}
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string name,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle handle,out FileInfoNative info);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandle(SafeFileHandle handle,StringBuilder path,uint size,uint flags);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle handle,int kind,ref byte value,uint size);
  [DllImport("kernel32.dll",SetLastError=true)] static extern SafeFileHandle OpenProcess(uint access,bool inherit,int pid);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageName(SafeFileHandle process,int flags,StringBuilder path,ref int size);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(SafeFileHandle process,out long created,out long exit,out long kernel,out long user);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(SafeFileHandle process,out uint exitCode);
  const uint QueryLimited=0x1000, ReadControl=0x20000, WriteDac=0x40000, DaclInformation=4;
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetKernelObjectSecurity(SafeFileHandle handle,uint information,byte[] descriptor,uint length,out uint needed);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool SetKernelObjectSecurity(SafeFileHandle handle,uint information,byte[] descriptor);
  static IOException NativeFailure(string action){int error=Marshal.GetLastWin32Error();return new IOException(action+" (Win32 "+error+"): "+new Win32Exception(error).Message);}
  static bool LiveImage(SafeFileHandle proc,string expected){var image=new StringBuilder(4096);int length=image.Capacity;uint exitCode;return QueryFullProcessImageName(proc,0,image,ref length)&&string.Equals(image.ToString(),expected,StringComparison.OrdinalIgnoreCase)&&GetExitCodeProcess(proc,out exitCode)&&exitCode==259;}
  // Called only by the fixed installed SYSTEM task. No request-supplied PID, path, ACL or account.
  // Only a query-limited ACE on the currently registered standard ClamD process is added.
  internal static bool RefreshClamPeerAccess(SecurityIdentifier serviceSid){
   using(var identity=WindowsIdentity.GetCurrent())if(!identity.IsSystem)throw new UnauthorizedAccessException("ClamD access maintenance requires the installed SYSTEM task.");
   string expected=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"ClamAV","clamd.exe");
   uint pid=ClamUpdateWorker.StandardClamdResponsePid();if(pid==0)return false;
   using(var proc=OpenProcess(QueryLimited|ReadControl|WriteDac,false,(int)pid)){
    if(proc.IsInvalid)throw NativeFailure("Cannot open the registered ClamD process for query ACL maintenance");
    if(!LiveImage(proc,expected)||ClamUpdateWorker.StandardClamdResponsePid()!=pid)throw new IOException("Registered ClamD process changed during access maintenance.");
    uint needed;GetKernelObjectSecurity(proc,DaclInformation,null,0,out needed);
    if(needed<20||needed>65536)throw NativeFailure("Cannot read ClamD process DACL size");
    var data=new byte[(int)needed];if(!GetKernelObjectSecurity(proc,DaclInformation,data,(uint)data.Length,out needed))throw NativeFailure("Cannot read ClamD process DACL");
    var descriptor=new RawSecurityDescriptor(data,0);var acl=descriptor.DiscretionaryAcl;
    if(acl==null)throw new IOException("ClamD process has a null DACL; no ACL changes were made.");
    // Preserve existing ACEs and order. Explicit denials are not removed or bypassed.
    foreach(GenericAce ace in acl){var allow=ace as CommonAce;if(allow!=null&&allow.AceQualifier==AceQualifier.AccessAllowed&&allow.SecurityIdentifier.Equals(serviceSid)&&(allow.AceFlags&AceFlags.InheritOnly)==0&&(allow.AccessMask&(int)QueryLimited)!=0)return true;}
    int insert=acl.Count;for(int i=0;i<acl.Count;i++){if((acl[i].AceFlags&AceFlags.Inherited)!=0){insert=i;break;}}
    acl.InsertAce(insert,new CommonAce(AceFlags.None,AceQualifier.AccessAllowed,(int)QueryLimited,serviceSid,false,null));
    var updated=new byte[descriptor.BinaryLength];descriptor.GetBinaryForm(updated,0);
    if(!LiveImage(proc,expected)||ClamUpdateWorker.StandardClamdResponsePid()!=pid)throw new IOException("ClamD restarted before ACL update; retry scheduled.");
    if(!SetKernelObjectSecurity(proc,DaclInformation,updated))throw NativeFailure("Cannot grant query-only access to the LinkScope service SID");
    return true;
   }
  }
  internal static string CheckResponseEngine(EndpointSettings c,WaitHandle stop){
   if(c.Mode=="monitor")return "Detection only; automatic response disabled.";
   string pong=EndpointProtection.Command(c.Port,"PING",null,stop,tcp=>VerifyEngine(c,tcp));
   if(pong!="PONG")throw new IOException("Unexpected response from verified ClamD peer.");
   return "Connected peer process and pinned executable SHA-256 verified.";
  }
  // Non-mutating advisory check under the actual monitor identity. Per-file ACLs and locks
  // are still checked on the real quarantine handle, and no directory rights are granted here.
  internal static EndpointResponsePathCheck[] CheckResponsePaths(EndpointSettings c){
   var rows=new List<EndpointResponsePathCheck>();foreach(string path in c.ResponsePaths){string status="ok",detail;try{
    if(!SafeScope(path)||EndpointProtection.Excluded(c,path)||!c.Paths.Any(x=>EndpointProtection.Under(path,x)))throw new IOException("Path is outside the authorized response policy.");
    EndpointProtection.SafePath(path);bool directory=(File.GetAttributes(path)&FileAttributes.Directory)!=0;
    using(var handle=CreateFile(path,directory?0x41U:0x80010000U,7,IntPtr.Zero,3,0x02200000,IntPtr.Zero)){
     if(handle.IsInvalid)throw NativeFailure(directory?"Directory list/delete-child access unavailable; individual files may grant DELETE":"File read/delete access unavailable");
     if(!directory)VerifyHandle(handle,path);
     detail=directory?"Directory list and delete-child access granted. Individual file read access and locks still checked.":"File read and delete access granted; no file was changed.";
    }
   }catch(Exception ex){status="warning";detail=ex.Message;}
   rows.Add(new EndpointResponsePathCheck {path=path,status=status,detail=detail});}return rows.ToArray();
  }

  [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(SafeFileHandle process,uint exitCode);
  [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(SafeFileHandle process,uint milliseconds);
  [DllImport("kernel32.dll",SetLastError=true)] static extern uint GetProcessId(SafeFileHandle process);
  // The caller must authorize the target and hold the original process object. The lab
  // never opens a PID supplied by a caller; production retains all its independent gates.
  static bool TerminateAndObserve(SafeFileHandle process,uint expectedExitCode,out uint? observedExitCode){
   observedExitCode=null;
   if(WaitForSingleObject(process,0)!=258U)throw new IOException("Target process is not verified running on the retained handle.");
   if(!TerminateProcess(process,expectedExitCode))throw NativeFailure("Windows refused process termination");
   uint code;if(WaitForSingleObject(process,2000U)!=0U||!GetExitCodeProcess(process,out code))return false;
   observedExitCode=code;return code==expectedExitCode;
  }
  // Explicit lab-only mechanics check: fixed finite-lived child, original creation handle,
  // no process selection, no allowlist edits, no injected scanner verdict, no elevation.
  internal static object OwnedChildTerminationProbe(WaitHandle stop,Func<bool> authorized,Action<string,string,string> add){
   const uint labExitCode=0x4C530068U;
   int pid=0,servicePid;using(var self=Process.GetCurrentProcess()){servicePid=self.Id;}uint handlePid=0;uint? observedExitCode=null;
   string image=null,expectedImage=null,createdUtc=null,requestedUtc=null,observedUtc=null;bool identityVerified=false,ready=false,requested=false,exitVerified=false,childExited=false;
   Process child=null;var started=DateTime.UtcNow;
   try{
    if(stop.WaitOne(0)||!authorized())throw new OperationCanceledException("Lab authorization ended before child launch.");
    expectedImage=Path.Combine(Environment.SystemDirectory,"WindowsPowerShell","v1.0","powershell.exe");EndpointProtection.SafePath(expectedImage);
    using(var executable=new FileStream(expectedImage,FileMode.Open,FileAccess.Read,FileShare.Read)){
     // Windows-serviced system binaries can be hard-linked to WinSxS. This read-only
     // check requires the canonical OS path and regular non-reparse file, not link count.
     var final=new StringBuilder(4096);uint len=GetFinalPathNameByHandle(executable.SafeFileHandle,final,(uint)final.Capacity,0);FileInfoNative info;
     if(len==0||len>=final.Capacity||!string.Equals(final.ToString(),@"\\?\"+Path.GetFullPath(expectedImage),StringComparison.OrdinalIgnoreCase)||!GetFileInformationByHandle(executable.SafeFileHandle,out info)||(info.Attributes&0x410)!=0)throw new IOException("Fixed system executable path could not be verified.");
     var psi=new ProcessStartInfo(expectedImage,"-NoLogo -NoProfile -NonInteractive -Command \"Write-Output 'LINKSCOPE_TERMINATION_READY'; Start-Sleep -Seconds 10\""){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=Environment.SystemDirectory,RedirectStandardOutput=true};
     started=DateTime.UtcNow;child=Process.Start(psi);if(child==null)throw new IOException("Fixed lab child failed to start.");pid=child.Id;
     // Process.Start retains the CreateProcess handle. Borrow it; do not reopen by PID.
     using(var owned=new SafeFileHandle(child.Handle,false)){
      handlePid=GetProcessId(owned);long created,exit,kernel,user;bool critical;var name=new StringBuilder(4096);int size=name.Capacity;uint code;
      if(pid<=4||pid==servicePid||handlePid!=(uint)pid||!QueryFullProcessImageName(owned,0,name,ref size)||!string.Equals(name.ToString(),expectedImage,StringComparison.OrdinalIgnoreCase)||!GetProcessTimes(owned,out created,out exit,out kernel,out user)||!IsProcessCritical(owned,out critical)||critical||!GetExitCodeProcess(owned,out code)||code!=259U||WaitForSingleObject(owned,0)!=258U)throw new IOException("Owned child identity, noncriticality or live state could not be established.");
      var born=DateTime.FromFileTimeUtc(created);if(born<started.AddSeconds(-1)||born>DateTime.UtcNow.AddSeconds(2))throw new IOException("Child creation time is outside the launch interval.");
      image=name.ToString();createdUtc=born.ToString("o");identityVerified=true;
      var line=child.StandardOutput.ReadLineAsync();if(!line.Wait(4000)||line.Result!="LINKSCOPE_TERMINATION_READY")throw new IOException("Fixed child did not reach its ready state.");ready=true;
      if(stop.WaitOne(0)||!authorized())throw new OperationCanceledException("Lab authorization ended before termination.");
      requestedUtc=DateTime.UtcNow.ToString("o");exitVerified=TerminateAndObserve(owned,labExitCode,out observedExitCode);requested=true;observedUtc=DateTime.UtcNow.ToString("o");
     }
    }
   }catch(Exception ex){add("Owned child termination detail","Review",ex.GetType().Name+": "+ex.Message);}
   finally{
    // On cancellation/failure do not kill another process or reopen a PID. The fixed
    // sleep command expires naturally. Observe the same Process object, or report Review.
    if(child!=null){try{childExited=child.WaitForExit(15000);}catch(Exception ex){add("Owned child exit observation detail","Review",ex.GetType().Name+": "+ex.Message);}finally{child.Dispose();}}
   }
   bool passed=identityVerified&&ready&&requested&&exitVerified&&childExited&&observedExitCode.HasValue&&observedExitCode.Value==labExitCode;
   add("Owned child termination mechanics",passed?"Pass":"Review",passed?"Fixed harmless child PID "+pid+"; image "+image+"; original launch handle; created UTC "+createdUtc+"; termination UTC "+requestedUtc+"; observed exit UTC "+observedUtc+"; exit code 0x"+observedExitCode.Value.ToString("X8")+" verified. No production authorization or malware-verdict gate bypass; not malicious-process containment.":"No verified termination result for the fixed owned child. PID "+pid+"; exit observed="+childExited+". No production termination verdict.");
   return new {pid,servicePid,handlePid,image,expectedImage,createdUtc,requestedUtc,observedUtc,identityVerified,ready,requested,exitVerified,childExited,expectedExitCode=labExitCode,observedExitCode};
  }

  [DllImport("kernel32.dll",SetLastError=true)] static extern bool IsProcessCritical(SafeFileHandle process,out bool critical);
  internal static void VerifyHandle(SafeFileHandle handle,string path){var final=new StringBuilder(4096);uint len=GetFinalPathNameByHandle(handle,final,(uint)final.Capacity,0);if(len==0||len>=final.Capacity||!string.Equals(final.ToString(),@"\\?\"+Path.GetFullPath(path),StringComparison.OrdinalIgnoreCase))throw new IOException("File identity or final path mismatch.");FileInfoNative info;if(!GetFileInformationByHandle(handle,out info)||info.Links!=1||(info.Attributes&0x410)!=0)throw new IOException("Hard-linked, directory or reparse file refused.");}
  internal static bool TrustedEngineLocation(string path){if(string.IsNullOrWhiteSpace(path)||!Path.IsPathRooted(path)||!string.Equals(Path.GetFileName(path),"clamd.exe",StringComparison.OrdinalIgnoreCase))return false;string full;try{full=Path.GetFullPath(path);}catch(Exception){return false;}return new[]{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)}.Any(root=>!string.IsNullOrEmpty(root)&&EndpointProtection.Under(full,root));}
  [DllImport("iphlpapi.dll")] static extern uint GetExtendedTcpTable(IntPtr table,ref uint size,bool order,int family,int tableClass,uint reserved);
  static int Port(uint value){return (int)(((value&255)<<8)|((value>>8)&255));}
  static void VerifyEngine(EndpointSettings c,TcpClient client){
   if(!TrustedEngineLocation(c.TrustedEnginePath))throw new IOException("Trusted ClamD executable location is invalid.");int local=((IPEndPoint)client.Client.LocalEndPoint).Port,remote=((IPEndPoint)client.Client.RemoteEndPoint).Port;int pid=0;uint size=0;GetExtendedTcpTable(IntPtr.Zero,ref size,false,2,5,0);
   for(int attempt=0;attempt<3;attempt++){if(size<4||size>16*1024*1024)throw new IOException("TCP owner table unavailable.");IntPtr mem=Marshal.AllocHGlobal((int)size);try{uint result=GetExtendedTcpTable(mem,ref size,false,2,5,0);if(result==122)continue;if(result!=0)throw new IOException("TCP owner table query failed.");int count=Marshal.ReadInt32(mem);if(count<0||4L+count*24L>size)throw new IOException("Invalid TCP owner table.");for(int i=0;i<count;i++){int off=4+i*24;if(Marshal.ReadInt32(mem,off)==5&&Marshal.ReadInt32(mem,off+4)==0x0100007f&&Marshal.ReadInt32(mem,off+12)==0x0100007f&&Port((uint)Marshal.ReadInt32(mem,off+8))==remote&&Port((uint)Marshal.ReadInt32(mem,off+16))==local){pid=Marshal.ReadInt32(mem,off+20);break;}}break;}finally{Marshal.FreeHGlobal(mem);}}
   if(pid<=4)throw new IOException("Could not identify the ClamD peer process.");using(var proc=OpenProcess(0x1000,false,pid)){if(proc.IsInvalid)throw NativeFailure("Cannot inspect ClamD peer process");var image=new StringBuilder(4096);int length=image.Capacity;long create,exit,kernel,user;uint exitCode;if(!QueryFullProcessImageName(proc,0,image,ref length)||!string.Equals(image.ToString(),c.TrustedEnginePath,StringComparison.OrdinalIgnoreCase)||!GetProcessTimes(proc,out create,out exit,out kernel,out user)||!GetExitCodeProcess(proc,out exitCode)||exitCode!=259)throw new IOException("ClamD peer does not match trusted executable.");EndpointProtection.SafePath(c.TrustedEnginePath);using(var file=new FileStream(c.TrustedEnginePath,FileMode.Open,FileAccess.Read,FileShare.Read)){VerifyHandle(file.SafeFileHandle,c.TrustedEnginePath);if(!string.Equals(EndpointProtection.FileHash(file),c.TrustedEngineSha256,StringComparison.OrdinalIgnoreCase))throw new IOException("ClamD executable SHA-256 pin mismatch.");}}
  }
  // Read-only lab checks. Never call Contain, Quarantine, or publish a detection from this path.
  internal static object ContainmentDiagnostics(EndpointSettings c,string marker){
   var rows=new List<object>();var timer=Stopwatch.StartNew();
   Action<string,string,string> add=(name,state,evidence)=>{rows.Add(new {name=name,state=state,evidence=evidence,durationMs=timer.ElapsedMilliseconds});timer.Restart();};
   add("Containment policy",c.Enabled&&c.Mode=="contain"&&c.RealTime&&c.ProcessCorrelation&&c.ResponsePaths.Length>0&&c.ContainmentExecutables.Length>0?"Pass":"Review","Enabled="+c.Enabled+"; mode="+c.Mode+"; real-time="+c.RealTime+"; correlation="+c.ProcessCorrelation+"; response paths="+c.ResponsePaths.Length+"; eligible executables="+c.ContainmentExecutables.Length+". Configuration prerequisites only; no response executed.");
   try{
    byte[] flat=new byte[65536],uniform=new byte[65536];for(int i=0;i<uniform.Length;i++)uniform[i]=(byte)(i%256);
    double low=EndpointProtection.Entropy(flat,flat.Length),high=EndpointProtection.Entropy(uniform,uniform.Length);
    bool vectors=Math.Abs(low)<0.00001&&Math.Abs(high-8)<0.00001;
    bool qualifies=EndpointProtection.EntropyTransition(uniform.Length,high,low,c);
    add("Entropy detector (in memory)",vectors&&qualifies?"Pass":"Review","Known vectors: "+low.ToString("F3",System.Globalization.CultureInfo.InvariantCulture)+" -> "+high.ToString("F3",System.Globalization.CultureInfo.InvariantCulture)+" bits/byte; current policy qualifies="+qualifies+". No files written.");
    bool rapid=EndpointProtection.RansomwareCorroborated(c.ChangeThreshold,3,c.ChangeThreshold)&&!EndpointProtection.RansomwareCorroborated(c.ChangeThreshold,2,c.ChangeThreshold);
    var now=DateTime.UtcNow;var paths=new Dictionary<string,DateTime>(StringComparer.OrdinalIgnoreCase){{@"C:\Lab\one",now},{@"C:\Lab\two",now},{@"C:\Other\three",now},{@"C:\Lab\old",now.AddSeconds(-c.ExtendedEntropyWindowSeconds-1)}};
    bool extended=EndpointProtection.ExtendedEntropyPeak(paths,now,c.ExtendedEntropyWindowSeconds).Value==2;
    add("Behavior aggregation (in memory)",rapid&&extended?"Pass":"Fail","Rapid corroboration, directory grouping and expiry; no incident emitted.");
    bool canary=CanaryTemplates.Names.All(n=>{var b=CanaryTemplates.Bytes(n);string original=CanaryTemplates.ExpectedHash(n);if(b.Length==0||EndpointProtection.Hash(b)!=original)return false;b[0]^=1;return EndpointProtection.Hash(b)!=original;});
    add("Canary hash (in memory)",canary?"Pass":"Fail","Original and changed template hashes compared; no enrolled canary altered.");
    bool cleanRejected=false,heuristicRejected=false;try{Confirmed("stream: OK");}catch(IOException){cleanRejected=true;}try{Confirmed("stream: Heuristics.Test FOUND");}catch(IOException){heuristicRejected=true;}
    add("Response refusal gate (in memory)",cleanRejected&&heuristicRejected?"Pass":"Fail","Actual verdict gate rejected clean and heuristic-only replies. No positive verdict injected and no response executed.");
   }catch(Exception ex){add("Detector checks","Fail",ex.GetType().Name+": "+ex.Message);}
   bool securityReadable=false;
   try{using(var reader=new EventLogReader(new EventLogQuery("Security",PathType.LogName,"*"){ReverseDirection=true})){reader.BatchSize=1;using(var ev=reader.ReadEvent(TimeSpan.FromMilliseconds(1000))){securityReadable=ev!=null;add("Security log readability",ev==null?"Review":"Pass",ev==null?"Query succeeded, but no event returned; actual read not verified.":"Service read Security record "+ev.RecordId+". Read-only channel access verified.");}}}catch(Exception ex){add("Security log readability","Review",ex.GetType().Name+": "+ex.Message+". Read access not verified; inspect local Setup > Endpoint permission repair if access is denied.");}
   if(securityReadable){
    // Diagnostic only: a recent file write/delete within a saved protected root is evidence of auditing, not writer attribution or a response verdict.
    const int auditBudgetMs=3000,auditMaxRecords=512;
    var auditTimer=Stopwatch.StartNew();int inspected=0;bool matched=false,exhausted=false;
    try{
     var auditQuery=new EventLogQuery("Security",PathType.LogName,"*"){ReverseDirection=true};
     DateTime cutoff=DateTime.UtcNow.AddMinutes(-15);
     using(var reader=new EventLogReader(auditQuery)){
      reader.BatchSize=1;
      while(inspected<auditMaxRecords&&auditTimer.ElapsedMilliseconds<auditBudgetMs){
       using(var ev=reader.ReadEvent(TimeSpan.FromMilliseconds(Math.Max(1L,auditBudgetMs-auditTimer.ElapsedMilliseconds)))){
        if(ev==null){exhausted=true;break;}inspected++;
        if(!ev.TimeCreated.HasValue)continue;
        if(ev.TimeCreated.Value.ToUniversalTime()<cutoff){exhausted=true;break;}
        if(ev.Id!=4663||!ev.RecordId.HasValue||ev.RecordId.Value<=0||ev.TimeCreated.Value.ToUniversalTime()>DateTime.UtcNow.AddSeconds(2))continue;
        var doc=new XmlDocument{XmlResolver=null};doc.LoadXml(ev.ToXml());var ns=new XmlNamespaceManager(doc.NameTable);ns.AddNamespace("e","http://schemas.microsoft.com/win/2004/08/events/event");
        var typeNode=doc.SelectSingleNode("/e:Event/e:EventData/e:Data[@Name='ObjectType']",ns);
        if(typeNode==null||!string.Equals(typeNode.InnerText,"File",StringComparison.OrdinalIgnoreCase))continue;
        var objectNode=doc.SelectSingleNode("/e:Event/e:EventData/e:Data[@Name='ObjectName']",ns);var accessNode=doc.SelectSingleNode("/e:Event/e:EventData/e:Data[@Name='AccessMask']",ns);
        if(objectNode==null||accessNode==null||!ev.TimeCreated.HasValue)continue;
        string path=objectNode.InnerText;long mask;
        if(string.IsNullOrEmpty(path)||!Hex(accessNode.InnerText,out mask)||(mask&0x10046)==0||!c.Paths.Any(x=>EndpointProtection.Under(path,x))||EndpointProtection.Excluded(c,path))continue;
        matched=true;add("File system audit evidence","Pass","Recent protected-path write/delete audit: Security record "+ev.RecordId+"; UTC "+ev.TimeCreated.Value.ToUniversalTime().ToString("o")+"; "+path+". Auditing evidence only; not a matching writer or containment test.");break;
       }
      }
     }
     if(!matched)add("File system audit evidence","Review",(exhausted?"Query completed; no matching recent protected-path write/delete record.":"Bounded query incomplete; no matching record verified before the time or record limit.")+" Inspected "+inspected+" records (15-minute window, up to 512 Security records / 3 seconds of reads). Verify file-system success auditing and folder SACL inheritance, then generate fresh lab activity.");
    }catch(Exception ex){add("File system audit evidence","Review","Audit evidence query inconclusive after "+auditTimer.ElapsedMilliseconds+" ms and "+inspected+" records: "+ex.GetType().Name+": "+ex.Message+". Security channel access was checked separately; this does not prove that auditing is disabled. Generate fresh lab activity and retry.");}
   }else add("File system audit evidence","Not tested","Security channel read access must be resolved first.");
   var pathChecks=CheckResponsePaths(c);if(pathChecks.Length==0)add("Response directory permissions","Review","No explicit response paths configured.");else foreach(var pathCheck in pathChecks)add("Response path access",pathCheck.status=="ok"?"Pass":"Review",pathCheck.path+" — "+pathCheck.detail);
   if(string.IsNullOrWhiteSpace(marker)){add("Lab writer correlation","Not tested","Run the local lab script, paste its exact marker path, then check within 30 seconds of the write.");}
   else try{
    if(marker.Length>1024||!Path.IsPathRooted(marker)||!string.Equals(Path.GetFullPath(marker),marker,StringComparison.OrdinalIgnoreCase)||!string.Equals(Path.GetFileName(marker),"audit-marker.txt",StringComparison.OrdinalIgnoreCase))throw new IOException("Expected the exact lab marker path.");
    string folder=Path.GetDirectoryName(marker);if(!Regex.IsMatch(Path.GetFileName(folder)??"",@"^LinkScope-Containment-Lab-[0-9a-f]{32}$",RegexOptions.IgnoreCase)||!SafeScope(marker)||EndpointProtection.Excluded(c,marker)||!c.Paths.Any(x=>EndpointProtection.Under(marker,x)))throw new IOException("Marker must be inside an existing protected, non-system lab folder.");
    EndpointProtection.SafePath(marker);var a=FindWriter(marker);if(a==null){add("Lab writer correlation","Review","No matching write event in the production 30-second/512-event search window.");}
    else{
     string expected=Path.Combine(folder,"LinkScopeLab.exe");bool exact=string.Equals(a.Image,expected,StringComparison.OrdinalIgnoreCase);
     add("Lab writer correlation",exact?"Pass":"Review","Record "+a.Record+"; PID "+a.Pid+"; "+a.Image+"; UTC "+a.Utc.ToString("o")+". Matching event is correlation, not proof.");
     if(exact&&a.Pid!=Process.GetCurrentProcess().Id&&a.Pid>4){
      using(var process=OpenProcess(0x1000,false,a.Pid)){
       if(process.IsInvalid)throw NativeFailure("Cannot query lab process");
       var name=new StringBuilder(4096);int size=name.Capacity;long created,exit,kernel,user;uint exitCode;bool critical;
       bool verified=QueryFullProcessImageName(process,0,name,ref size)&&string.Equals(name.ToString(),expected,StringComparison.OrdinalIgnoreCase)&&GetProcessTimes(process,out created,out exit,out kernel,out user)&&DateTime.FromFileTimeUtc(created)<=a.Utc&&GetExitCodeProcess(process,out exitCode)&&exitCode==259&&IsProcessCritical(process,out critical)&&!critical;
       add("Lab process identity",verified?"Pass":"Review","Query-only handle; image, lifetime and noncritical process verification="+verified+". No termination access requested.");
      }
     }
    }
   }catch(Exception ex){add("Lab writer / process check","Review",ex.GetType().Name+": "+ex.Message);}
   add("Live quarantine and termination","Not tested","No files quarantined and no process terminated by these checks. Use the isolated lab procedures; a successful production malicious-process termination requires a real confirmed signature and every response gate.");
   return new {utc=DateTime.UtcNow.ToString("o"),checks=rows.ToArray()};
  }
  // Explicit administrator-requested live probe. This is separate from the read-only diagnostics and
  // never invokes production response, changes ACLs, modifies existing files, or accepts file content.
  // Called inside the independent PowerShell process. Reuse the proven native reopen, and check
  // the service-owned file identity BEFORE writing. A late child cannot write to a replacement path.
  static string ProbeIdentity(FileInfoNative info){return info.Volume.ToString("X8")+":"+info.IndexHigh.ToString("X8")+":"+info.IndexLow.ToString("X8");}
  internal static void WriteExternalMarker(string path,string expectedIdentity){
   if(string.IsNullOrEmpty(path)||path.Length>1024||!Path.IsPathRooted(path)||!string.Equals(Path.GetFullPath(path),path,StringComparison.OrdinalIgnoreCase)||!SafeScope(path)||!Regex.IsMatch(Path.GetFileName(path),@"^LinkScope-Audit-Probe-[0-9a-f]{32}\.txt$",RegexOptions.IgnoreCase)||string.IsNullOrEmpty(expectedIdentity))throw new IOException("Invalid fixed lab marker.");
   EndpointProtection.SafePath(path);
   using(var handle=CreateFile(path,0x40000080U,7,IntPtr.Zero,3,0x00200000,IntPtr.Zero)){
    if(handle.IsInvalid)throw NativeFailure("Cannot reopen the service-owned marker");VerifyHandle(handle,path);FileInfoNative info;
    if(!GetFileInformationByHandle(handle,out info)||info.SizeHigh!=0||info.SizeLow!=0||!string.Equals(ProbeIdentity(info),expectedIdentity,StringComparison.Ordinal))throw new IOException("Marker identity or empty length changed; no write performed.");
    using(var file=new FileStream(handle,FileAccess.Write)){byte[] text=Encoding.ASCII.GetBytes("LinkScope benign external writer probe\r\n");file.Write(text,0,text.Length);file.Flush(true);}
   }
  }
  internal static object LiveAuditProbe(EndpointSettings c,string directory){return LiveAuditProbe(c,directory,false);}
  internal static object LiveAuditProbe(EndpointSettings c,string directory,bool external){
   var rows=new List<object>();var timer=Stopwatch.StartNew();
   Action<string,string,string> add=(name,state,evidence)=>{rows.Add(new {name=name,state=state,evidence=evidence,durationMs=timer.ElapsedMilliseconds});timer.Restart();};
   string path=null,observedPath=null,image=null;int pid=0,servicePid=0;Process child=null;SafeFileHandle childQuery=null;DateTime childCreated=DateTime.MinValue;FileStream scriptLock=null;var ancestorPins=new List<SafeFileHandle>();long baselineRecord=0;bool created=false,written=false,clean=false,completeWrite=false;object proof=null;DateTime start=DateTime.UtcNow;
   try{
    if(!Program.ServiceMode||!c.Enabled||!c.ProcessCorrelation)throw new IOException("Run on the installed service with Endpoint Protection and process correlation enabled.");
    // Use the canonical spelling from the saved policy, not a request-supplied path alias.
    string root=c.ResponsePaths.FirstOrDefault(x=>string.Equals(x,directory,StringComparison.OrdinalIgnoreCase));
    if(string.IsNullOrEmpty(root)||!c.TestPaths.Contains(root,StringComparer.OrdinalIgnoreCase)||c.ResponsePaths.Any(x=>!string.Equals(x,root,StringComparison.OrdinalIgnoreCase)&&EndpointProtection.Under(x,root))||!Path.IsPathRooted(root)||!string.Equals(Path.GetFullPath(root),root,StringComparison.OrdinalIgnoreCase)||!SafeScope(root)||!c.Paths.Any(x=>EndpointProtection.Under(root,x))||EndpointProtection.Excluded(c,root)||!Directory.Exists(root))throw new IOException("Select an existing, non-excluded directory explicitly saved in Test Center settings, within leaf response scope.");
    EndpointProtection.SafePath(root);
    path=Path.Combine(root,"LinkScope-Audit-Probe-"+Guid.NewGuid().ToString("N")+".txt");
    if(EndpointProtection.Excluded(c,path)||!SafeScope(path)||c.CanaryPaths.Contains(path,StringComparer.OrdinalIgnoreCase))throw new IOException("The generated marker is excluded or is not eligible.");
    using(var current=Process.GetCurrentProcess()){pid=servicePid=current.Id;image=current.MainModule.FileName;}
    add("Selected audit scope","Pass",root+"; existing service identity and saved response policy only.");
    // Capture a real channel watermark before generating any activity. Do not infer it from timestamps.
    using(var baselineReader=new EventLogReader(new EventLogQuery("Security",PathType.LogName,"*"){ReverseDirection=true})){
     baselineReader.BatchSize=1;using(var baseline=baselineReader.ReadEvent(TimeSpan.FromMilliseconds(1000))){
      if(baseline==null||!baseline.RecordId.HasValue||baseline.RecordId.Value<=0)throw new IOException("Cannot establish a pre-probe Security record watermark; no marker created.");
      baselineRecord=baseline.RecordId.Value;
     }
    }
    start=DateTime.UtcNow;
    if(external){
     // Pin ancestors against replacement while the separate process opens the service-owned file.
     for(var d=new DirectoryInfo(root);d!=null&&d.Parent!=null;d=d.Parent){var pin=CreateFile(d.FullName,0x80U,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);ancestorPins.Add(pin);FileInfoNative di;var resolved=new StringBuilder(4096);uint n=pin.IsInvalid?0:GetFinalPathNameByHandle(pin,resolved,(uint)resolved.Capacity,0);if(n==0||n>=resolved.Capacity||!string.Equals(resolved.ToString().TrimEnd('\\'),(@"\\?\"+d.FullName).TrimEnd('\\'),StringComparison.OrdinalIgnoreCase)||!GetFileInformationByHandle(pin,out di)||(di.Attributes&0x410)!=0x10)throw new IOException("Cannot pin lab directory ancestry.");}
     string script=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"lab","Test-LinkScopeContainmentLab.ps1");
     EndpointProtection.SafePath(script);scriptLock=new FileStream(script,FileMode.Open,FileAccess.Read,FileShare.Read);VerifyHandle(scriptLock.SafeFileHandle,script);
     byte[] embedded=Program.Resource("Test-LinkScopeContainmentLab.ps1");if(scriptLock.Length!=embedded.Length)throw new IOException("Installed lab script differs from embedded version; repair Setup.");
     using(var mem=new MemoryStream()){scriptLock.CopyTo(mem);if(!mem.ToArray().SequenceEqual(embedded))throw new IOException("Installed lab script differs from embedded version; repair Setup.");}
     image=Path.Combine(Environment.SystemDirectory,"WindowsPowerShell","v1.0","powershell.exe");EndpointProtection.SafePath(image);if(!File.Exists(image))throw new IOException("Windows PowerShell 5.1 executable unavailable.");
    }
    // CREATE_NEW and DELETE_ON_CLOSE establish a unique owned marker and preserve cleanup even on error.
    // Reopen that same file for a distinct write access check against the inherited SACL.
    // Retain the original handle without delete sharing; verify identity before writing on the second handle.
    // No elevated helper, new access grant, truncation or explicit path-based deletion.
    using(var parent=CreateFile(root,0x80U,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero)){
     if(parent.IsInvalid)throw NativeFailure("Cannot pin selected directory");
     var finalDir=new StringBuilder(4096);uint dirLength=GetFinalPathNameByHandle(parent,finalDir,(uint)finalDir.Capacity,0);FileInfoNative parentInfo;
     if(dirLength==0||dirLength>=finalDir.Capacity||!string.Equals(finalDir.ToString().TrimEnd('\\'),(@"\\?\"+root).TrimEnd('\\'),StringComparison.OrdinalIgnoreCase)||!GetFileInformationByHandle(parent,out parentInfo)||(parentInfo.Attributes&0x410)!=0x10)throw new IOException("Selected directory identity or final path changed.");
     using(var handle=CreateFile(path,0x10080U,2,IntPtr.Zero,1,0x04200000,IntPtr.Zero)){
      if(handle.IsInvalid)throw NativeFailure("Cannot create disposable marker with existing service permissions; no ACL changes made");
      created=true;VerifyHandle(handle,path);
      var actual=new StringBuilder(4096);uint n=GetFinalPathNameByHandle(handle,actual,(uint)actual.Capacity,0);
      if(n==0||n>=actual.Capacity||!actual.ToString().StartsWith(@"\\?\",StringComparison.Ordinal))throw new IOException("Cannot resolve audit marker path.");
      observedPath=actual.ToString().Substring(4);
      FileInfoNative original;
      if(!GetFileInformationByHandle(handle,out original))throw NativeFailure("Cannot identify created marker");
      if(external){
       // Fixed installed script, fixed arguments, no shell or user-provided command. Runs as LocalService.
       var psi=new ProcessStartInfo(image,"-NoLogo -NoProfile -NonInteractive -File \""+scriptLock.Name+"\" -AutomaticWriter"){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=AppDomain.CurrentDomain.BaseDirectory,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardOutputEncoding=Encoding.UTF8};
       psi.EnvironmentVariables["LINKSCOPE_LAB_MARKER"]=observedPath;psi.EnvironmentVariables["LINKSCOPE_LAB_IDENTITY"]=ProbeIdentity(original);
       child=Process.Start(psi);if(child==null)throw new IOException("PowerShell failed to start.");var retained=child.Handle;pid=child.Id;
       childQuery=OpenProcess(QueryLimited,false,pid);long born,exited,kernel,user;
       if(pid==servicePid||childQuery.IsInvalid||!LiveImage(childQuery,image)||!GetProcessTimes(childQuery,out born,out exited,out kernel,out user))throw new IOException("Independent PowerShell process identity could not be verified.");childCreated=DateTime.FromFileTimeUtc(born);
       if(childCreated<start.AddSeconds(-1)||childCreated>DateTime.UtcNow.AddSeconds(2))throw new IOException("Unexpected PowerShell start time.");
       var err=child.StandardError.ReadToEndAsync();var line=child.StandardOutput.ReadLineAsync();
       if(!line.Wait(6000)||!string.Equals(line.Result,"LINKSCOPE_MARKER:"+Convert.ToBase64String(Encoding.UTF8.GetBytes(observedPath)),StringComparison.Ordinal))throw new IOException("PowerShell did not confirm the expected marker write. Check installed script and execution policy."+(err.IsCompleted&& !err.IsFaulted&&!err.IsCanceled?" "+err.Result.Substring(0,Math.Min(500,err.Result.Length)):""));
       FileInfoNative after;if(!GetFileInformationByHandle(handle,out after)||after.Volume!=original.Volume||after.IndexHigh!=original.IndexHigh||after.IndexLow!=original.IndexLow||after.SizeHigh!=0||after.SizeLow!=(uint)Encoding.ASCII.GetByteCount("LinkScope benign external writer probe\r\n"))throw new IOException("Owned marker identity or written length differs.");
       written=true;
      }else{
      // OPEN_EXISTING, with share-delete for the original DELETE_ON_CLOSE handle. No create/truncate on reopen.
      using(var writerHandle=CreateFile(path,0x40000080U,7,IntPtr.Zero,3,0x00200000,IntPtr.Zero)){
       if(writerHandle.IsInvalid)throw NativeFailure("Cannot reopen the owned marker for a separate audited write; no permissions changed");
       VerifyHandle(writerHandle,path);FileInfoNative reopened;
       if(!GetFileInformationByHandle(writerHandle,out reopened)||original.Volume!=reopened.Volume||original.IndexHigh!=reopened.IndexHigh||original.IndexLow!=reopened.IndexLow||reopened.SizeHigh!=0||reopened.SizeLow!=0)throw new IOException("Reopened marker identity or initial length differs; no write performed.");
       using(var stream=new FileStream(writerHandle,FileAccess.Write)){
        byte[] marker=Encoding.ASCII.GetBytes("LinkScope benign live audit probe\r\n");stream.Write(marker,0,marker.Length);stream.Flush(true);written=true;
       }
      }
      }
     }
    }
    completeWrite=true;add("Disposable marker write","Pass",observedPath+"; writer PID "+pid+(external?"; independent PowerShell reported the exact marker; original file identity and length verified.":"; fixed harmless content written through a separately opened, identity-verified handle."));
   }catch(Exception ex){add("Disposable marker write","Review",ex.GetType().Name+": "+ex.Message+(created?"; created marker: "+path+"; intended writer PID "+pid:""));}
   if(created){
    try{File.GetAttributes(path);add("Marker cleanup","Review","Marker path still exists or was reused. No additional deletion attempted: "+path);}
    catch(FileNotFoundException){clean=true;add("Marker cleanup","Pass","Delete-on-close verified; marker no longer exists.");}
    catch(Exception ex){add("Marker cleanup","Review","Cleanup not independently verified: "+ex.GetType().Name+": "+ex.Message+"; "+path);}
   }else add("Marker cleanup","Not tested","No marker was created by this request.");
   string exactCheck=external?"Exact Event 4663 / external writer":"Exact Event 4663 / service writer";
   bool matched=false;string queryError=null;int inspected=0;
   if(written){
    var budget=Stopwatch.StartNew();const int maxMs=8000,maxRecords=512;var seen=new HashSet<long>();var eventCounts=new Dictionary<int,int>();int queries=0,pathMatches=0,auditRecords=0,parentMatches=0;bool reachedBaseline=false;
    try{
     // Use the already verified unfiltered channel reader, not the sparse EventID=4663 XPath.
     // Stop at the pre-write record watermark; inspect only newly observed records.
     string filter="*";
     while(!matched&&budget.ElapsedMilliseconds<maxMs&&inspected<maxRecords){
      try{queries++;using(var reader=new EventLogReader(new EventLogQuery("Security",PathType.LogName,filter){ReverseDirection=true})){
       reader.BatchSize=1;
       while(inspected<maxRecords&&budget.ElapsedMilliseconds<maxMs){
        using(var ev=reader.ReadEvent(TimeSpan.FromMilliseconds(Math.Max(1L,Math.Min(2000L,maxMs-budget.ElapsedMilliseconds))))){
         if(ev==null)break;
         DateTime eventUtc=ev.TimeCreated.HasValue?ev.TimeCreated.Value.ToUniversalTime():DateTime.MinValue;
         if(!ev.RecordId.HasValue||ev.RecordId.Value<=0)continue;
         if(ev.RecordId.Value<=baselineRecord){reachedBaseline=true;break;}
         // Skip duplicate records across retries, including after an incomplete traversal.
         if(!seen.Add(ev.RecordId.Value))continue;inspected++;
         int eventCount;eventCounts.TryGetValue(ev.Id,out eventCount);eventCounts[ev.Id]=eventCount+1;
         if(ev.Id!=4663)continue;auditRecords++;
         var doc=new XmlDocument{XmlResolver=null};doc.LoadXml(ev.ToXml());var ns=new XmlNamespaceManager(doc.NameTable);ns.AddNamespace("e","http://schemas.microsoft.com/win/2004/08/events/event");
         Func<string,string> field=name=>{var node=doc.SelectSingleNode("/e:Event/e:EventData/e:Data[@Name='"+name+"']",ns);return node==null?"":node.InnerText;};
         long mask,writer;
         if(ev.Id!=4663||!string.Equals(field("ObjectType"),"File",StringComparison.OrdinalIgnoreCase))continue;
         string auditedPath=field("ObjectName");
         if(string.Equals(auditedPath,Path.GetDirectoryName(observedPath),StringComparison.OrdinalIgnoreCase))parentMatches++;
         if(!string.Equals(field("ObjectName"),observedPath,StringComparison.OrdinalIgnoreCase))continue;pathMatches++;
         if(!Hex(field("AccessMask"),out mask)||(mask&6)==0||!Hex(field("ProcessId"),out writer)||writer!=pid||!string.Equals(field("ProcessName"),image,StringComparison.OrdinalIgnoreCase)||eventUtc<start.AddSeconds(-1)||eventUtc>DateTime.UtcNow.AddSeconds(2))continue;
         if(external&&(childQuery==null||!LiveImage(childQuery,image)||eventUtc<childCreated))continue;
         proof=new {eventId=ev.Id,recordId=ev.RecordId.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),eventUtc=eventUtc.ToString("o"),path=field("ObjectName"),pid=writer,image=field("ProcessName"),accessMask=mask};
         matched=true;add(exactCheck,"Pass","Record "+ev.RecordId+"; UTC "+eventUtc.ToString("o")+"; PID "+writer+"; pre-probe record "+baselineRecord+"; image "+image+"; mask 0x"+mask.ToString("X")+"; "+observedPath);break;
        }
       }
      }}catch(EventLogException ex){queryError=ex.GetType().Name+": "+ex.Message;}
      if(!matched&&budget.ElapsedMilliseconds<maxMs)Thread.Sleep((int)Math.Min(150L,Math.Max(0L,maxMs-budget.ElapsedMilliseconds)));
     }
    }catch(Exception ex){queryError=ex.GetType().Name+": "+ex.Message;}
    if(!matched)add(exactCheck,"Review","No exact fresh write event verified within the bounded query ("+inspected+" unique post-watermark Security records, "+auditRecords+" Event 4663 records, "+pathMatches+" exact-path candidates, "+parentMatches+" parent-directory candidates, observed event IDs: "+(eventCounts.Count==0?"none":string.Join(", ",eventCounts.OrderBy(x=>x.Key).Select(x=>x.Key+"="+x.Value)))+"; "+queries+" queries, "+budget.ElapsedMilliseconds+" ms; baseline record "+baselineRecord+"; reached watermark="+reachedBaseline+"). "+(queryError==null?"No verified match; this does not establish that Windows auditing failed. Inspect the exact marker in the local Security log and compare audit policy for the service identity and SACL on the selected folder. Use a disposable test folder, not the application root.":"Last query error: "+queryError+". Query inconclusive; no writer verdict."));
   }else add(exactCheck,"Not tested","A successful marker write is required first.");
   bool exitedCleanly=!external;
   if(external){
    try{if(child!=null){child.StandardInput.Close();exitedCleanly=child.WaitForExit(3000)&&child.ExitCode==0;add("External writer exit",exitedCleanly?"Pass":"Review",exitedCleanly?"The exact launched PowerShell process exited normally with code 0.":"Normal exit not verified; no termination attempted.");}else add("External writer exit","Not tested","No process launched.");}catch(Exception ex){add("External writer exit","Review",ex.Message);}
    finally{if(childQuery!=null)childQuery.Dispose();if(child!=null)child.Dispose();if(scriptLock!=null)scriptLock.Dispose();foreach(var pin in ancestorPins)pin.Dispose();}
   }
   add("Production containment","Not tested","This probe verifies audit delivery and "+(external?"independent PowerShell writer attribution":"self-writer attribution")+" only. No malware verdict, quarantine or process termination requested.");
   return new {utc=DateTime.UtcNow.ToString("o"),passed=written&&clean&&matched&&completeWrite&&exitedCleanly,marker=written?new {path=observedPath,pid=pid,image=image,startedUtc=start.ToString("o"),baselineRecordId=baselineRecord.ToString(System.Globalization.CultureInfo.InvariantCulture),servicePid=servicePid,external=external,processCreatedUtc=external?childCreated.ToString("o"):null}:null,proof=proof,checks=rows.ToArray()};
  }
  // Only service-generated GUID names in a selected saved lab directory. Pin the full ancestry.
  internal static List<SafeFileHandle> PinProtectionLab(EndpointSettings c,string directory){
   if(!Program.ServiceMode||!c.Enabled||!c.RealTime||c.Mode=="monitor"||!c.ResponsePaths.Contains(directory,StringComparer.OrdinalIgnoreCase)||!c.TestPaths.Contains(directory,StringComparer.OrdinalIgnoreCase)||!c.Paths.Any(x=>EndpointProtection.Under(directory,x))||!SafeScope(directory)||EndpointProtection.Excluded(c,directory)||!Directory.Exists(directory)||c.ResponsePaths.Any(x=>!string.Equals(x,directory,StringComparison.OrdinalIgnoreCase)&&EndpointProtection.Under(x,directory)))throw new IOException("Select a dedicated existing leaf response directory saved in Test Center settings in Protect or Contain mode with real-time scanning enabled. Broad parent response directories are refused.");
   EndpointProtection.SafePath(directory);var pins=new List<SafeFileHandle>();try{
    for(var d=new DirectoryInfo(directory);d!=null&&d.Parent!=null;d=d.Parent){var pin=CreateFile(d.FullName,0x80U,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);pins.Add(pin);FileInfoNative di;var resolved=new StringBuilder(4096);uint n=pin.IsInvalid?0:GetFinalPathNameByHandle(pin,resolved,(uint)resolved.Capacity,0);if(n==0||n>=resolved.Capacity||!string.Equals(resolved.ToString().TrimEnd('\\'),(@"\\?\"+d.FullName).TrimEnd('\\'),StringComparison.OrdinalIgnoreCase)||!GetFileInformationByHandle(pin,out di)||(di.Attributes&0x410)!=0x10)throw new IOException("Cannot pin lab directory ancestry.");}
    return pins;
   }catch{foreach(var pin in pins)pin.Dispose();throw;}
  }
  internal static string ProtectionLabPath(EndpointSettings c,string root,string name){string path=Path.Combine(root,name);if(!SafeScope(path)||EndpointProtection.Excluded(c,path)||c.CanaryPaths.Contains(path,StringComparer.OrdinalIgnoreCase)||c.ContainmentExecutables.Contains(path,StringComparer.OrdinalIgnoreCase))throw new IOException("Generated test file is excluded or registered in production policy.");return path;}
  // Test actual disk bytes against the shared production comparator, without enrolling a production canary.
  internal static void DisposableCanary(string path,byte[] original,out string before,out string after){
   before=after=null;using(var h=CreateFile(path,0xC0010080U,0,IntPtr.Zero,1,0x04200000,IntPtr.Zero)){
    if(h.IsInvalid)throw NativeFailure("Cannot create disposable canary");VerifyHandle(h,path);
    using(var f=new FileStream(h,FileAccess.ReadWrite)){f.Write(original,0,original.Length);f.Flush(true);f.Position=0;before=EndpointProtection.FileHash(f);f.Position=0;f.WriteByte((byte)(original[0]^1));f.Flush(true);f.Position=0;after=EndpointProtection.FileHash(f);}
   }
  }
  internal static void CreateEicarLabSample(string path,byte[] bytes,out string identity){CreateOwnedLabSample(path,bytes,out identity);}
  internal static void CreateOwnedLabSample(string path,byte[] bytes,out string identity){
   identity=null;using(var h=CreateFile(path,0xC0000080U,0,IntPtr.Zero,1,0x00200000,IntPtr.Zero)){
    if(h.IsInvalid)throw NativeFailure("Cannot create owned lab sample (another security product may have intercepted it)");VerifyHandle(h,path);FileInfoNative info;if(!GetFileInformationByHandle(h,out info))throw NativeFailure("Cannot identify lab sample");identity=ProbeIdentity(info);
    using(var f=new FileStream(h,FileAccess.ReadWrite)){f.Write(bytes,0,bytes.Length);f.Flush(true);f.Position=0;if(EndpointProtection.FileHash(f)!=EndpointProtection.Hash(bytes))throw new IOException("Lab sample bytes changed during creation.");}
   }
  }
  internal static void ChangeEnrolledLabCanary(string path,string identity,byte[] baseline){
   EndpointProtection.SafePath(path);using(var h=CreateFile(path,0xC0000080U,0,IntPtr.Zero,3,0x00200000,IntPtr.Zero)){
    if(h.IsInvalid)throw NativeFailure("Cannot reopen enrolled disposable canary");VerifyHandle(h,path);FileInfoNative info;
    if(!GetFileInformationByHandle(h,out info)||ProbeIdentity(info)!=identity)throw new IOException("Disposable canary identity changed.");
    using(var f=new FileStream(h,FileAccess.ReadWrite)){if(f.Length!=baseline.Length||EndpointProtection.FileHash(f)!=EndpointProtection.Hash(baseline))throw new IOException("Disposable canary baseline changed before the exercise.");f.Position=0;f.WriteByte((byte)(baseline[0]^1));f.Flush(true);}
   }
  }
  internal static void CleanupEnrolledLabCanary(string path,string identity,string expected,string changed,int length){
   if(string.IsNullOrEmpty(identity))throw new IOException("No original canary identity; no deletion authorized.");EndpointProtection.SafePath(path);
   using(var h=CreateFile(path,0x80010080U,0,IntPtr.Zero,3,0x00200000,IntPtr.Zero)){
    if(h.IsInvalid)throw NativeFailure("Cannot open owned disposable canary for cleanup");VerifyHandle(h,path);FileInfoNative info;if(!GetFileInformationByHandle(h,out info)||ProbeIdentity(info)!=identity)throw new IOException("Canary identity changed; not deleted.");
    using(var f=new FileStream(h,FileAccess.Read)){string hash=EndpointProtection.FileHash(f);if(f.Length!=length||(hash!=expected&&hash!=changed))throw new IOException("Canary contents changed unexpectedly; not deleted.");byte delete=1;if(!SetFileInformationByHandle(h,4,ref delete,1))throw NativeFailure("Cannot delete owned disposable canary");}
   }
  }
  // Cleanup never deletes a replacement or altered file. It does not create a quarantine receipt.
  internal static void CleanupEicarLabSample(string path,string identity,string expected){
   if(string.IsNullOrEmpty(identity))throw new IOException("No original file identity; no cleanup deletion authorized.");EndpointProtection.SafePath(path);
   using(var h=CreateFile(path,0x80010080U,0,IntPtr.Zero,3,0x00200000,IntPtr.Zero)){
    if(h.IsInvalid)throw NativeFailure("Cannot open original lab sample for cleanup");VerifyHandle(h,path);FileInfoNative info;if(!GetFileInformationByHandle(h,out info)||ProbeIdentity(info)!=identity)throw new IOException("Lab sample identity changed; not deleted.");
    using(var f=new FileStream(h,FileAccess.Read)){if(f.Length!=68||EndpointProtection.FileHash(f)!=expected)throw new IOException("Lab sample bytes changed; not deleted.");byte delete=1;if(!SetFileInformationByHandle(h,4,ref delete,1))throw NativeFailure("Cannot delete original lab sample");}
   }
  }
  static void Confirmed(string reply){if(!EndpointProtection.Malware(reply)||reply.IndexOf("Heuristics.",StringComparison.OrdinalIgnoreCase)>=0)throw new IOException("No confirmed non-heuristic malware signature on re-scan.");}
  internal static string Quarantine(string store,EndpointSettings c,string path,string expected,WaitHandle stop,Func<bool> authorized){if(!authorized()||!SafeScope(path)||EndpointProtection.Excluded(c,path)||!c.ResponsePaths.Any(x=>EndpointProtection.Under(path,x)))throw new IOException("Response policy refused file.");EndpointProtection.SafePath(path);string vault=Path.Combine(store,"quarantine");Directory.CreateDirectory(vault);EndpointProtection.SafePath(vault);long used=0;int count=0;foreach(var file in Directory.EnumerateFiles(vault,"*.sealed")){if(++count>=1000)throw new IOException("Quarantine item quota reached.");used+=new FileInfo(file).Length;if(used>2147483648L)throw new IOException("Quarantine vault quota reached.");}
   using(var handle=CreateFile(path,0x80010000,1,IntPtr.Zero,3,0x00200000,IntPtr.Zero)){if(handle.IsInvalid)throw NativeFailure("Cannot obtain exclusive write/delete protection for the file");VerifyHandle(handle,path);using(var stream=new FileStream(handle,FileAccess.Read)){if(stream.Length>c.MaxFileMiB*1048576L||used+stream.Length>2147483648L)throw new IOException("Quarantine size limit.");string hash=EndpointProtection.FileHash(stream);if(hash!=expected)throw new IOException("File changed since detection.");stream.Position=0;Confirmed(EndpointProtection.Command(c.Port,"INSTREAM",stream,stop,tcp=>VerifyEngine(c,tcp)));stream.Position=0;byte[] bytes=new byte[(int)stream.Length];int total=0,n;while(total<bytes.Length&&(n=stream.Read(bytes,total,bytes.Length-total))>0)total+=n;if(total!=bytes.Length||EndpointProtection.Hash(bytes)!=hash)throw new IOException("Evidence verification failed.");string id=Guid.NewGuid().ToString("N"),sealedPath=Path.Combine(vault,id+".sealed"),meta=Path.Combine(vault,id+".json");byte[] encrypted=ProtectedData.Protect(bytes,null,DataProtectionScope.LocalMachine);Array.Clear(bytes,0,bytes.Length);using(var output=new FileStream(sealedPath,FileMode.CreateNew,FileAccess.Write,FileShare.None)){output.Write(encrypted,0,encrypted.Length);output.Flush(true);}Config.Save(meta,new {id=id,path=path,sha256=hash,utc=DateTime.UtcNow.ToString("o"),state="evidence_saved"});if(!authorized()||stop.WaitOne(0))throw new IOException("Response cancelled; sealed evidence retained, original unchanged.");VerifyHandle(handle,path);byte delete=1;if(!SetFileInformationByHandle(handle,4,ref delete,1))throw NativeFailure("Original could not be removed; sealed evidence retained: "+id);Config.Save(meta,new {id=id,path=path,sha256=hash,utc=DateTime.UtcNow.ToString("o"),state="quarantined"});try{UserAudit.Write("endpoint-service","local","Quarantined confirmed malware: "+path+"; evidence "+id,200,"Success");}catch(Exception ex){AppJournal.Fault("Endpoint","audit",ex);}return "Sealed evidence ID "+id+"; original marked for deletion on close. SHA-256 "+hash;}}}
  // This helper is called only with a server-derived path inside the restricted vault.
  // Open the exact file without following reparse points; refuse hard links and path swaps.
  internal static void DeleteSealedPayload(string path){
   EndpointProtection.SafePath(path);using(var handle=CreateFile(path,0x10080U,0,IntPtr.Zero,3,0x00200000,IntPtr.Zero)){
    if(handle.IsInvalid)throw NativeFailure("Cannot open sealed payload for deletion");VerifyHandle(handle,path);byte delete=1;
    if(!SetFileInformationByHandle(handle,4,ref delete,1))throw NativeFailure("Cannot delete sealed payload");
   }
  }
  // The actual production precondition, also used by a read-only live refusal check.
  internal static bool EligibleContainmentTarget(EndpointSettings c,EndpointWriter a){return a!=null&&c.Mode=="contain"&&a.Pid>4&&a.Pid!=Process.GetCurrentProcess().Id&&c.ContainmentExecutables.Contains(a.Image,StringComparer.OrdinalIgnoreCase)&&SafeScope(a.Image)&&!EndpointProtection.Excluded(c,a.Image)&&c.ResponsePaths.Any(x=>EndpointProtection.Under(a.Image,x));}
  internal static string Contain(EndpointSettings c,EndpointWriter a,WaitHandle stop,Func<bool> authorized,out bool exitVerified){exitVerified=false;if(!authorized()||!EligibleContainmentTarget(c,a))throw new IOException("Writer is not explicitly eligible for containment.");if((DateTime.UtcNow-a.Utc).TotalSeconds>30||a.Utc>DateTime.UtcNow.AddSeconds(2))throw new IOException("Audit evidence is stale.");EndpointProtection.SafePath(a.Image);using(var process=OpenProcess(0x101001,false,a.Pid)){if(process.IsInvalid)throw new IOException("Cannot open verified process handle.");long created,exit,kernel,user;uint exitCode;bool critical;var name=new StringBuilder(4096);int size=name.Capacity;if(!QueryFullProcessImageName(process,0,name,ref size)||!string.Equals(name.ToString(),a.Image,StringComparison.OrdinalIgnoreCase)||!GetProcessTimes(process,out created,out exit,out kernel,out user)||!GetExitCodeProcess(process,out exitCode)||exitCode!=259||DateTime.FromFileTimeUtc(created)>a.Utc||!IsProcessCritical(process,out critical)||critical)throw new IOException("Process identity, lifetime or criticality could not be verified.");using(var p=Process.GetProcessById(a.Pid)){if(p.SessionId==0)throw new IOException("Session-zero services are excluded from automatic termination.");}uint? observedExitCode=null;using(var file=new FileStream(a.Image,FileMode.Open,FileAccess.Read,FileShare.Read)){VerifyHandle(file.SafeFileHandle,a.Image);if(file.Length>c.MaxFileMiB*1048576L)throw new IOException("Executable exceeds scan size cap.");Confirmed(EndpointProtection.Command(c.Port,"INSTREAM",file,stop,tcp=>VerifyEngine(c,tcp)));if(!authorized()||stop.WaitOne(0))throw new IOException("Containment cancelled.");exitVerified=TerminateAndObserve(process,1,out observedExitCode);}try{UserAudit.Write("endpoint-service","local",(exitVerified?"Verified exit of confirmed malicious writer: ":"Termination requested; exit unverified for confirmed malicious writer: ")+a.Image+" PID "+a.Pid+" audit record "+a.Record,exitVerified?200:409,exitVerified?"Success":"Error");}catch(Exception ex){AppJournal.Fault("Endpoint","audit",ex);}return (exitVerified?"Verified process exit (exit code 1) for explicitly eligible writer PID ":"Termination requested; exit unverified for explicitly eligible writer PID ")+a.Pid+"; Windows audit record "+a.Record+". Verify application recovery.";}}
 } // Fixed, non-privileged writer entry point for the installed PowerShell lab script.
 public static class LabProbeWriter {
  public static void WriteMarker(string path,string expectedIdentity){EndpointResponse.WriteExternalMarker(path,expectedIdentity);}
 }
}
