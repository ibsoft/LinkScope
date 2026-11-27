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
 internal sealed class EndpointWriter {internal int Pid; internal string Image; internal long Record; internal DateTime Utc;}
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
  internal static object[] CheckResponsePaths(EndpointSettings c){
   var rows=new List<object>();foreach(string path in c.ResponsePaths){string status="ok",detail;try{
    if(!SafeScope(path)||EndpointProtection.Excluded(c,path)||!c.Paths.Any(x=>EndpointProtection.Under(path,x)))throw new IOException("Path is outside the authorized response policy.");
    EndpointProtection.SafePath(path);bool directory=(File.GetAttributes(path)&FileAttributes.Directory)!=0;
    using(var handle=CreateFile(path,directory?0x41U:0x80010000U,7,IntPtr.Zero,3,0x02200000,IntPtr.Zero)){
     if(handle.IsInvalid)throw NativeFailure(directory?"Directory list/delete-child access unavailable; individual files may grant DELETE":"File read/delete access unavailable");
     if(!directory)VerifyHandle(handle,path);
     detail=directory?"Directory list and delete-child access granted. Individual file read access and locks still checked.":"File read and delete access granted; no file was changed.";
    }
   }catch(Exception ex){status="warning";detail=ex.Message;}
   rows.Add(new {path=path,status=status,detail=detail});}return rows.ToArray();
  }

  [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(SafeFileHandle process,uint exitCode);
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
  internal static string Contain(EndpointSettings c,EndpointWriter a,WaitHandle stop,Func<bool> authorized){if(!authorized()||c.Mode!="contain"||a.Pid<=4||a.Pid==Process.GetCurrentProcess().Id||!c.ContainmentExecutables.Contains(a.Image,StringComparer.OrdinalIgnoreCase)||!SafeScope(a.Image)||EndpointProtection.Excluded(c,a.Image)||!c.ResponsePaths.Any(x=>EndpointProtection.Under(a.Image,x)))throw new IOException("Writer is not explicitly eligible for containment.");if((DateTime.UtcNow-a.Utc).TotalSeconds>30||a.Utc>DateTime.UtcNow.AddSeconds(2))throw new IOException("Audit evidence is stale.");EndpointProtection.SafePath(a.Image);using(var process=OpenProcess(0x1001,false,a.Pid)){if(process.IsInvalid)throw new IOException("Cannot open verified process handle.");long created,exit,kernel,user;uint exitCode;bool critical;var name=new StringBuilder(4096);int size=name.Capacity;if(!QueryFullProcessImageName(process,0,name,ref size)||!string.Equals(name.ToString(),a.Image,StringComparison.OrdinalIgnoreCase)||!GetProcessTimes(process,out created,out exit,out kernel,out user)||!GetExitCodeProcess(process,out exitCode)||exitCode!=259||DateTime.FromFileTimeUtc(created)>a.Utc||!IsProcessCritical(process,out critical)||critical)throw new IOException("Process identity, lifetime or criticality could not be verified.");using(var p=Process.GetProcessById(a.Pid)){if(p.SessionId==0)throw new IOException("Session-zero services are excluded from automatic termination.");}using(var file=new FileStream(a.Image,FileMode.Open,FileAccess.Read,FileShare.Read)){VerifyHandle(file.SafeFileHandle,a.Image);if(file.Length>c.MaxFileMiB*1048576L)throw new IOException("Executable exceeds scan size cap.");Confirmed(EndpointProtection.Command(c.Port,"INSTREAM",file,stop,tcp=>VerifyEngine(c,tcp)));if(!authorized()||stop.WaitOne(0))throw new IOException("Containment cancelled.");if(!TerminateProcess(process,1))throw new IOException("Windows refused process termination.");}try{UserAudit.Write("endpoint-service","local","Terminated confirmed malicious writer: "+a.Image+" PID "+a.Pid+" audit record "+a.Record,200,"Success");}catch(Exception ex){AppJournal.Fault("Endpoint","audit",ex);}return "Termination requested for verified explicitly eligible writer PID "+a.Pid+"; Windows audit record "+a.Record+". Verify process exit and recovery.";}}
 }
}
