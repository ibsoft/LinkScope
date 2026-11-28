using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace LinkScope {
 // Privileged component: NTFS journal metadata and a separate scoped read-only scan pipe.
 // No file bytes are returned to clients, no shell commands, ACL changes or network listener.
 internal sealed class UsnJournalService : ServiceBase {
  internal const string Name="LinkScopeUsn";
  const string PipeName="LinkScope.UsnJournal.v2", ScanPipeName="LinkScope.ScopedScan.v1", WatchPipeName="LinkScope.ScopedWatch.v1";
  const int MaxScanReply=8*1024*1024, MaxDirectoryEntries=8192;
  const uint QueryJournal=0x000900f4, ReadJournal=0x000900bb;
  const uint Reasons=0x00003377; // content, create/delete, rename old/new
  const int MaxRecords=128, MaxReply=1024*1024;
  readonly ManualResetEvent stopping=new ManualResetEvent(false);
  readonly object watchLock=new object();
  const int MaxPrivilegedWatchRoots=32, MaxPrivilegedWatchQueue=2048, MaxPrivilegedWatchBatch=256;
  sealed class PrivilegedWatch {internal FileSystemWatcher Watcher;internal long Lease;internal bool Faulted,Gap;internal readonly Dictionary<string,bool> Events=new Dictionary<string,bool>(StringComparer.OrdinalIgnoreCase);}
  readonly Dictionary<string,PrivilegedWatch> privilegedWatches=new Dictionary<string,PrivilegedWatch>(StringComparer.OrdinalIgnoreCase);
  System.Threading.Timer watchLeaseTimer;
  readonly object gate=new object(); NamedPipeServerStream active,scanActive,watchActive; Thread worker,scanWorker,watchWorker;
  internal UsnJournalService(){ServiceName=Name;CanShutdown=true;}
  internal sealed class Batch {
   internal long Journal, Next, Tail; internal bool Gap; internal int Unresolved;
   internal string Error; internal readonly List<string> Paths=new List<string>(); internal readonly HashSet<string> Arrivals=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
  }
  [StructLayout(LayoutKind.Sequential)] struct FileId {internal uint Size;internal int Type;internal long Id;internal long Reserved;}
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool DeviceIoControl(SafeFileHandle h,uint control,byte[] input,int inputSize,byte[] output,int outputSize,out int returned,IntPtr overlapped);
  [DllImport("kernel32.dll",SetLastError=true)] static extern SafeFileHandle OpenFileById(SafeFileHandle volume,ref FileId id,uint access,uint share,IntPtr security,uint flags);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandle(SafeFileHandle h,StringBuilder path,uint size,uint flags);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe,out uint pid);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenSCManager(string machine,string database,uint access);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenService(IntPtr scm,string name,uint access);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool QueryServiceStatusEx(IntPtr service,int level,byte[] buffer,int size,out int needed);
  [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr handle);
  static bool IsReader(SafePipeHandle handle){
   uint pid;if(!GetNamedPipeServerProcessId(handle,out pid)||pid==0)return false;
   IntPtr scm=OpenSCManager(null,null,1);if(scm==IntPtr.Zero)return false;
   try{IntPtr svc=OpenService(scm,Name,4);if(svc==IntPtr.Zero)return false;try{var b=new byte[36];int n;return QueryServiceStatusEx(svc,0,b,b.Length,out n)&&BitConverter.ToUInt32(b,4)==4&&BitConverter.ToUInt32(b,28)==pid;}finally{CloseServiceHandle(svc);}}finally{CloseServiceHandle(scm);}
  }
  protected override void OnStart(string[] args){worker=new Thread(Run){IsBackground=true,Name="USN journal reader"};worker.Start();watchLeaseTimer=new System.Threading.Timer(_=>PrunePrivilegedWatches(),null,30000,30000);scanWorker=new Thread(()=>ScanRun(false)){IsBackground=true,Name="Scoped read-only scanner"};scanWorker.Start();watchWorker=new Thread(()=>ScanRun(true)){IsBackground=true,Name="Scoped watcher metadata"};watchWorker.Start();}
  protected override void OnStop(){stopping.Set();if(watchLeaseTimer!=null)watchLeaseTimer.Dispose();lock(watchLock){foreach(var w in privilegedWatches.Values)w.Watcher.Dispose();privilegedWatches.Clear();}lock(gate){if(active!=null)active.Dispose();if(scanActive!=null)scanActive.Dispose();if(watchActive!=null)watchActive.Dispose();}if(worker!=null)worker.Join(3000);if(scanWorker!=null)scanWorker.Join(3000);if(watchWorker!=null)watchWorker.Join(3000);}
  protected override void OnShutdown(){OnStop();}
  void Run(){
   while(!stopping.WaitOne(0))try{
    var acl=new PipeSecurity();acl.SetAccessRuleProtection(true,false);
    acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid,null),PipeAccessRights.FullControl,AccessControlType.Deny));
    acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),PipeAccessRights.FullControl,AccessControlType.Allow));
    acl.AddAccessRule(new PipeAccessRule(Program.ServiceSid(),PipeAccessRights.ReadWrite|PipeAccessRights.Synchronize,AccessControlType.Allow));
    using(var pipe=new NamedPipeServerStream(PipeName,PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous,4096,65536,acl)){
     lock(gate){if(stopping.WaitOne(0))return;active=pipe;}
     try{pipe.WaitForConnection();var request=ReadExact(pipe,17,3000);char drive=(char)request[0];long journal=BitConverter.ToInt64(request,1),cursor=BitConverter.ToInt64(request,9);
      Batch batch;try{batch=Read(drive,journal,cursor);}catch(Exception ex){batch=new Batch{Error="native journal read: "+ex.GetType().Name+": "+ex.Message};}
      var response=Encode(batch);WriteBounded(pipe,response,5000);
     }finally{lock(gate){active=null;}}
    }
   }catch(Exception){if(stopping.WaitOne(500))return;}
  }
  internal sealed class ScanBatch {
   public string Kind {get;set;} public string Detail {get;set;} public string Hash {get;set;}
   public double Entropy {get;set;} public long Size {get;set;} public int Sample {get;set;} public string Verdict {get;set;}
   public bool Cached {get;set;} public string Generation {get;set;} public bool MetadataCached {get;set;} public string Stamp {get;set;}
   public string[] Children {get;set;}
   public DownloadEntry[] Downloads {get;set;}
   public bool WatchStarted {get;set;} public bool WatchGap {get;set;} public string[] WatchArrivals {get;set;}
  }
  public sealed class DownloadEntry {
   public string Path {get;set;} public long Size {get;set;} public long Written {get;set;} public long Created {get;set;}
  }
  // Scoped metadata-only enumeration. No file contents or unapproved directory listings are returned.
  ScanBatch ReadDownloads(string path){
   var c=Config.Load().Endpoint;
   if(!LocalScanPath(path,c)||!string.Equals(Path.GetFileName(path.TrimEnd('\\')),"Downloads",StringComparison.OrdinalIgnoreCase))throw new UnauthorizedAccessException("Downloads directory outside saved scan scope");
   EndpointProtection.SafePath(path);
   using(var h=CreateFile(path,0x80,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero)){
    if(h.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error());VerifyScanPath(h,path);
    var entries=new List<DownloadEntry>();bool partial=false;
    int count=0;
    foreach(var f in new DirectoryInfo(path).EnumerateFiles()){
     if(++count>MaxDirectoryEntries){partial=true;break;}
     try{if((f.Attributes&FileAttributes.ReparsePoint)!=0||f.FullName.Length>1024||EndpointProtection.Excluded(c,f.FullName))continue;
      entries.Add(new DownloadEntry{Path=f.FullName,Size=f.Length,Written=f.LastWriteTimeUtc.Ticks,Created=f.CreationTimeUtc.Ticks});
     }catch(FileNotFoundException){}catch(DirectoryNotFoundException){}catch(IOException){partial=true;}catch(UnauthorizedAccessException){partial=true;}
    }
    return new ScanBatch{Kind="Downloads",Downloads=entries.ToArray(),Detail=partial?"Downloads listing incomplete; journal and scheduled scanning remain active":null};
   }
  }
  // Exact saved directory roots only. A lease bounds collection if the client stops.
  // Events are metadata, not content; ordinary scanning enforces saved exclusions and handle checks.
  void PrunePrivilegedWatches(){try{lock(watchLock){long now=History.Now();foreach(var root in privilegedWatches.Where(x=>x.Value.Lease<now).Select(x=>x.Key).ToArray()){var w=privilegedWatches[root];privilegedWatches.Remove(root);w.Watcher.Dispose();}}}catch(Exception){}}
  void WatchEvent(string root,PrivilegedWatch watch,string path,bool priority){lock(watchLock){PrivilegedWatch current;if(!privilegedWatches.TryGetValue(root,out current)||!ReferenceEquals(current,watch)||watch.Faulted)return;
   if(string.IsNullOrEmpty(path)||path.Length>1024||!EndpointProtection.Under(path,root)){watch.Gap=true;return;}
   bool previous;if(watch.Events.TryGetValue(path,out previous)){watch.Events[path]=previous||priority;return;}
   if(watch.Events.Count>=MaxPrivilegedWatchQueue){watch.Gap=true;return;}watch.Events.Add(path,priority);
  }}
  ScanBatch ReadWatcher(string path){
   var c=Config.Load().Endpoint;
   if(!c.RealTime||!LocalScanPath(path,c)||!c.Paths.Any(x=>string.Equals(x.TrimEnd('\\'),path.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase)))throw new UnauthorizedAccessException("Watcher root outside saved real-time scope");
   EndpointProtection.SafePath(path);if((File.GetAttributes(path)&FileAttributes.Directory)==0)throw new IOException("Privileged watcher requires a directory root");
   using(var handle=CreateFile(path,0x80,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero)){if(handle.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error());VerifyScanPath(handle,path);}
   lock(watchLock){if(stopping.WaitOne(0))throw new OperationCanceledException();
    // Remove roots that are no longer authorized before delivering any events.
    foreach(var key in privilegedWatches.Keys.Where(x=>!c.Paths.Any(p=>string.Equals(p.TrimEnd('\\'),x.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase))||EndpointProtection.Excluded(c,x)).ToArray()){var old=privilegedWatches[key];privilegedWatches.Remove(key);old.Watcher.Dispose();}
    PrivilegedWatch w;bool started=false,gap=false;
    if(privilegedWatches.TryGetValue(path,out w)&&w.Faulted){gap=true;privilegedWatches.Remove(path);w.Watcher.Dispose();w=null;}
    if(w==null){if(privilegedWatches.Count>=MaxPrivilegedWatchRoots)throw new IOException("Privileged watcher root limit reached");
     w=new PrivilegedWatch();var instance=w;var fs=new FileSystemWatcher(path);w.Watcher=fs;
     try{fs.IncludeSubdirectories=true;fs.InternalBufferSize=32768;fs.NotifyFilter=NotifyFilters.FileName|NotifyFilters.DirectoryName|NotifyFilters.LastWrite|NotifyFilters.Size;
      fs.Created+=(a,e)=>WatchEvent(path,instance,e.FullPath,true);fs.Changed+=(a,e)=>WatchEvent(path,instance,e.FullPath,false);fs.Deleted+=(a,e)=>WatchEvent(path,instance,e.FullPath,false);fs.Renamed+=(a,e)=>{WatchEvent(path,instance,e.OldFullPath,false);WatchEvent(path,instance,e.FullPath,true);};
      fs.Error+=(a,e)=>{lock(watchLock){instance.Faulted=true;instance.Gap=true;}};
      privilegedWatches.Add(path,w);w.Lease=History.Now()+120;fs.EnableRaisingEvents=true;started=true;
     }catch{privilegedWatches.Remove(path);fs.Dispose();throw;}
    }
    w.Lease=History.Now()+120;var batch=w.Events.Take(MaxPrivilegedWatchBatch).ToArray();foreach(var item in batch)w.Events.Remove(item.Key);
    gap|=w.Gap;w.Gap=false;
    var visible=batch.Where(x=>EndpointProtection.Under(x.Key,path)&&!EndpointProtection.Excluded(c,x.Key)).ToArray();
    return new ScanBatch{Kind="Watcher",Children=visible.Select(x=>x.Key).ToArray(),WatchArrivals=visible.Where(x=>x.Value).Select(x=>x.Key).ToArray(),WatchStarted=started,WatchGap=gap};
   }
  }
  static bool LocalScanPath(string path,EndpointSettings policy){
   if(string.IsNullOrEmpty(path)||path.Length>1024||path.Length<3||path[1]!=':'||path[2]!='\\'||path.Substring(2).Contains(":")||path.Any(char.IsControl))return false;
   if(!string.Equals(path,Path.GetFullPath(path),StringComparison.OrdinalIgnoreCase))return false;
   var drive=new DriveInfo(Path.GetPathRoot(path));
   return drive.DriveType==DriveType.Fixed&&drive.IsReady&&policy.Enabled&&policy.Paths.Any(p=>EndpointProtection.Under(path,p))&&!EndpointProtection.Excluded(policy,path);
  }
  internal static void VerifyScanPath(SafeFileHandle h,string path){
   var buffer=new StringBuilder(4096);uint n=GetFinalPathNameByHandle(h,buffer,(uint)buffer.Capacity,0);
   if(n==0||n>=buffer.Capacity||!string.Equals(buffer.ToString().TrimEnd('\\'),(@"\\?\"+path).TrimEnd('\\'),StringComparison.OrdinalIgnoreCase))throw new IOException("Scan handle final path mismatch");
  }
  [StructLayout(LayoutKind.Sequential)] struct StampFileInfo {
   internal uint Attributes,CreationLow,CreationHigh,AccessLow,AccessHigh,WriteLow,WriteHigh,Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;
  }
  [StructLayout(LayoutKind.Sequential)] struct StampBasicInfo {internal long Creation,Access,Write,Change;internal uint Attributes;}
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out StampFileInfo info);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle h,int kind,out StampBasicInfo info,uint size);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool GetVolumeNameForVolumeMountPoint(string root,StringBuilder name,uint size);
  static bool StampJournal(SafeFileHandle volume,out long id,out long first,out long tail){
   id=first=tail=0;var data=new byte[128];int n;
   if(!DeviceIoControl(volume,QueryJournal,null,0,data,data.Length,out n,IntPtr.Zero)||n<56)return false;
   id=BitConverter.ToInt64(data,0);first=Math.Max(BitConverter.ToInt64(data,8),BitConverter.ToInt64(data,24));tail=BitConverter.ToInt64(data,16);
   return id!=0&&first>=0&&tail>=first;
  }
  // A transient comparison token for shared-read snapshots, never a cache key.
  // Access time is deliberately omitted because inspection can change it.
  internal static string SharedReadStamp(SafeFileHandle h,string path){
   EndpointResponse.VerifyHandle(h,path);StampFileInfo info;StampBasicInfo basic;
   if(!GetFileInformationByHandle(h,out info)||info.Links!=1||(info.Attributes&0x00441410)!=0||!GetFileInformationByHandleEx(h,0,out basic,(uint)Marshal.SizeOf(typeof(StampBasicInfo))))throw new IOException("Shared-read identity or change metadata unavailable.");
   if(info.IndexHigh==0&&info.IndexLow==0)throw new IOException("Shared-read file identity unavailable.");
   return string.Join("|",new[]{info.Volume.ToString(),info.IndexHigh.ToString(),info.IndexLow.ToString(),info.SizeHigh.ToString(),info.SizeLow.ToString(),basic.Creation.ToString(),basic.Write.ToString(),basic.Change.ToString(),basic.Attributes.ToString()});
  }
  // Never use timestamps alone. Bind the same verified read handle to a local
  // NTFS volume GUID, file reference, current journal ID and per-file USN.
  // A journal reset, inaccessible metadata, unsupported version, aged-out
  // record, hard link or offline/reparse file disables this fast path.
  static SafeFileHandle OpenStampVolume(string root){
   string path=@"\\.\"+root.Substring(0,2);var handle=CreateFile(path,0,7,IntPtr.Zero,3,0,IntPtr.Zero);
   long id,first,tail;if(!handle.IsInvalid&&StampJournal(handle,out id,out first,out tail))return handle;
   handle.Dispose();return CreateFile(path,0x80000000,7,IntPtr.Zero,3,0,IntPtr.Zero);
  }
  internal static string FileChangeStamp(SafeFileHandle file,string path){
   try{
    string root=Path.GetPathRoot(path);if(root==null||root.Length!=3||root[1]!=':')return null;
    var drive=new DriveInfo(root);if(drive.DriveType!=DriveType.Fixed||!drive.IsReady||!string.Equals(drive.DriveFormat,"NTFS",StringComparison.OrdinalIgnoreCase))return null;
    var guid=new StringBuilder(128);if(!GetVolumeNameForVolumeMountPoint(root,guid,(uint)guid.Capacity))return null;
    var final=new StringBuilder(4096);uint finalLength=GetFinalPathNameByHandle(file,final,(uint)final.Capacity,1);if(finalLength==0||finalLength>=final.Capacity||!final.ToString().StartsWith(guid.ToString(),StringComparison.OrdinalIgnoreCase))return null;
    StampFileInfo info;StampBasicInfo basic;
    if(!GetFileInformationByHandle(file,out info)||info.Links!=1||(info.Attributes&0x00441410)!=0||!GetFileInformationByHandleEx(file,0,out basic,(uint)Marshal.SizeOf(typeof(StampBasicInfo))))return null;
    using(var volume=OpenStampVolume(root)){
     long id,first,tail;if(volume.IsInvalid||!StampJournal(volume,out id,out first,out tail))return null;
     // FSCTL_READ_FILE_USN_DATA, explicitly request the NTFS V2 layout.
     var input=new byte[]{2,0,2,0};var record=new byte[1024];int n;
     if(!DeviceIoControl(file,0x000900eb,input,input.Length,record,record.Length,out n,IntPtr.Zero)||n<60||BitConverter.ToUInt16(record,4)!=2||BitConverter.ToUInt16(record,6)!=0||BitConverter.ToUInt32(record,0)>n||BitConverter.ToUInt32(record,0)<60)return null;
     ulong reference=((ulong)info.IndexHigh<<32)|info.IndexLow;long usn=BitConverter.ToInt64(record,24);
     if(reference==0||BitConverter.ToUInt64(record,8)!=reference||usn<first||usn>=tail)return null;
     long afterId,afterFirst,afterTail;if(!StampJournal(volume,out afterId,out afterFirst,out afterTail)||afterId!=id||usn<afterFirst||usn>=afterTail)return null;
     return EndpointProtection.Hash(Encoding.UTF8.GetBytes(string.Join("|",new[]{"ntfs-v1",guid.ToString(),info.Volume.ToString(),reference.ToString(),id.ToString(),usn.ToString(),info.SizeHigh.ToString(),info.SizeLow.ToString(),basic.Creation.ToString(),basic.Write.ToString(),basic.Change.ToString(),basic.Attributes.ToString()})));
    }
   }catch(Exception){return null;}
  }
  ScanBatch ReadScan(string path,bool enumerate,bool cacheBaseline=false,string expectedHash=null,string expectedGeneration=null,string expectedStamp=null){
   // Authorize independently of caller inputs, against the saved protection scope.
   var c=Config.Load().Endpoint;if(!LocalScanPath(path,c))throw new UnauthorizedAccessException("Path outside saved local scan scope");
   try{EndpointProtection.SafePath(path);}catch(EndpointProtection.ScanReparseException ex){return new ScanBatch{Kind="Reparse",Detail=ex.Message};}var attr=File.GetAttributes(path);
   if((attr&FileAttributes.Directory)!=0){
    if(!enumerate)return new ScanBatch{Kind="Directory",Children=new string[0]};
    // Hold the directory open without delete sharing; refuse reparse paths and verify the handle.
    using(var h=CreateFile(path,0x80,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero)){
     if(h.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error());VerifyScanPath(h,path);
     var entries=Directory.EnumerateFileSystemEntries(path).Take(MaxDirectoryEntries+1).ToArray();
     return new ScanBatch{Kind="Directory",Children=entries.Take(MaxDirectoryEntries).ToArray(),Detail=entries.Length>MaxDirectoryEntries?"Privileged directory enumeration limit exceeded; coverage incomplete":null};
    }
   }
   // Only the standard, locally installed ClamD listener may receive privileged file bytes.
   if(c.Port!=3310)throw new IOException("Privileged scan requires standard ClamD port 3310");
   using(var handle=CreateFile(path,0x80000000,1,IntPtr.Zero,3,0x00200000,IntPtr.Zero)){
    if(handle.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error());VerifyScanPath(handle,path);EndpointResponse.VerifyHandle(handle,path);
    using(var file=new FileStream(handle,FileAccess.Read)){
     if(file.Length>c.MaxFileMiB*1048576L)return new ScanBatch{Kind="Limited",Size=file.Length};
     bool cacheAllowed=cacheBaseline&&!c.CanaryPaths.Contains(path,StringComparer.OrdinalIgnoreCase)&&!EndpointProtection.BackgroundExcluded(c,path);
     string stamp=cacheAllowed&&c.MetadataFastCache?FileChangeStamp(handle,path):null;
     string generation=cacheAllowed?ClamUpdateWorker.CacheGeneration(stopping,true):null;
     if(cacheAllowed&&c.MetadataFastCache&&stamp!=null&&stamp==expectedStamp&&generation!=null&&generation==expectedGeneration&&!string.IsNullOrEmpty(expectedHash)&&stamp==FileChangeStamp(handle,path))return new ScanBatch{Kind="File",Hash=expectedHash,Verdict="Cached clean",Cached=true,Generation=generation,MetadataCached=true,Stamp=stamp};
     var budget=enumerate&&!c.CanaryPaths.Contains(path,StringComparer.OrdinalIgnoreCase)?new EndpointReadBudget(c.BackgroundReadMiB,stopping):null;
     byte[] b=new byte[65536];int n=0,read;while(n<b.Length&&(read=budget==null?file.Read(b,n,b.Length-n):budget.Read(file,b,n,b.Length-n))>0)n+=read;
     double entropy=EndpointProtection.Entropy(b,n);file.Position=0;string hash=EndpointProtection.FileHash(file,budget);file.Position=0;
     if(cacheAllowed)generation=ClamUpdateWorker.CacheGeneration(stopping,true);
     if(generation!=null&&generation==expectedGeneration&&hash==expectedHash)return new ScanBatch{Kind="File",Hash=hash,Entropy=entropy,Sample=n,Verdict="Cached clean",Cached=true,Generation=generation};
     string reply;try{reply=EndpointProtection.Command(3310,"INSTREAM",file,stopping,tcp=>ClamUpdateWorker.VerifyPrivilegedScanPeer(tcp),budget);}catch(OperationCanceledException){throw;}catch(Exception ex){reply="Privileged ClamAV scan error: "+ex.GetType().Name+": "+ex.Message+" [ERROR]";}
     if(generation!=null&&(!EndpointProtection.CleanVerdict(reply)||generation!=ClamUpdateWorker.CacheGeneration(stopping,true)))generation=null;
     return new ScanBatch{Kind="File",Hash=hash,Entropy=entropy,Sample=n,Verdict=reply,Generation=generation,Stamp=generation!=null&&stamp!=null&&stamp==FileChangeStamp(handle,path)?stamp:null};
    }
   }
  }
  void ScanRun(bool watchOnly){
   while(!stopping.WaitOne(0))try{
    var acl=new PipeSecurity();acl.SetAccessRuleProtection(true,false);
    acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid,null),PipeAccessRights.FullControl,AccessControlType.Deny));
    acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),PipeAccessRights.FullControl,AccessControlType.Allow));
    acl.AddAccessRule(new PipeAccessRule(Program.ServiceSid(),PipeAccessRights.ReadWrite|PipeAccessRights.Synchronize,AccessControlType.Allow));
    using(var pipe=new NamedPipeServerStream(watchOnly?WatchPipeName:ScanPipeName,PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous,4096,65536,acl)){
     lock(gate){if(stopping.WaitOne(0))return;if(watchOnly)watchActive=pipe;else scanActive=pipe;}
     try{pipe.WaitForConnection();int length=BitConverter.ToInt32(ReadExact(pipe,4,3000),0);if(length<2||length>4097)throw new IOException("Invalid scan request length");
      byte[] request=ReadExact(pipe,length,3000);ScanBatch result;
      try{if(watchOnly?request[0]!=3:(request[0]>4||request[0]==3))throw new IOException("Invalid scan request");string path=new UTF8Encoding(false,true).GetString(request,1,length-1);
       if(request[0]==4){var args=path.Split('\n');if((args.Length!=3&&args.Length!=4)||!CacheToken(args[1])||!CacheToken(args[2])||(args.Length==4&&!CacheToken(args[3])))throw new IOException("Invalid baseline cache request");using(var priority=new EndpointBackgroundPriority(true))result=ReadScan(args[0],true,true,args[1],args[2],args.Length==4?args[3]:null);}
       else if(request[0]==1){using(var priority=new EndpointBackgroundPriority(true))result=ReadScan(path,true);}
       else result=request[0]==2?ReadDownloads(path):request[0]==3?ReadWatcher(path):ReadScan(path,false);}
      catch(FileNotFoundException ex){result=new ScanBatch{Kind="Missing",Detail=ex.Message};}catch(DirectoryNotFoundException ex){result=new ScanBatch{Kind="Missing",Detail=ex.Message};}
      catch(Win32Exception ex){result=new ScanBatch{Kind=ex.NativeErrorCode==2||ex.NativeErrorCode==3?"Missing":ex.NativeErrorCode==32||ex.NativeErrorCode==33?"Locked":"Error",Detail=ex.Message};}
      catch(Exception ex){result=new ScanBatch{Kind=EndpointProtection.LockedFile(ex)?"Locked":"Error",Detail=ex.GetType().Name+": "+ex.Message};}
      byte[] response=Encoding.UTF8.GetBytes(Config.Json().Serialize(result));if(response.Length>MaxScanReply)response=Encoding.UTF8.GetBytes(Config.Json().Serialize(new ScanBatch{Kind="Error",Detail="Privileged scan reply exceeds limit"}));
      WriteBounded(pipe,BitConverter.GetBytes(response.Length),5000);WriteBounded(pipe,response,5000);
     }finally{lock(gate){if(watchOnly)watchActive=null;else scanActive=null;}}
    }
   }catch(Exception){if(stopping.WaitOne(500))return;}
  }
  static bool CacheToken(string value){return value!=null&&(value.Length==0||(value.Length==64&&value.All(Uri.IsHexDigit)));}
  internal static ScanBatch FetchBaselineScan(string path,string hash,string generation,string stamp){return FetchScanMode(path,4,hash,generation,stamp);}
  internal static ScanBatch FetchScan(string path,bool enumerate){return FetchScanMode(path,(byte)(enumerate?1:0));}
  internal static ScanBatch FetchDownloads(string path){return FetchScanMode(path,2);}
  internal static ScanBatch FetchWatcher(string path){return FetchScanMode(path,3);}
  static ScanBatch FetchScanMode(string path,byte mode,string hash=null,string generation=null,string stamp=null){
   string stage="connect";try{using(var pipe=new NamedPipeClientStream(".",mode==3?WatchPipeName:ScanPipeName,PipeAccessRights.ReadWrite|PipeAccessRights.Synchronize,PipeOptions.Asynchronous,TokenImpersonationLevel.Identification,HandleInheritability.None)){
    pipe.Connect(1500);stage="verify LinkScopeUsn service identity";if(!IsReader(pipe.SafePipeHandle))throw new IOException("Privileged scan service identity could not be verified");
    byte[] request=new[]{mode}.Concat(Encoding.UTF8.GetBytes(mode==4?path+"\n"+hash+"\n"+generation+"\n"+stamp:path)).ToArray();if(request.Length>4097)throw new IOException("Scan path exceeds protocol limit");
    stage="send request";WriteBounded(pipe,BitConverter.GetBytes(request.Length),3000);WriteBounded(pipe,request,3000);
    stage="read reply header";int length=BitConverter.ToInt32(ReadExact(pipe,4,mode==3?5000:mode==4||mode==1?90000:45000),0);if(length<2||length>MaxScanReply)throw new IOException("Invalid privileged scan reply size");
    stage="read and validate reply";var result=Config.Json().Deserialize<ScanBatch>(new UTF8Encoding(false,true).GetString(ReadExact(pipe,length,10000)));
    if(result==null||!new[]{"Directory","File","Missing","Limited","Error","Locked","Downloads","Watcher","Reparse"}.Contains(result.Kind))throw new IOException("Invalid privileged scan reply");
    if(result.Kind=="Downloads"&&(mode!=2||result.Downloads==null||result.Downloads.Length>MaxDirectoryEntries||result.Downloads.Any(f=>f==null||string.IsNullOrEmpty(f.Path)||f.Path.Length>1024||f.Size<0||f.Written<0||f.Created<0||!string.Equals(Path.GetDirectoryName(f.Path),path.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase)||!string.Equals(Path.GetFullPath(f.Path),f.Path,StringComparison.OrdinalIgnoreCase)||f.Path.Substring(2).Contains(":"))))throw new IOException("Invalid Downloads metadata reply");
    if(mode==2&&result.Kind!="Downloads"&&result.Kind!="Missing"&&result.Kind!="Error")throw new IOException("Unexpected Downloads reply");
    if(mode==3&&result.Kind!="Watcher"&&result.Kind!="Missing"&&result.Kind!="Error")throw new IOException("Unexpected watcher reply");
    if(result.Kind=="Watcher"&&(mode!=3||result.Children==null||result.WatchArrivals==null||result.Children.Length>MaxPrivilegedWatchBatch||result.WatchArrivals.Length>result.Children.Length||result.Children.Any(x=>string.IsNullOrEmpty(x)||x.Length>1024||x.Length<3||x.Any(char.IsControl)||x.Substring(2).Contains(":")||!string.Equals(Path.GetFullPath(x),x,StringComparison.OrdinalIgnoreCase)||!EndpointProtection.Under(x,path))||result.WatchArrivals.Any(x=>!result.Children.Contains(x,StringComparer.OrdinalIgnoreCase))))throw new IOException("Invalid privileged watcher metadata");
    if(result.Kind=="Directory"&&(result.Children==null||result.Children.Length>MaxDirectoryEntries||result.Children.Any(child=>string.IsNullOrEmpty(child)||!string.Equals(Path.GetDirectoryName(child),path.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase)&&!string.Equals(Path.GetDirectoryName(child),path,StringComparison.OrdinalIgnoreCase)||child.Length>1024)))throw new IOException("Invalid directory reply");
    if(result.Kind=="Limited"&&result.Size<0)throw new IOException("Invalid limited file size");
    if(result.Kind=="Reparse"&&(mode>1&&mode!=4||string.IsNullOrEmpty(result.Detail)||result.Detail.Length>2048))throw new IOException("Invalid reparse boundary reply");
    if(result.Kind=="File"&&(result.Hash==null||result.Hash.Length!=64||!result.Hash.All(Uri.IsHexDigit)||result.Sample<0||result.Sample>65536||double.IsNaN(result.Entropy)||result.Entropy<0||result.Entropy>8||result.Verdict==null||result.Verdict.Length>4096))throw new IOException("Invalid file verdict");
    if(result.Cached&&(mode!=4||result.Kind!="File"||result.Verdict!="Cached clean"||result.Hash!=hash||result.Generation!=generation||string.IsNullOrEmpty(generation)))throw new IOException("Invalid cached baseline reply");
    if(!string.IsNullOrEmpty(result.Generation)&&(mode!=4||!CacheToken(result.Generation)||result.Kind!="File"||(!result.Cached&&!EndpointProtection.CleanVerdict(result.Verdict))))throw new IOException("Invalid cache generation reply");
    if(result.MetadataCached&&(!result.Cached||mode!=4||string.IsNullOrEmpty(stamp)||result.Stamp!=stamp))throw new IOException("Invalid NTFS cached reply");
    if(!string.IsNullOrEmpty(result.Stamp)&&(mode!=4||!CacheToken(result.Stamp)||string.IsNullOrEmpty(result.Generation)||result.Kind!="File"||(!result.MetadataCached&&!EndpointProtection.CleanVerdict(result.Verdict))))throw new IOException("Invalid NTFS stamp reply");
    return result;
   }}catch(Exception ex){if(mode==3)throw new IOException("Privileged watcher "+stage+": "+ex.GetType().Name+": "+ex.Message,ex);throw;}
  }
  // PipeStream owns its asynchronous I/O handles. Never dispose an APM wait
  // handle before EndRead/EndWrite: the framework may still need that handle.
  // Task-based I/O also observes faults after a timed-out connection is closed.
  static void AwaitPipe(Stream stream,Task operation,int timeout,string action){
   if(timeout<=0||Task.WhenAny(operation,Task.Delay(timeout)).GetAwaiter().GetResult()!=operation){
    operation.ContinueWith(t=>{var ignored=t.Exception;},CancellationToken.None,TaskContinuationOptions.OnlyOnFaulted|TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);
    stream.Dispose();throw new System.TimeoutException("Journal pipe "+action+" timed out");
   }
   operation.GetAwaiter().GetResult();
  }
  static byte[] ReadExact(Stream stream,int length,int timeout){
   var b=new byte[length];int offset=0;var timer=System.Diagnostics.Stopwatch.StartNew();
   while(offset<length){int left=timeout-(int)timer.ElapsedMilliseconds;if(left<=0){stream.Dispose();throw new System.TimeoutException("Journal pipe read timed out");}
    var operation=stream.ReadAsync(b,offset,length-offset);AwaitPipe(stream,operation,left,"read");int n=operation.GetAwaiter().GetResult();if(n==0)throw new EndOfStreamException();offset+=n;
   }return b;
  }
  static void WriteBounded(Stream stream,byte[] b,int timeout){AwaitPipe(stream,stream.WriteAsync(b,0,b.Length),timeout,"write");}
  static byte[] Encode(Batch b){using(var m=new MemoryStream())using(var w=new BinaryWriter(m,Encoding.UTF8)){w.Write(b.Error??"");w.Write(b.Journal);w.Write(b.Next);w.Write(b.Tail);w.Write(b.Gap);w.Write(b.Unresolved);w.Write(b.Paths.Count);foreach(var p in b.Paths){w.Write(p);w.Write(b.Arrivals.Contains(p));}w.Flush();var payload=m.ToArray();if(payload.Length>MaxReply)throw new IOException("Journal reply too large");return BitConverter.GetBytes(payload.Length).Concat(payload).ToArray();}}
  internal static Batch Fetch(string root,long journal,long cursor){
   string stage="connect";try{using(var pipe=new NamedPipeClientStream(".",PipeName,PipeAccessRights.ReadWrite|PipeAccessRights.Synchronize,PipeOptions.Asynchronous,TokenImpersonationLevel.Identification,HandleInheritability.None)){
    pipe.Connect(1500);stage="verify reader identity";if(!IsReader(pipe.SafePipeHandle))throw new IOException("Journal reader service identity could not be verified");
    stage="write request";var req=new byte[17];req[0]=(byte)root[0];Buffer.BlockCopy(BitConverter.GetBytes(journal),0,req,1,8);Buffer.BlockCopy(BitConverter.GetBytes(cursor),0,req,9,8);WriteBounded(pipe,req,3000);
    stage="read reply header";int size=BitConverter.ToInt32(ReadExact(pipe,4,15000),0);if(size<1||size>MaxReply)throw new IOException("Invalid journal reply size");
    stage="read reply payload";using(var m=new MemoryStream(ReadExact(pipe,size,5000)))using(var r=new BinaryReader(m,Encoding.UTF8)){
     var b=new Batch{Error=r.ReadString(),Journal=r.ReadInt64(),Next=r.ReadInt64(),Tail=r.ReadInt64(),Gap=r.ReadBoolean(),Unresolved=r.ReadInt32()};int count=r.ReadInt32();if(count<0||count>MaxRecords||b.Unresolved<0||b.Unresolved>MaxRecords||b.Next<0||b.Tail<0||b.Next>b.Tail)throw new IOException("Invalid journal response");for(int i=0;i<count;i++){string p=r.ReadString();if(p.Length<3||p.Length>1024||!p.StartsWith(root,StringComparison.OrdinalIgnoreCase)||!EndpointProtection.Under(p,root)||p.Any(char.IsControl)||p.Substring(2).Contains(":"))throw new IOException("Invalid journal path");b.Paths.Add(p);if(r.ReadBoolean())b.Arrivals.Add(p);}if(m.Position!=m.Length)throw new IOException("Unexpected journal response data");return b;
    }
   }}catch(Exception ex){return new Batch{Error=stage+": "+ex.GetType().Name+": "+ex.Message};}
  }
  static Batch Read(char drive,long journal,long cursor){
   if(drive<'A'||drive>'Z'||cursor<0)throw new IOException("Invalid drive or checkpoint");string root=drive+@":\";
   var info=new DriveInfo(root);if(info.DriveType!=DriveType.Fixed||!info.IsReady||!string.Equals(info.DriveFormat,"NTFS",StringComparison.OrdinalIgnoreCase))throw new IOException("USN requires a ready fixed NTFS volume");
   using(var h=CreateFile(@"\\.\"+drive+":",0x80000000,7,IntPtr.Zero,3,0,IntPtr.Zero)){
    if(h.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error());var data=new byte[128];int n;
    if(!DeviceIoControl(h,QueryJournal,null,0,data,data.Length,out n,IntPtr.Zero))throw new Win32Exception(Marshal.GetLastWin32Error());if(n<56)throw new IOException("Truncated journal metadata");
    long id=BitConverter.ToInt64(data,0),first=Math.Max(BitConverter.ToInt64(data,8),BitConverter.ToInt64(data,24)),tail=BitConverter.ToInt64(data,16);
    if(first<0||tail<first)throw new IOException("Invalid journal bounds");var b=new Batch{Journal=id,Next=tail,Tail=tail};
    // Initial activation starts at tail; a full scan covers existing data. Never create or resize a journal.
    if(cursor==0&&journal==0)return b;
    if(journal!=id||cursor<first||cursor>tail){b.Gap=true;return b;}
    if(cursor==tail)return b;
    // READ_USN_JOURNAL_DATA_V0: 40 bytes, timeout and bytes-to-wait both zero.
    var request=new byte[40];Buffer.BlockCopy(BitConverter.GetBytes(cursor),0,request,0,8);Buffer.BlockCopy(BitConverter.GetBytes(Reasons),0,request,8,4);Buffer.BlockCopy(BitConverter.GetBytes(id),0,request,32,8);
    var records=new byte[64*1024];if(!DeviceIoControl(h,ReadJournal,request,request.Length,records,records.Length,out n,IntPtr.Zero))throw new Win32Exception(Marshal.GetLastWin32Error());
    var parents=new Dictionary<long,string>();Parse(records,n,cursor,b,delegate(long parent,string name){string folder;if(!parents.TryGetValue(parent,out folder)){folder=ResolveParent(h,root,parent);parents[parent]=folder;}if(folder==null||name=="."||name==".."||name.IndexOfAny(new[]{'\\','/',':','\0'})>=0||name.Any(char.IsControl))return null;string path=Path.Combine(folder,name);return path.Length<=1024?path:null;});return b;
   }
  }
  // V2 NTFS record offsets are defined by USN_RECORD_V2. Unsupported layouts stop replay;
  // do not silently advance the checkpoint. Each partial page resumes at the next record USN.
  internal static void Parse(byte[] records,int length,long cursor,Batch b,Func<long,string,string> resolve){
   if(length<8||length>records.Length)throw new IOException("Truncated journal page");long next=BitConverter.ToInt64(records,0);if(next<cursor)throw new IOException("Journal cursor moved backwards");
   b.Tail=Math.Max(b.Tail,next);int pos=8,count=0;long previous=-1;
   while(pos<length){if(length-pos<60)throw new IOException("Truncated USN record");int size=BitConverter.ToInt32(records,pos);if(size<60||size>length-pos||size%8!=0||BitConverter.ToUInt16(records,pos+4)!=2)throw new IOException("Unsupported or invalid USN record");long usn=BitConverter.ToInt64(records,pos+24);if(usn<cursor||usn<=previous||usn>=next)throw new IOException("Invalid USN record sequence");if(count==MaxRecords){b.Next=usn;return;}previous=usn;int nameLen=BitConverter.ToUInt16(records,pos+56),nameOffset=BitConverter.ToUInt16(records,pos+58);if(nameLen==0||nameLen%2!=0||nameOffset<60||nameOffset>size||nameLen>size-nameOffset)throw new IOException("Invalid USN filename");string name=Encoding.Unicode.GetString(records,pos+nameOffset,nameLen);uint reason=BitConverter.ToUInt32(records,pos+40);
    if((reason&Reasons)!=0){string p=resolve(BitConverter.ToInt64(records,pos+16),name);if(p==null)b.Unresolved++;else {b.Paths.Add(p);if((reason&0x2100u)!=0)b.Arrivals.Add(p);}}
    count++;pos+=size;
   }b.Next=next;
  }
  // Platform-independent synthetic page tests, executable through --usn-self-test on Windows.
  internal static void SelfTest(){
   var data=new byte[8+129*72];Buffer.BlockCopy(BitConverter.GetBytes(200L),0,data,0,8);
   for(int i=0;i<129;i++){int p=8+i*72;Buffer.BlockCopy(BitConverter.GetBytes(72),0,data,p,4);Buffer.BlockCopy(BitConverter.GetBytes((ushort)2),0,data,p+4,2);Buffer.BlockCopy(BitConverter.GetBytes(42L),0,data,p+16,8);Buffer.BlockCopy(BitConverter.GetBytes((long)i+1),0,data,p+24,8);Buffer.BlockCopy(BitConverter.GetBytes(1u),0,data,p+40,4);Buffer.BlockCopy(BitConverter.GetBytes((ushort)2),0,data,p+56,2);Buffer.BlockCopy(BitConverter.GetBytes((ushort)60),0,data,p+58,2);data[p+60]=(byte)'x';}
   var batch=new Batch{Tail=200};Parse(data,data.Length,1,batch,(id,name)=>id==42&&name=="x"?@"C:\x":null);
   if(batch.Paths.Count!=128||batch.Next!=129||batch.Unresolved!=0)throw new IOException("USN partial page fixture failed");
   var last=new byte[80];Buffer.BlockCopy(data,0,last,0,8);Buffer.BlockCopy(data,8+128*72,last,8,72);batch=new Batch{Tail=200};Parse(last,last.Length,129,batch,(id,name)=>null);
   if(batch.Next!=200||batch.Unresolved!=1)throw new IOException("USN unresolved fixture failed");
   last[12]=3;bool rejected=false;try{Parse(last,last.Length,129,new Batch(),(id,name)=>null);}catch(IOException){rejected=true;}if(!rejected)throw new IOException("USN unsupported record accepted");
   Console.WriteLine("USN synthetic parser tests passed.");
   PipeSelfTest();
   Console.WriteLine("USN asynchronous named pipe tests passed.");
   EndpointProtection.PrioritySelfTest();
   Console.WriteLine("Priority watcher queue tests passed.");
  }
  static void PipeSelfTest(){
   string name="LinkScope.Usn.Test."+Guid.NewGuid().ToString("N");
   using(var server=new NamedPipeServerStream(name,PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous))
   using(var client=new NamedPipeClientStream(".",name,PipeDirection.InOut,PipeOptions.Asynchronous)){
    var accept=Task.Factory.StartNew(()=>server.WaitForConnection(),CancellationToken.None,TaskCreationOptions.None,TaskScheduler.Default);
    client.Connect(3000);AwaitPipe(server,accept,3000,"test accept");
    for(int i=0;i<32;i++){
     byte[] request=BitConverter.GetBytes(i);WriteBounded(client,request,3000);
     if(BitConverter.ToInt32(ReadExact(server,4,3000),0)!=i)throw new IOException("USN pipe request mismatch");
     WriteBounded(server,new byte[]{1,2},3000);WriteBounded(server,new byte[]{3,4},3000);
     if(!ReadExact(client,4,3000).SequenceEqual(new byte[]{1,2,3,4}))throw new IOException("USN pipe response mismatch");
    }
    bool timedOut=false;try{ReadExact(client,1,100);}catch(System.TimeoutException){timedOut=true;}
    if(!timedOut)throw new IOException("USN pipe timeout fixture failed");
   }
  }
  static string ResolveParent(SafeFileHandle volume,string root,long parent){
   var id=new FileId{Size=24,Type=0,Id=parent};using(var h=OpenFileById(volume,ref id,0x80,7,IntPtr.Zero,0x02200000)){
    if(h.IsInvalid)return null;var buffer=new StringBuilder(2048);uint n=GetFinalPathNameByHandle(h,buffer,(uint)buffer.Capacity,0);if(n==0||n>=buffer.Capacity)return null;string path=buffer.ToString();if(!path.StartsWith(@"\\?\"+root,StringComparison.OrdinalIgnoreCase))return null;return path.Substring(4);
   }
  }
 }
 // Runs under the existing LocalService account. Durable queue and checkpoint share one
 // SQLite transaction; interrupted scan work is retried and queue pressure pauses replay.
 internal sealed class UsnJournalMonitor {
  const int Capacity=8192;
  sealed class Volume {internal string Root,Status="Waiting",Detail="";internal long Journal,Next,Tail;internal long Retry;internal bool Loaded;internal Task<UsnJournalService.Batch> Work;}
  readonly List<Volume> volumes=new List<Volume>(); string scope; bool preferRecent=true;
  internal void Configure(EndpointSettings c,string key){volumes.Clear();scope=key;if(!c.Enabled||!c.RealTime)return;foreach(string root in c.Paths.Select(Path.GetPathRoot).Distinct(StringComparer.OrdinalIgnoreCase)){if(root!=null&&root.Length==3&&root[1]==':')volumes.Add(new Volume{Root=root.ToUpperInvariant()});}}
  internal static void Schema(Sqlite db){db.Exec("CREATE TABLE IF NOT EXISTS usn_checkpoint(scope TEXT NOT NULL,volume TEXT NOT NULL,journal INTEGER NOT NULL,cursor INTEGER NOT NULL,PRIMARY KEY(scope,volume))");db.Exec("CREATE TABLE IF NOT EXISTS usn_pending(scope TEXT NOT NULL,path TEXT COLLATE NOCASE NOT NULL,PRIMARY KEY(scope,path))");db.Exec("CREATE TABLE IF NOT EXISTS usn_arrivals(scope TEXT NOT NULL,path TEXT COLLATE NOCASE NOT NULL,PRIMARY KEY(scope,path))");db.Exec("CREATE TABLE IF NOT EXISTS usn_retry(scope TEXT NOT NULL,path TEXT COLLATE NOCASE NOT NULL,ready INTEGER NOT NULL,PRIMARY KEY(scope,path))");db.Exec("CREATE TABLE IF NOT EXISTS usn_retry_attempts(scope TEXT NOT NULL,path TEXT COLLATE NOCASE NOT NULL,attempts INTEGER NOT NULL,PRIMARY KEY(scope,path))");}
  internal void Poll(Sqlite db,EndpointSettings c,Action<string,string> warning,Action<string> clear,Action<string,string> gap,Action reconcile){
   if(!c.RealTime||volumes.Count==0)return;
   long now=History.Now();if(!volumes.Any(v=>v.Loaded)){db.Exec("DELETE FROM usn_pending WHERE scope<>?",scope);db.Exec("DELETE FROM usn_checkpoint WHERE scope<>?",scope);db.Exec("DELETE FROM usn_arrivals WHERE scope<>?",scope);db.Exec("DELETE FROM usn_retry WHERE scope<>?",scope);db.Exec("DELETE FROM usn_retry_attempts WHERE scope<>?",scope);}int queued=Convert.ToInt32(db.Rows("SELECT COUNT(*) FROM usn_pending WHERE scope=?",scope)[0][0]);
   foreach(var v in volumes){
    if(!v.Loaded){var row=db.Rows("SELECT journal,cursor FROM usn_checkpoint WHERE scope=? AND volume=?",scope,v.Root).FirstOrDefault();if(row!=null){v.Journal=Convert.ToInt64(row[0]);v.Next=Convert.ToInt64(row[1]);}v.Loaded=true;}
    if(v.Work!=null&&v.Work.IsCompleted){var b=v.Work.Result;v.Work=null;
     if(!string.IsNullOrEmpty(b.Error)){v.Status="Fallback";v.Detail=b.Error;v.Retry=now+60;warning(v.Root,"USN unavailable: "+b.Error+". FileSystemWatcher and periodic scans remain active.");continue;}
     if(queued+ b.Paths.Count>Capacity){v.Status="Backpressure";v.Detail="Durable scan queue full; checkpoint retained";continue;}
     if(!b.Gap&&v.Journal!=0&&(v.Journal!=b.Journal||b.Next<v.Next)){v.Status="Fallback";v.Detail="Unexpected checkpoint response";v.Retry=now+60;warning(v.Root,v.Detail);continue;}
     var paths=b.Paths.Where(p=>c.Paths.Any(x=>EndpointProtection.Under(p,x))&&!EndpointProtection.Excluded(c,p)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
     // Persist the coverage warning before advancing beyond unavailable historical records.
     if(b.Gap||b.Unresolved>0){string detail=b.Gap?"Journal reset or records aged out; scheduled reconciliation required":b.Unresolved+" journal records have unresolved historical parent paths; protected-scope membership unknown; scheduled reconciliation required";
      // Record the gap before checkpoint advancement. Reconciliation is coalesced by the scanner.
      gap(v.Root,detail);reconcile();
     }
     db.Exec("BEGIN IMMEDIATE");try{foreach(var p in paths){db.Exec("INSERT OR IGNORE INTO usn_pending(scope,path) VALUES(?,?)",scope,p);if(b.Arrivals.Contains(p))db.Exec("INSERT OR IGNORE INTO usn_arrivals(scope,path) VALUES(?,?)",scope,p);}db.Exec("INSERT OR REPLACE INTO usn_checkpoint(scope,volume,journal,cursor) VALUES(?,?,?,?)",scope,v.Root,b.Journal,b.Next);db.Exec("COMMIT");}catch{db.Exec("ROLLBACK");throw;}
     queued+=paths.Length;v.Journal=b.Journal;v.Next=b.Next;v.Tail=b.Tail;v.Status=b.Next<b.Tail?"Replaying":"Live";v.Detail="Journal checkpoint committed";clear(v.Root);
     if(b.Gap||b.Unresolved>0)v.Detail=b.Gap?"Journal reset or records aged out; scheduled reconciliation required":b.Unresolved+" journal records have unresolved historical parent paths; protected-scope membership unknown; scheduled reconciliation required";
    }
   }
   // One outstanding request across all volumes per monitor; round-robin to prevent starvation.
   if(volumes.Any(v=>v.Work!=null))return;
   if(queued>Capacity-128){foreach(var v in volumes.Where(v=>v.Status!="Fallback")){v.Status="Backpressure";v.Detail="Durable scan queue full; checkpoint retained";}return;}
   var next=volumes.FirstOrDefault(v=>v.Retry<=now);if(next==null)return;volumes.Remove(next);volumes.Add(next);
   string root=next.Root;long journal=next.Journal,cursor=next.Next;next.Work=Task.Factory.StartNew(()=>UsnJournalService.Fetch(root,journal,cursor),CancellationToken.None,TaskCreationOptions.None,TaskScheduler.Default);
  }
  internal string[] Pending(Sqlite db,int limit){
   if(limit<=0)return new string[0];long now=History.Now();
   // Alternate the first item so recent arrivals and oldest replay work both progress,
   // even when a slow scan consumes the entire tick budget.
   var fifo=db.Rows("SELECT path FROM usn_pending p WHERE scope=? AND NOT EXISTS (SELECT 1 FROM usn_retry r WHERE r.scope=p.scope AND r.path=p.path AND r.ready>?) ORDER BY rowid LIMIT ?",scope,now,limit).Select(x=>(string)x[0]).ToArray();
   var downloads=db.Rows("SELECT path FROM usn_pending p WHERE scope=? AND NOT EXISTS (SELECT 1 FROM usn_retry r WHERE r.scope=p.scope AND r.path=p.path AND r.ready>?) AND instr(lower(path),?)>0 ORDER BY rowid DESC LIMIT 1",scope,now,@"\downloads\").Select(x=>(string)x[0]);
   var recent=db.Rows("SELECT path FROM usn_pending p WHERE scope=? AND NOT EXISTS (SELECT 1 FROM usn_retry r WHERE r.scope=p.scope AND r.path=p.path AND r.ready>?) ORDER BY rowid DESC LIMIT ?",scope,now,Math.Max(1,limit/2)).Select(x=>(string)x[0]);
   var arrivals=db.Rows("SELECT p.path FROM usn_pending p JOIN usn_arrivals a ON a.scope=p.scope AND a.path=p.path WHERE p.scope=? AND NOT EXISTS (SELECT 1 FROM usn_retry r WHERE r.scope=p.scope AND r.path=p.path AND r.ready>?) ORDER BY a.rowid LIMIT ?",scope,now,limit).Select(x=>(string)x[0]);
   var fast=downloads.Concat(arrivals).Concat(recent);bool fastFirst=preferRecent;preferRecent=!preferRecent;return (fastFirst?fast.Concat(fifo):fifo.Take(1).Concat(fast).Concat(fifo)).Distinct(StringComparer.OrdinalIgnoreCase).Take(limit).ToArray();
  }
  // Persist accepted watcher work before scanning so transient failures and restarts
  // do not depend on the existence of an NTFS journal event for the same path.
  internal bool RetainWatcher(Sqlite db,string path,bool priority){
   if(Depth(db)>=Capacity&&db.Rows("SELECT path FROM usn_pending WHERE scope=? AND path=?",scope,path).Count==0)return false;
   db.Exec("BEGIN IMMEDIATE");try{db.Exec("INSERT OR IGNORE INTO usn_pending(scope,path) VALUES(?,?)",scope,path);if(priority)db.Exec("INSERT OR IGNORE INTO usn_arrivals(scope,path) VALUES(?,?)",scope,path);db.Exec("COMMIT");return true;}catch{db.Exec("ROLLBACK");throw;}
  }
  internal bool RetryWaiting(Sqlite db,string path){return db.Rows("SELECT 1 FROM usn_retry WHERE scope=? AND path=? AND ready>?",scope,path,History.Now()).Count!=0;}
  internal int ReadyDepth(Sqlite db){return Convert.ToInt32(db.Rows("SELECT COUNT(*) FROM usn_pending p WHERE scope=? AND NOT EXISTS (SELECT 1 FROM usn_retry r WHERE r.scope=p.scope AND r.path=p.path AND r.ready>?)",scope,History.Now())[0][0]);}
  internal int DeferredDepth(Sqlite db){return Convert.ToInt32(db.Rows("SELECT COUNT(*) FROM usn_retry WHERE scope=? AND ready>?",scope,History.Now())[0][0]);}
  internal static int RetryDelay(int attempts){return Math.Min(900,30 << Math.Min(5,Math.Max(0,attempts-1)));}
  internal void Defer(Sqlite db,string path){
   long now=History.Now();db.Exec("BEGIN IMMEDIATE");try{
    // Duplicate callers in the same attempt must not extend or accelerate the cooldown.
    if(db.Rows("SELECT 1 FROM usn_pending WHERE scope=? AND path=?",scope,path).Count!=0&&!RetryWaiting(db,path)){
     var prior=db.Rows("SELECT attempts FROM usn_retry_attempts WHERE scope=? AND path=?",scope,path).FirstOrDefault();int attempts=prior==null?1:Math.Min(6,Convert.ToInt32(prior[0])+1);
     db.Exec("INSERT OR REPLACE INTO usn_retry_attempts(scope,path,attempts) VALUES(?,?,?)",scope,path,attempts);
     db.Exec("INSERT OR REPLACE INTO usn_retry(scope,path,ready) VALUES(?,?,?)",scope,path,now+RetryDelay(attempts));
    }
    db.Exec("COMMIT");
   }catch{db.Exec("ROLLBACK");throw;}
  }
  internal void Ack(Sqlite db,string path){db.Exec("BEGIN IMMEDIATE");try{db.Exec("DELETE FROM usn_pending WHERE scope=? AND path=?",scope,path);db.Exec("DELETE FROM usn_arrivals WHERE scope=? AND path=?",scope,path);db.Exec("DELETE FROM usn_retry WHERE scope=? AND path=?",scope,path);db.Exec("DELETE FROM usn_retry_attempts WHERE scope=? AND path=?",scope,path);db.Exec("COMMIT");}catch{db.Exec("ROLLBACK");throw;}}
  internal int PriorityDepth(Sqlite db){if(volumes.Count==0)return 0;return Convert.ToInt32(db.Rows("SELECT COUNT(*) FROM usn_arrivals WHERE scope=?",scope)[0][0]);}
  internal int Depth(Sqlite db){if(volumes.Count==0)return 0;return Convert.ToInt32(db.Rows("SELECT COUNT(*) FROM usn_pending WHERE scope=?",scope)[0][0]);}
  internal bool Covers(string path){string root=Path.GetPathRoot(path);return volumes.Any(v=>string.Equals(v.Root,root,StringComparison.OrdinalIgnoreCase)&&(v.Status=="Live"||v.Status=="Replaying"));}
  internal object[] Status(){return volumes.Select(v=>(object)new {volume=v.Root,status=v.Status,detail=v.Detail,checkpoint=v.Next.ToString(),tail=v.Tail.ToString()}).ToArray();}
 }
}
