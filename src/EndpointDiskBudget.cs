using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace LinkScope {
 // Application-side read pacing; not a hard physical disk bandwidth guarantee.
 internal sealed class EndpointReadBudget {
  readonly long rate; readonly WaitHandle stop; readonly Stopwatch timer=Stopwatch.StartNew(); long due;
  internal EndpointReadBudget(int mib,WaitHandle stop){rate=Math.Max(1,mib)*1048576L;this.stop=stop;}
  internal int Read(Stream s,byte[] buffer,int offset,int count){
   if(stop.WaitOne(0))throw new OperationCanceledException();
   long start=timer.ElapsedMilliseconds;int n=s.Read(buffer,offset,count);
   if(n==0)return 0;
   // Maintain millisecond fractional credit; do not accrue idle-time burst credit.
   due=Math.Max(due,start*rate)+n*1000L;long delay=(due+rate-1)/rate-timer.ElapsedMilliseconds;
   while(delay>0){if(stop.WaitOne((int)Math.Min(delay,100)))throw new OperationCanceledException();delay=(due+rate-1)/rate-timer.ElapsedMilliseconds;}
   return n;
  }
 }
 // Windows background mode lowers CPU, I/O and memory scheduling priority of
 // this thread only. Never lower the real-time watcher or the ClamD service.
 internal sealed class EndpointBackgroundPriority : IDisposable {
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetThreadPriority(IntPtr thread,int priority);
  readonly bool entered;
  internal EndpointBackgroundPriority(bool enabled){if(enabled)try{entered=SetThreadPriority(GetCurrentThread(),0x00010000);}catch(Exception){}}
  public void Dispose(){if(entered)SetThreadPriority(GetCurrentThread(),0x00020000);}
 }
 // Optional physical disk pressure provider. English PDH names may not be
 // registered on every host; absence never disables real-time protection.
 internal sealed class EndpointDiskPressure {
  PerformanceCounter idle; long lastSample,lastRetry; bool busy; int high,low;
  internal string Status {get;private set;}
  internal EndpointDiskPressure(){Status="Not sampled";}
  [StructLayout(LayoutKind.Sequential)] struct PowerStatus {internal byte Ac,Battery,Percent,Flags;internal int Life,FullLife;}
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetSystemPowerStatus(out PowerStatus power);
  internal string PauseReason(EndpointSettings policy){
   if(policy.BackgroundPauseOnBattery){PowerStatus power;if(GetSystemPowerStatus(out power)&&power.Ac==0)return "On battery power";}
   if(!policy.BackgroundPauseOnBusyDisk){Status="Disk pressure pause disabled";return "";}
   long now=History.Now();if(now-lastSample<3)return busy?"High disk activity":"";lastSample=now;
   try{
    if(idle==null){if(now-lastRetry<60)return "";lastRetry=now;idle=new PerformanceCounter("PhysicalDisk","% Idle Time","_Total",true);idle.NextValue();Status="Sampling physical disk idle time";return "";}
    float value=idle.NextValue();if(float.IsNaN(value)||float.IsInfinity(value)||value<0||value>100)throw new IOException("Invalid disk idle counter");
    Status="Physical disk idle: "+Math.Round(value)+"%";
    if(value<=10){high++;low=0;if(high>=2)busy=true;}else if(value>=25){low++;high=0;if(low>=2)busy=false;}else{high=low=0;}
    return busy?"High disk activity":"";
   }catch(Exception){if(idle!=null){idle.Dispose();idle=null;}busy=false;high=low=0;lastRetry=now;Status="Disk pressure counter unavailable; read pacing still active";return "";}
  }
 }
}

namespace LinkScope {
 // Read-only, bounded sampling. No GC forcing, process working-set trimming, or service control.
 internal sealed class EndpointResourceMonitor {
  [StructLayout(LayoutKind.Sequential)] struct MemoryStatus {internal uint Length,Load;internal ulong Total,Available,PageTotal,PageAvailable,VirtualTotal,VirtualAvailable,Extended;}
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GlobalMemoryStatusEx(ref MemoryStatus value);
  // Windows 7+ supports these counters with PROCESS_QUERY_LIMITED_INFORMATION.
  // Do not request PROCESS_VM_READ, PROCESS_ALL_ACCESS, or a more privileged service token.
  const uint QueryLimited=0x1000,StillActive=259;
  [StructLayout(LayoutKind.Sequential)] struct ProcessMemoryCountersEx {
   internal uint Size,PageFaultCount;
   internal UIntPtr PeakWorkingSet,WorkingSet,QuotaPeakPagedPool,QuotaPagedPool,QuotaPeakNonPagedPool,QuotaNonPagedPool,PagefileUsage,PeakPagefileUsage,PrivateUsage;
  }
  [DllImport("kernel32.dll",SetLastError=true)] static extern SafeFileHandle OpenProcess(uint access,bool inherit,uint pid);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(SafeFileHandle process,out long created,out long exited,out long kernel,out long user);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(SafeFileHandle process,out uint code);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageName(SafeFileHandle process,int flags,StringBuilder name,ref int length);
  [DllImport("psapi.dll",SetLastError=true)] static extern bool GetProcessMemoryInfo(SafeFileHandle process,ref ProcessMemoryCountersEx counters,uint bytes);
  static IOException CounterFailure(string action){int error=Marshal.GetLastWin32Error();return new IOException(action+" (Win32 "+error+")"+(error==5?": access denied; verify the installed ClamD query-access task":""));}
  static bool Running(SafeFileHandle process){uint code;return GetExitCodeProcess(process,out code)&&code==StillActive;}
  static bool ReadMemory(SafeFileHandle process,out long working,out long priv){
   working=priv=0;var m=new ProcessMemoryCountersEx();m.Size=(uint)Marshal.SizeOf(typeof(ProcessMemoryCountersEx));
   if(!GetProcessMemoryInfo(process,ref m,m.Size))return false;
   working=(long)(m.WorkingSet.ToUInt64()/1048576UL);priv=(long)(m.PrivateUsage.ToUInt64()/1048576UL);return true;
  }
  internal static double? CpuDelta(long priorCpu,long cpu,long priorAt,long now,int processors){
   if(now<=priorAt||cpu<priorCpu||processors<1)return null;
   return Math.Round(Math.Min(100.0,100.0*(cpu-priorCpu)/(now-priorAt)/processors),1);
  }
  // Native smoke test on our own process, never requires an elevated test account.
  internal static bool NativeCounterSelfCheck(){
   using(var self=Process.GetCurrentProcess())using(var proc=OpenProcess(QueryLimited,false,(uint)self.Id)){
    long start,exit,kernel,user,working,priv;
    return !proc.IsInvalid&&Running(proc)&&GetProcessTimes(proc,out start,out exit,out kernel,out user)&&start>0&&ReadMemory(proc,out working,out priv)&&working>0&&priv>0;
   }
  }
  readonly Stopwatch clock=Stopwatch.StartNew(); long lastSample=-5000,previousCpuMs,previousAt;uint previousPid;long previousStart;
  int lowCount,highCount;long? availableMiB,totalMiB,clamWorkingMiB,clamPrivateMiB;double? clamCpu;uint clamPid;
  string memoryStatus="Not sampled",clamStatus="Not sampled",sampleUtc; bool lowMemory;int effectiveFloor,previousFloor;
  readonly System.Collections.Generic.Queue<ResourcePoint> history=new System.Collections.Generic.Queue<ResourcePoint>();
  internal sealed class ResourcePoint {public string utc {get;set;} public long? availableMiB {get;set;} public long? clamWorkingMiB {get;set;} public long? clamPrivateMiB {get;set;} public double? clamCpu {get;set;}}
  internal bool LowMemory {get{return lowMemory&&availableMiB.HasValue;}}
  internal static int Floor(long total,int mib,int percent){return (int)Math.Min(total/2,Math.Max(mib,Math.Ceiling(total*percent/100.0)));}
  internal static long RecoveryFloor(long total,int floor){return Math.Min(total, floor+Math.Max(128L,(long)Math.Ceiling(total*.03)));}
  internal static bool Pressure(bool previous,long available,long total,int floor,ref int low,ref int high){
   long recovery=RecoveryFloor(total,floor);
   if(available<floor){low=Math.Min(2,low+1);high=0;if(low>=2)return true;}
   else if(available>=recovery){high=Math.Min(2,high+1);low=0;if(high>=2)return false;}
   else{low=high=0;}return previous;
  }
  internal void Sample(EndpointSettings policy){
   long now=clock.ElapsedMilliseconds;if(now-lastSample<5000)return;lastSample=now;sampleUtc=DateTime.UtcNow.ToString("o");
   try{var m=new MemoryStatus();m.Length=(uint)Marshal.SizeOf(typeof(MemoryStatus));if(!GlobalMemoryStatusEx(ref m)||m.Total<1048576||m.Available>m.Total)throw new IOException("Memory status unavailable");
    totalMiB=(long)(m.Total/1048576);availableMiB=(long)(m.Available/1048576);effectiveFloor=Floor(totalMiB.Value,policy.MemoryMinimumAvailableMiB,policy.MemoryMinimumAvailablePercent);
    if(previousFloor!=effectiveFloor){lowCount=highCount=0;previousFloor=effectiveFloor;}
    lowMemory=Pressure(lowMemory,availableMiB.Value,totalMiB.Value,effectiveFloor,ref lowCount,ref highCount);
    memoryStatus=lowMemory?"Low available memory":"Available memory measured";
   }catch(Exception){availableMiB=totalMiB=null;lowMemory=false;lowCount=highCount=0;memoryStatus="Memory measurement unavailable; memory pause not applied";}
   clamWorkingMiB=clamPrivateMiB=null;clamCpu=null;clamPid=0;clamStatus="Registered ClamD service counters unavailable";
   try{
    if(policy.Port!=3310)throw new IOException("Custom port; registered ClamD counter attribution unavailable");
    uint pid=ClamUpdateWorker.ResourceClamdPid();if(pid<=4)throw new IOException("Registered clamd service not running or SCM status unavailable");
    using(var proc=OpenProcess(QueryLimited,false,pid)){
     if(proc.IsInvalid)throw CounterFailure("Cannot open registered ClamD with query-only access");
     var image=new StringBuilder(4096);int length=image.Capacity;
     if(!QueryFullProcessImageName(proc,0,image,ref length))throw CounterFailure("Cannot verify ClamD image");
     string expected=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"ClamAV","clamd.exe");
     if(!string.Equals(image.ToString(),expected,StringComparison.OrdinalIgnoreCase)||!Running(proc))throw new IOException("Registered ClamD image is nonstandard or no longer running");
     long started,exited,kernel,user;
     if(!GetProcessTimes(proc,out started,out exited,out kernel,out user))throw CounterFailure("Cannot read ClamD CPU times");
     long working,priv;bool memoryOk=ReadMemory(proc,out working,out priv);string memoryError=memoryOk?null:CounterFailure("Cannot read ClamD memory counters").Message;
     if(!Running(proc)||ClamUpdateWorker.ResourceClamdPid()!=pid)throw new IOException("Registered ClamD restarted during sampling; retrying");
     long cpu=(kernel+user)/10000L;
     if(pid==previousPid&&started==previousStart)clamCpu=CpuDelta(previousCpuMs,cpu,previousAt,now,Environment.ProcessorCount);
     previousPid=pid;previousStart=started;previousCpuMs=cpu;previousAt=now;clamPid=pid;
     if(memoryOk){clamWorkingMiB=working;clamPrivateMiB=priv;}
     clamStatus="Registered ClamD service process (query-only)"+(memoryError==null?"":" · "+memoryError)+(clamCpu.HasValue?"":" · CPU awaiting second sample");
    }
   }catch(IOException ex){previousPid=0;clamStatus=ex.Message;}catch(Exception ex){previousPid=0;clamStatus="ClamD resource counters unavailable ("+ex.GetType().Name+")";}
   history.Enqueue(new ResourcePoint{utc=sampleUtc,availableMiB=availableMiB,clamWorkingMiB=clamWorkingMiB,clamPrivateMiB=clamPrivateMiB,clamCpu=clamCpu});while(history.Count>120)history.Dequeue();
  }
  internal object Snapshot(EndpointSettings policy){return new {sampleUtc=sampleUtc,memoryStatus=memoryStatus,availableMiB=availableMiB,totalMiB=totalMiB,effectiveFloorMiB=availableMiB.HasValue?(int?)effectiveFloor:null,recoveryFloorMiB=totalMiB.HasValue?(long?)RecoveryFloor(totalMiB.Value,effectiveFloor):null,lowMemory=LowMemory,backgroundPauseEnabled=policy.BackgroundPauseOnLowMemory,clamStatus=clamStatus,clamPid=clamPid>0?(uint?)clamPid:null,clamWorkingMiB=clamWorkingMiB,clamPrivateMiB=clamPrivateMiB,clamCpu=clamCpu,history=history.ToArray()};}
 }
}
