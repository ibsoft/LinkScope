using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

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
