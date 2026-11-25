using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;

namespace LinkScope {
    // Elevated tools write a fixed event ID to Windows, never to a service-writable database.
    internal static class MaintenanceEvents {
        static readonly string[] Verbs={"install","uninstall","init-config","smart-once","set-admin","prepare-certificate","check-config","self-test","restart-installed"};
        const int BaseId=4310;
        internal static void Command(string verb,bool success){
            int i=Array.IndexOf(Verbs,verb.TrimStart('-'));if(i<0)return;
            try{
                if(!EventLog.SourceExists("Unixfor LinkScope"))return;
                EventLog.WriteEntry("Unixfor LinkScope","LinkScope "+Verbs[i]+(success?" completed.":" failed."),
                    success?EventLogEntryType.Information:EventLogEntryType.Error,BaseId+i*2+(success?0:1));
            }catch(Exception){} // Diagnostics must not change the result of an administrative command.
        }
        internal static List<LogEntry> Read(long lastId,long lastTime,long cutoff,out long id,out long stamp){
            id=lastId;stamp=lastTime;
            string recent=DateTime.FromFileTimeUtc(Math.Max(0,cutoff*10000000L+116444736000000000L)).ToString("o",CultureInfo.InvariantCulture);
            string last=DateTime.FromFileTimeUtc(Math.Max(0,lastTime)).ToString("o",CultureInfo.InvariantCulture);
            string query="*[System[Provider[@Name='Unixfor LinkScope'] and EventID >= "+BaseId+" and EventID < "+(BaseId+Verbs.Length*2)+
                " and TimeCreated[@SystemTime >= '"+recent+"'] and (EventRecordID > "+lastId+" or TimeCreated[@SystemTime > '"+last+"'])]]";
            var result=new List<LogEntry>();
            using(var reader=new EventLogReader(new EventLogQuery("Application",PathType.LogName,query))){
                while(result.Count<256){
                    using(var item=reader.ReadEvent()){
                        if(item==null)break;if(!item.TimeCreated.HasValue||!item.RecordId.HasValue)continue;
                        var utc=item.TimeCreated.Value.ToUniversalTime();int n=item.Id-BaseId;
                        if(n<0||n>=Verbs.Length*2)continue;
                        string verb=Verbs[n/2];bool ok=n%2==0;
                        result.Add(new LogEntry{Time=(utc.ToFileTimeUtc()-116444736000000000L)/10000000L,
                            Level=!ok?LogLevel.Error:verb=="smart-once"||verb=="check-config"?LogLevel.Debug:LogLevel.Info,
                            Module=verb=="smart-once"?"SMART":"Maintenance",Operation=verb,Peer="",
                            Message=ok?"Command completed.":"Command failed."});
                        id=item.RecordId.Value;stamp=utc.ToFileTimeUtc();
                    }
                }
            }
            return result;
        }
    }
}
