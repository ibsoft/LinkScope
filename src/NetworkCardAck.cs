using System;
using System.Linq;
namespace LinkScope {
    public sealed class NetworkCardAckInput { public string target {get;set;} public string metric {get;set;} public long throughT {get;set;} public long throughRow {get;set;} }
    internal static class NetworkCardAck {
        internal static object Snapshot(string target,int hours) {
            using(var db=new Sqlite(true)) { db.Exec("BEGIN"); long now=History.Now();
                var last=db.Rows("SELECT t,rowid,status FROM raw WHERE target=? ORDER BY t DESC,rowid DESC LIMIT 1",target).FirstOrDefault();
                long t=last==null?0:Convert.ToInt64(last[0]), row=last==null?0:Convert.ToInt64(last[1]);
                var items=new[]{"loss","timeouts"}.Select(metric=>{
                    var ack=db.Rows("SELECT stamp,through_t,through_row FROM network_card_ack WHERE target=? AND metric=?",target,metric).FirstOrDefault();
                    long stamp=ack==null?0:Convert.ToInt64(ack[0]), at=ack==null?0:Convert.ToInt64(ack[1]), ar=ack==null?0:Convert.ToInt64(ack[2]);
                    string condition=metric=="loss"?"rtt IS NULL AND status NOT LIKE 'Probe error:%'":"status='TimedOut'";
                    var counts=db.Rows("SELECT COUNT(*),COALESCE(SUM(CASE WHEN t>?3 OR (t=?3 AND rowid>?4) THEN 1 ELSE 0 END),0) FROM raw WHERE target=?1 AND t>=?2 AND ("+condition+")",target,now-hours*3600L,at,ar)[0];
                    var sent=db.Rows("SELECT COUNT(*) FROM raw WHERE target=?1 AND t>=?2 AND (t>?3 OR (t=?3 AND rowid>?4)) AND status NOT LIKE 'Probe error:%'",target,now-hours*3600L,at,ar)[0];
                    return new {metric=metric,acknowledgedAt=stamp,total=counts[0],unacknowledged=counts[1],probesSinceAck=sent[0]};
                }).ToArray();
                var active=db.Rows("SELECT alert_key FROM alert_events WHERE resolved=0 AND category='network' AND (alert_key=? OR alert_key=?)","network/"+target,"network/"+target+"/loss");
                bool failing=active.Any(a=>(string)a[0]=="network/"+target), lossAlert=active.Any(a=>(string)a[0]=="network/"+target+"/loss");
                db.Exec("COMMIT");return new {target=target,hours=hours,throughT=t,throughRow=row,items=items,failing=failing,lossAlert=lossAlert};
            }
        }
        internal static void Acknowledge(NetworkCardAckInput input) {
            using(var db=new Sqlite(false)) {db.Exec("BEGIN IMMEDIATE");try {
                if(input.throughRow<=0||input.throughT<=0||db.Rows("SELECT 1 FROM raw WHERE target=? AND t=? AND rowid=?",input.target,input.throughT,input.throughRow).Count!=1)throw new HttpError(409,"Observation expired. Refresh and try again.");
                foreach(string metric in input.metric=="all"?new[]{"loss","timeouts"}:new[]{input.metric}){
                    db.Exec("INSERT OR IGNORE INTO network_card_ack VALUES(?,?,0,0,0)",input.target,metric);
                    db.Exec("UPDATE network_card_ack SET stamp=?1,through_t=?2,through_row=?3 WHERE target=?4 AND metric=?5 AND (through_t<?2 OR (through_t=?2 AND through_row<?3))",History.Now(),input.throughT,input.throughRow,input.target,metric);
                }db.Exec("COMMIT");}catch{db.Exec("ROLLBACK");throw;}}
        }
    }
}
