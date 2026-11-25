using System;
using System.Collections.Generic;
using System.Linq;

namespace LinkScope {
    internal sealed class Probe {
        internal string Address, Status;
        internal long? Rtt;
        internal bool LocalError;
    }
    internal sealed class Traffic {
        internal string Id, Name;
        internal long RxBytes, TxBytes;
        internal double Seconds;
    }
    internal static class History {
        internal const long Day = 86400;
        internal static long Now() { return (DateTime.UtcNow.Ticks - 621355968000000000L) / TimeSpan.TicksPerSecond; }
        internal static void Init(Sqlite db) {
            db.Exec("PRAGMA journal_mode=WAL");
            db.Exec("PRAGMA synchronous=NORMAL");
            db.Exec("CREATE TABLE IF NOT EXISTS raw (target TEXT NOT NULL, t INTEGER NOT NULL, status TEXT NOT NULL, rtt INTEGER)");
            db.Exec("CREATE INDEX IF NOT EXISTS raw_by_target ON raw(target,t DESC)");
            db.Exec("CREATE INDEX IF NOT EXISTS raw_by_time ON raw(t)");
            db.Exec("CREATE TABLE IF NOT EXISTS ping_roll (target TEXT NOT NULL,res INTEGER NOT NULL,t INTEGER NOT NULL,ok INTEGER NOT NULL DEFAULT 0,lost INTEGER NOT NULL DEFAULT 0,timeouts INTEGER NOT NULL DEFAULT 0,errors INTEGER NOT NULL DEFAULT 0,total INTEGER NOT NULL DEFAULT 0,lo INTEGER,hi INTEGER,PRIMARY KEY(target,res,t)) WITHOUT ROWID");
            db.Exec("CREATE TABLE IF NOT EXISTS traffic_roll (nic TEXT NOT NULL,res INTEGER NOT NULL,t INTEGER NOT NULL,rx INTEGER NOT NULL DEFAULT 0,tx INTEGER NOT NULL DEFAULT 0,seconds REAL NOT NULL DEFAULT 0,PRIMARY KEY(nic,res,t)) WITHOUT ROWID");
            db.Exec("CREATE TABLE IF NOT EXISTS resource_roll (metric TEXT NOT NULL,res INTEGER NOT NULL,t INTEGER NOT NULL,n INTEGER NOT NULL,total REAL NOT NULL,lo REAL NOT NULL,hi REAL NOT NULL,first_sample INTEGER NOT NULL,last_sample INTEGER NOT NULL,PRIMARY KEY(metric,res,t)) WITHOUT ROWID");
        }
        static readonly int[] Resolutions = {300,3600};
        internal static void SaveResources(Dictionary<string,double> usage) {
            using(var db=new Sqlite(false)){
                long now=Now();db.Exec("BEGIN IMMEDIATE");
                try{foreach(var pair in usage)foreach(int res in Resolutions){
                    long t=now-now%res;
                    db.Exec("INSERT OR IGNORE INTO resource_roll VALUES(?,?,?,0,0,?,?,?,?)",pair.Key,res,t,pair.Value,pair.Value,now,now);
                    db.Exec("UPDATE resource_roll SET n=n+1,total=total+?4,lo=MIN(lo,?4),hi=MAX(hi,?4),last_sample=?5 WHERE metric=?1 AND res=?2 AND t=?3",pair.Key,res,t,pair.Value,now);
                }db.Exec("COMMIT");}catch{db.Exec("ROLLBACK");throw;}
            }
        }
        internal static void Save(Sqlite db, long t, Probe[] probes, Traffic traffic, bool cleanup) {
            db.Exec("BEGIN IMMEDIATE");
            try {
                foreach (Probe p in probes) {
                    db.Exec("INSERT INTO raw(target,t,status,rtt) VALUES(?,?,?,?)",p.Address,t,p.Status,p.Rtt);
                    foreach (int res in Resolutions) {
                        long bucket = t - t % res;
                        db.Exec("INSERT OR IGNORE INTO ping_roll(target,res,t) VALUES(?,?,?)",p.Address,res,bucket);
                        db.Exec(@"UPDATE ping_roll SET ok=ok+?4,lost=lost+?5,timeouts=timeouts+?6,errors=errors+?7,total=total+coalesce(?8,0),
                            lo=CASE WHEN lo IS NULL OR ?8<lo THEN ?8 ELSE lo END,hi=CASE WHEN hi IS NULL OR ?8>hi THEN ?8 ELSE hi END
                            WHERE target=?1 AND res=?2 AND t=?3",p.Address,res,bucket,p.Rtt.HasValue,
                            !p.LocalError && !p.Rtt.HasValue,p.Status=="TimedOut",p.LocalError,p.Rtt);
                    }
                }
                if (traffic != null && traffic.Seconds > 0) {
                    foreach (int res in Resolutions) {
                        long bucket = t - t % res;
                        db.Exec("INSERT OR IGNORE INTO traffic_roll(nic,res,t) VALUES(?,?,?)",traffic.Id,res,bucket);
                        db.Exec("UPDATE traffic_roll SET rx=rx+?,tx=tx+?,seconds=seconds+? WHERE nic=? AND res=? AND t=?",
                            traffic.RxBytes,traffic.TxBytes,traffic.Seconds,traffic.Id,res,bucket);
                    }
                }
                if (cleanup) {
                    db.Exec("DELETE FROM raw WHERE t<?",t-2*Day);
                    foreach (int res in Resolutions) {
                        long cutoff = t - (res==300 ? 35 : 400)*Day;
                        db.Exec("DELETE FROM ping_roll WHERE res=? AND t<?",res,cutoff);
                        db.Exec("DELETE FROM traffic_roll WHERE res=? AND t<?",res,cutoff);
                        db.Exec("DELETE FROM resource_roll WHERE res=? AND t<?",res,cutoff);
                    }
                }
                db.Exec("COMMIT");
            } catch { db.Exec("ROLLBACK"); throw; }
        }

        internal static object Report(Config cfg, string ip, string period, string nicId, string nicName, string collectorError, long? at=null) {
            using (var db=new Sqlite(true)) {
                db.Exec("BEGIN");
                long now=at??Now();
                object result;
                if(period=="all") {
                    // Read every range under the same SQLite snapshot and clock.
                    result=new[] {"day","week","month","year"}
                        .Select(range=>ReadRange(db,cfg,ip,range,nicId,nicName,collectorError,now)).ToArray();
                } else {
                    result=ReadRange(db,cfg,ip,period,nicId,nicName,collectorError,now);
                }
                db.Exec("COMMIT");
                return result;
            }
        }

        static void Window(string period,long now,out int step,out int res,out long start,out long end) {
            int days;
            switch(period) {
                case "day": days=1; step=300; break;
                case "week": days=7; step=1800; break;
                case "month": days=30; step=7200; break;
                case "year": days=365; step=86400; break;
                default: throw new ArgumentException("Unknown range.");
            }
            end=now-now%step+step; start=end-days*Day;
            res=days>35 ? 3600 : 300;
        }
        internal static object ResourceTrend(string period,long now){
            int step,res;long start,end;Window(period,now,out step,out res,out start,out end);
            using(var db=new Sqlite(true)){
                var rows=db.Rows(@"SELECT metric,(t/?1)*?1 AS bucket,SUM(n),SUM(total)/SUM(n),MIN(lo),MAX(hi)
                    FROM resource_roll WHERE res=?2 AND t>=?3 AND t<?4 GROUP BY metric,bucket ORDER BY metric,bucket",step,res,start,end);
                var series=rows.GroupBy(r=>(string)r[0]).Select(g=>new {metric=g.Key,points=g.Select(r=>r.Skip(1).ToArray()).ToArray()}).ToArray();
                return new {range=period,start=start,end=end,now=now,step=step,series=series};
            }
        }
        static object ReadRange(Sqlite db, Config cfg, string ip, string period, string nicId, string nicName, string collectorError, long now) {
            int step,res;long start,end;Window(period,now,out step,out res,out start,out end);
            var points=db.Rows(@"SELECT (t/?4)*?4 AS bucket,SUM(ok),SUM(lost),SUM(timeouts),SUM(errors),SUM(total),MIN(lo),MAX(hi)
                FROM ping_roll WHERE target=?1 AND res=?2 AND t>=?3 AND t<?5 GROUP BY bucket ORDER BY bucket",ip,res,start,step,end);
            var rates=db.Rows(@"SELECT (t/?4)*?4 AS bucket,8.0*SUM(rx)/SUM(seconds)/1000000,8.0*SUM(tx)/SUM(seconds)/1000000
                FROM traffic_roll WHERE nic=?1 AND res=?2 AND t>=?3 AND t<?5 GROUP BY bucket ORDER BY bucket",nicId,res,start,step,end);
            var latest=db.Rows("SELECT t,status,rtt FROM raw WHERE target=? AND t<=? ORDER BY t DESC,rowid DESC LIMIT 1",ip,now).FirstOrDefault();
            var exceptions=db.Rows("SELECT t,status FROM raw WHERE target=? AND t>=? AND t<=? AND status<>'Success' ORDER BY t DESC,rowid DESC LIMIT 20",ip,Math.Max(start,now-2*Day),now);
            var resourceUsage=db.Rows("SELECT metric,SUM(n),SUM(total)/SUM(n),MIN(lo),MAX(hi),MIN(first_sample),MAX(last_sample) FROM resource_roll WHERE res=? AND t>=? AND t<? GROUP BY metric ORDER BY metric",res,start,end)
                .Select(r=>new {metric=r[0],samples=r[1],averagePercent=r[2],minPercent=r[3],peakPercent=r[4],firstUtc=Telemetry.Utc(Convert.ToInt64(r[5])),lastUtc=Telemetry.Utc(Convert.ToInt64(r[6]))}).ToArray();
            return new { range=period, target=ip, now=now, start=start, end=end, step=step, targets=cfg.Targets, interval=cfg.IntervalSeconds,
                resourceUsage=resourceUsage, points=points, rates=rates, latest=latest, events=exceptions, nic=nicName, error=collectorError };
        }
    }
}
