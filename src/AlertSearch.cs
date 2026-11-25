using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Web;

namespace LinkScope {
    internal sealed class AlertSearch {
        readonly List<string> predicates=new List<string>();
        readonly List<object> values=new List<object>();
        long? through;
        long requestedPage;
        int size;
        internal static string Fold(string s){
            var b=new StringBuilder();
            string clean=s??"";
            try{clean=clean.Normalize(NormalizationForm.FormD);}
            catch(ArgumentException){clean=Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(clean)).Normalize(NormalizationForm.FormD);}
            foreach(char c in clean.ToUpperInvariant())
                if(CharUnicodeInfo.GetUnicodeCategory(c)!=UnicodeCategory.NonSpacingMark)b.Append(c);
            return b.ToString().Normalize(NormalizationForm.FormC);
        }
        internal static void Index(Sqlite db,HealthAlert a){
            db.Exec("INSERT OR REPLACE INTO alert_search_index(seq,words) VALUES(?,?)",a.Sequence,
                Fold(string.Join(" ",a.Id,a.Key,a.Category,a.Severity,a.Title,a.Message)));
        }
        internal static void Migrate(Sqlite db){
            if(db.Rows("SELECT 1 FROM alert_migrations WHERE name='search-text-v1'").Count>0)return;
            long last=0;
            while(true){
                var rows=db.Rows("SELECT "+Alerts.Columns+" FROM alert_events WHERE seq>? ORDER BY seq LIMIT 512",last);
                foreach(var row in rows){var a=Alerts.FromRow(row);Index(db,a);last=a.Sequence;}
                if(rows.Count<512)break;
            }
            db.Exec("INSERT INTO alert_migrations VALUES('search-text-v1')");
        }
        static long? Number(string raw,long min,long max){
            if(raw==null)return null;
            long n;if(!long.TryParse(raw,NumberStyles.None,CultureInfo.InvariantCulture,out n)||n<min||n>max)throw new HttpError(400,"Invalid alert search number or date.");
            return n;
        }
        void Filter(string predicate,object val){predicates.Add(predicate);values.Add(val);}
        internal AlertSearch(string query){
            var q=HttpUtility.ParseQueryString(query);
            string[] known={"q","category","severity","state","read","from","until","through","page","size"};
            if(q.AllKeys.Any(k=>k==null||!known.Contains(k)||q.GetValues(k).Length!=1))throw new HttpError(400,"Invalid or repeated alert search parameter.");
            requestedPage=Number(q["page"],1,int.MaxValue)??1;
            size=(int)(Number(q["size"],1,100)??25);
            if(!new[]{10,25,50,100}.Contains(size))throw new HttpError(400,"Choose a supported page size.");
            through=Number(q["through"],0,long.MaxValue);
            string term=(q["q"]??"").Trim();
            if(term.Length>200||term.Any(char.IsControl))throw new HttpError(400,"Use up to 200 characters for search.");
            string[] words=Fold(term).Split((char[])null,StringSplitOptions.RemoveEmptyEntries).Distinct().ToArray();
            if(words.Length>12)throw new HttpError(400,"Use at most 12 search terms.");
            if(words.Length>0){
                predicates.Add("EXISTS (SELECT 1 FROM alert_search_index s WHERE s.seq=alert_events.seq AND "+
                    string.Join(" AND ",words.Select(x=>"instr(s.words,?)>0"))+")");
                values.AddRange(words);
            }
            string category=q["category"],severity=q["severity"],state=q["state"],read=q["read"];
            if(!string.IsNullOrEmpty(category)){
                if(!Config.Core.Concat(Config.Extras).Concat(new[]{"network"}).Contains(category))throw new HttpError(400,"Unknown alert category.");
                Filter("category=?",category);
            }
            if(!string.IsNullOrEmpty(severity)){
                if(!new[]{"info","warning","error","critical"}.Contains(severity))throw new HttpError(400,"Unknown severity.");
                Filter("severity=?",severity);
            }
            if(!string.IsNullOrEmpty(state)){
                if(state!="active"&&state!="resolved")throw new HttpError(400,"Unknown alert state.");
                Filter("resolved=?",state=="resolved");
            }
            if(!string.IsNullOrEmpty(read)){
                if(read!="read"&&read!="unread")throw new HttpError(400,"Unknown reading state.");
                Filter("is_read=?",read=="read");
            }
            var from=Number(q["from"],0,253402300799L);var until=Number(q["until"],0,253402300799L);
            if(from.HasValue&&until.HasValue&&from>=until)throw new HttpError(400,"The end date must be on or after the start date.");
            if(from.HasValue)Filter("since>=?",from.Value);
            if(until.HasValue)Filter("since<?",until.Value);
        }
        internal object Run(string database){
            using(var db=new Sqlite(database,true)){
                db.Exec("BEGIN");
                long head=(long)db.Rows("SELECT COALESCE(MAX(seq),0) FROM alert_events")[0][0];
                long cutoff=Math.Min(through??head,head);
                var filters=new List<string>(predicates){"seq<=?"};var args=new List<object>(values){cutoff};
                string where=" FROM alert_events WHERE "+string.Join(" AND ",filters);
                long total=(long)db.Rows("SELECT COUNT(*)"+where,args.ToArray())[0][0];
                long pages=Math.Max(1,(total+size-1)/size),page=Math.Min(requestedPage,pages);
                args.Add(size);args.Add((page-1)*size);
                var events=db.Rows("SELECT "+Alerts.Columns+where+" ORDER BY seq DESC LIMIT ? OFFSET ?",args.ToArray()).Select(Alerts.FromRow).Select(a=>a.View(true)).ToArray();
                long unread=(long)db.Rows("SELECT COUNT(*) FROM alert_events WHERE is_read=0")[0][0];
                string[] categories=db.Rows("SELECT DISTINCT category FROM alert_events ORDER BY category").Select(r=>(string)r[0]).ToArray();
                db.Exec("COMMIT");
                return new {alerts=events,through=cutoff,unread=unread,total=total,pages=pages,page=page,size=size,categories=categories};
            }
        }
    }
}
