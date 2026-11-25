using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Web;

namespace LinkScope {
    internal sealed class LogSearch {
        readonly List<string> filters=new List<string>();
        readonly List<object> args=new List<object>();
        readonly long requestedPage,size;
        readonly long? through;
        static long? Number(string value,long min,long max){
            if(value==null)return null;long n;
            if(!long.TryParse(value,NumberStyles.None,CultureInfo.InvariantCulture,out n)||n<min||n>max)
                throw new HttpError(400,"Invalid log search number or timestamp.");
            return n;
        }
        void Filter(string predicate,object v){filters.Add(predicate);args.Add(v);}
        static string Field(string value,int size){
            value=(value??"").Trim();if(value.Length>size||value.Any(char.IsControl))throw new HttpError(400,"Invalid log search text.");
            return value;
        }
        internal LogSearch(string query){
            var q=HttpUtility.ParseQueryString(query);
            string[] fields={"q","level","module","operation","peer","status","from","until","page","size","through"};
            if(q.AllKeys.Any(k=>k==null||!fields.Contains(k)||q.GetValues(k).Length!=1))throw new HttpError(400,"Unknown or repeated log search parameter.");
            requestedPage=Number(q["page"],1,int.MaxValue)??1;size=Number(q["size"],1,100)??25;
            if(!new long[]{10,25,50,100}.Contains(size))throw new HttpError(400,"Unsupported page size.");
            through=Number(q["through"],0,long.MaxValue);
            var terms=AlertSearch.Fold(Field(q["q"],200)).Split((char[])null,StringSplitOptions.RemoveEmptyEntries).Distinct().ToArray();
            if(terms.Length>12)throw new HttpError(400,"Use up to twelve search terms.");
            foreach(var term in terms)Filter("instr(words,?)>0",term);
            if(!string.IsNullOrEmpty(q["level"]))Filter("level=?",(int)LogSettings.Level(q["level"]));
            if(!string.IsNullOrEmpty(q["module"]))Filter("module=? COLLATE NOCASE",Field(q["module"],50));
            if(!string.IsNullOrEmpty(q["operation"]))Filter("instr(lower(operation),lower(?))>0",Field(q["operation"],100));
            if(!string.IsNullOrEmpty(q["peer"]))Filter("peer=? COLLATE NOCASE",Field(q["peer"],80));
            var status=Number(q["status"],100,599);if(status.HasValue)Filter("status=?",status.Value);
            var start=Number(q["from"],0,253402300799L);var end=Number(q["until"],0,253402300799L);
            if(start.HasValue&&end.HasValue&&end<=start)throw new HttpError(400,"End time must be later than start time.");
            if(start.HasValue)Filter("t>=?",start.Value);if(end.HasValue)Filter("t<?",end.Value);
        }
        internal object Run(string path){
            using(var db=new Sqlite(path,true)){
                db.Exec("BEGIN");
                long head=(long)db.Rows("SELECT COALESCE(MAX(id),0) FROM app_log")[0][0];
                long cutoff=Math.Min(through??head,head);
                var ps=new List<object>(args){cutoff};
                string where=" FROM app_log WHERE "+string.Join(" AND ",filters.Concat(new[]{"id<=?"}));
                long total=(long)db.Rows("SELECT COUNT(*)"+where,ps.ToArray())[0][0];
                long pages=Math.Max(1,(total+size-1)/size),page=Math.Min(requestedPage,pages);
                ps.Add(size);ps.Add((page-1)*size);
                var items=db.Rows("SELECT id,t,level,module,operation,message,peer,status,elapsed"+where+" ORDER BY id DESC LIMIT ? OFFSET ?",ps.ToArray())
                    .Select(r=>new {id=r[0],utc=Telemetry.Utc((long)r[1]),level=((LogLevel)Convert.ToInt32(r[2])).ToString(),module=r[3],operation=r[4],message=r[5],peer=r[6],status=r[7],elapsedMs=r[8]}).ToArray();
                var modules=db.Rows("SELECT DISTINCT module FROM app_log ORDER BY module").Select(r=>(string)r[0]).ToArray();
                db.Exec("COMMIT");return new {items=items,modules=modules,through=cutoff,total=total,pages=pages,page=page,size=size};
            }
        }
    }
}
