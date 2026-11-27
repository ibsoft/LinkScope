using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Web;
namespace LinkScope {
 internal static class UserAudit {
  static string FileName {get{return Path.Combine(Config.Data,"user-audit.sqlite");}}
  internal static void Init(){using(var db=new Sqlite(FileName,false)){db.Exec("CREATE TABLE IF NOT EXISTS user_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, utc INTEGER NOT NULL, actor TEXT NOT NULL, peer TEXT NOT NULL, action TEXT NOT NULL, status INTEGER NOT NULL, result TEXT NOT NULL)");db.Exec("CREATE INDEX IF NOT EXISTS user_audit_utc ON user_audit(utc)");}}
  internal static void Write(string actor,string peer,string action,int status,string result){using(var db=new Sqlite(FileName,false))db.Exec("INSERT INTO user_audit(utc,actor,peer,action,status,result) VALUES(?,?,?,?,?,?)",History.Now(),actor,peer,action,status,result);}
  internal static object Search(string query){var q=HttpUtility.ParseQueryString(query);if(q.AllKeys.Any(k=>!new[]{"q","result","before","from","until"}.Contains(k)))throw new HttpError(400,"Invalid audit filter.");
   string term=q["q"]??"",result=q["result"]??"";if(term.Length>200||!new[]{"","Success","Denied","Error","Password change required","MFA required"}.Contains(result))throw new HttpError(400,"Invalid audit filter.");
   long before=long.MaxValue,from=0,until=long.MaxValue;if((q["before"]!=null&&!long.TryParse(q["before"],out before))||(q["from"]!=null&&!long.TryParse(q["from"],out from))||(q["until"]!=null&&!long.TryParse(q["until"],out until))||before<=0||from<0||until<=from)throw new HttpError(400,"Invalid audit range.");
   using(var db=new Sqlite(FileName,true)){var rows=db.Rows("SELECT id,utc,actor,peer,action,status,result FROM user_audit WHERE id<? AND utc>=? AND utc<? AND (?='' OR result=?) AND instr(lower(actor||' '||peer||' '||action||' '||result||' '||status),lower(?))>0 ORDER BY id DESC LIMIT 101",before,from,until,result,result,term);return new {rows=rows.Take(100).ToArray(),more=rows.Count>100};}
  }
 }
}
