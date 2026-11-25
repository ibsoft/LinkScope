using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace LinkScope {
    public sealed class ApiKey {
        public string Id {get;set;} public string Name {get;set;} public string Hash {get;set;}
        public string[] Categories {get;set;} public long Expires {get;set;}
        public object Public(){return new {id=Id,name=Name,categories=Categories,expires=Expires};}
    }
    internal sealed class Session {
        internal string Csrf, Revision; internal long Created, Seen;
    }
    internal sealed class Access {
        readonly AdminPasswords passwords;
        readonly string KeyFile;
        readonly Dictionary<string,Session> sessions=new Dictionary<string,Session>();
        readonly Dictionary<string,Queue<long>> attempts=new Dictionary<string,Queue<long>>();
        readonly Queue<long> globalAttempts=new Queue<long>();
        List<ApiKey> keys;
        internal Access():this(Path.Combine(Config.SettingsDir,"tokens.json")){}
        internal Access(string path):this(path, AdminPasswords.Installed){}
        internal Access(string path, AdminPasswords credentials){passwords=credentials;KeyFile=path;keys=File.Exists(KeyFile)?Config.Json().Deserialize<List<ApiKey>>(File.ReadAllText(KeyFile)):new List<ApiKey>();}
        static byte[] Random(int count){var b=new byte[count];using(var r=RandomNumberGenerator.Create())r.GetBytes(b);return b;}
        internal static string Secret(){return Convert.ToBase64String(Random(32)).TrimEnd('=').Replace('+','-').Replace('/','_');}
        static string Digest(string s){using(var h=SHA256.Create())return Convert.ToBase64String(h.ComputeHash(Encoding.UTF8.GetBytes(s)));}
        internal static bool Equal(string a,string b){if(a==null||b==null||a.Length!=b.Length)return false;int diff=0;for(int i=0;i<a.Length;i++)diff|=a[i]^b[i];return diff==0;}
        internal static void SetPassword(){
            Console.WriteLine(AdminPasswords.Rules);
            Console.Write("New LinkScope admin password: ");string a=ReadPassword();
            Console.Write("Confirm password: ");string b=ReadPassword();
            if(!Equal(a,b))throw new InvalidDataException("The two passwords do not match.");
            AdminPasswords.Installed.Reset(a);
            Console.WriteLine("Password saved for admin. Existing browser sessions expire immediately.");
        }
        static string ReadPassword(){if(Console.IsInputRedirected)throw new InvalidOperationException("Use an interactive administrator terminal.");
            var s=new StringBuilder();while(true){var k=Console.ReadKey(true);if(k.Key==ConsoleKey.Enter){Console.WriteLine();return s.ToString();}
            if(k.Key==ConsoleKey.Backspace){if(s.Length>0)s.Length--;}else if(!char.IsControl(k.KeyChar)&&s.Length<129)s.Append(k.KeyChar);}}
        static void Trim(Queue<long> q,long now){while(q.Count>0&&q.Peek()<=now-300)q.Dequeue();}
        internal bool LoginAllowed(string ip){lock(attempts){long now=History.Now();Trim(globalAttempts,now);if(globalAttempts.Count>=30)return false;
            foreach(var key in attempts.Keys.ToArray()){Trim(attempts[key],now);if(attempts[key].Count==0)attempts.Remove(key);}
            Queue<long> q;if(!attempts.TryGetValue(ip,out q))attempts[ip]=q=new Queue<long>();
            if(q.Count>=8)return false;q.Enqueue(now);globalAttempts.Enqueue(now);return true;}}
        internal string Login(string user,string pass,string replacement,bool local,out bool changeRequired){
            var c=passwords.Authenticate(user,pass,replacement,local);
            changeRequired=c!=null&&c.MustChange;
            if(c==null||changeRequired)return null;
            var id=Secret();lock(sessions){long now=History.Now();foreach(var k in sessions.Where(x=>Expired(x.Value,now)).Select(x=>x.Key).ToArray())sessions.Remove(k);
                if(sessions.Count>=64)sessions.Remove(sessions.OrderBy(x=>x.Value.Seen).First().Key);
                sessions[Digest(id)]=new Session{Csrf=Secret(),Revision=c.Hash,Created=now,Seen=now};}return id;
        }
        static bool Expired(Session s,long now){return now-s.Seen>=900||now-s.Created>=28800||now<s.Created;}
        internal Session Find(string cookie){if(cookie==null||cookie.Length!=43)return null;var key=Digest(cookie);
            lock(sessions){Session s;if(!sessions.TryGetValue(key,out s))return null;
                string revision=passwords.Revision();long now=History.Now();
                if(Expired(s,now)||!Equal(s.Revision,revision)){sessions.Remove(key);return null;}s.Seen=now;return s;}}
        internal void Logout(string cookie){if(cookie!=null)lock(sessions)sessions.Remove(Digest(cookie));}
        internal object[] List(){lock(this)return keys.Select(k=>k.Public()).ToArray();}
        internal string Issue(string name,string[] scopes,int days,string[] allowed){
            if(string.IsNullOrWhiteSpace(name)||name.Length>80||!Config.Allowed(scopes,allowed)||scopes.Length==0||days<1||days>365)
                throw new InvalidDataException("Choose a label, available categories and a lifetime of 1-365 days.");
            var secret="ls_"+Secret();var k=new ApiKey{Id=Guid.NewGuid().ToString("N"),Name=name.Trim(),Hash=Digest(secret),Categories=scopes,Expires=History.Now()+days*86400L};
            lock(this){var next=keys.Where(x=>x.Expires>History.Now()).ToList();if(next.Count>=128)throw new InvalidDataException("Revoke an existing token first.");
                next.Add(k);Config.Save(KeyFile,next);keys=next;}return secret;
        }
        internal bool Revoke(string id){lock(this){var next=keys.Where(x=>x.Id!=id).ToList();if(next.Count==keys.Count)return false;Config.Save(KeyFile,next);keys=next;return true;}}
        internal string[] Authorize(string header){if(header==null||header.Length!=53||!header.StartsWith("Bearer ls_",StringComparison.Ordinal))return null;
            string hash=Digest(header.Substring(7));lock(this){var k=keys.FirstOrDefault(x=>x.Expires>History.Now()&&Equal(x.Hash,hash));return k==null?null:k.Categories;}}
    }
}
