using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace LinkScope {
    public sealed class IntegritySettings {
        public bool Enabled {get;set;}
        public int IntervalSeconds {get;set;}
        public bool Recursive {get;set;}
        public bool WriteEvents {get;set;}
        public string[] Paths {get;set;}
        public string[] ExcludedPaths {get;set;}
        public string[] ExcludedPatterns {get;set;}
        public IntegritySettings(){IntervalSeconds=300;Recursive=true;Paths=new string[0];ExcludedPaths=new string[0];ExcludedPatterns=new string[0];}
        static string[] Normalize(string[] paths){
            if(paths==null||paths.Length>128)throw new InvalidDataException("Maximum 128 integrity paths.");
            return paths.Select(p=>{if(string.IsNullOrWhiteSpace(p)||p.Length>240||p.Any(char.IsControl)||!Regex.IsMatch(p,@"^[A-Za-z]:\\")||p.Substring(2).IndexOf(':')>=0||p.IndexOfAny(new[]{'*','?'})>=0)throw new InvalidDataException("Use absolute local Windows file or directory paths.");
                string full=Path.GetFullPath(p);return full.Length==3?full:full.TrimEnd('\\');}).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x=>x,StringComparer.OrdinalIgnoreCase).ToArray();
        }
        internal void Validate(){Paths=Normalize(Paths);ExcludedPaths=Normalize(ExcludedPaths);
            if(IntervalSeconds<30||IntervalSeconds>86400||(Enabled&&Paths.Length==0))throw new InvalidDataException("Integrity requires paths and an interval of 30–86400 seconds.");
            if(ExcludedPatterns==null||ExcludedPatterns.Length>128||ExcludedPatterns.Any(p=>string.IsNullOrWhiteSpace(p)||p.Length>128||p.Any(char.IsControl)||p.IndexOfAny(new[]{'\\','/',':'})>=0))throw new InvalidDataException("Use filename-only exclusion patterns, e.g. *.log; use excluded paths for folders.");
            ExcludedPatterns=ExcludedPatterns.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x=>x,StringComparer.OrdinalIgnoreCase).ToArray();
            if(Paths.Any(p=>FileIntegrity.Under(p,Config.Root)||FileIntegrity.Under(Config.Root,p)))throw new InvalidDataException("Do not monitor LinkScope's own runtime directory or its ancestors.");
        }
    }
    public sealed class IntegrityEntry {public long Sequence{get;set;} public string Utc{get;set;} public string Previous{get;set;} public string Root{get;set;} public string Policy{get;set;} public string Mac{get;set;} }
    public sealed class IntegrityState {public Dictionary<string,string> Baseline{get;set;} public List<IntegrityEntry> Chain{get;set;} }
    internal sealed class FileIntegrity {
        readonly string folder,data;
        internal FileIntegrity():this(Config.Data){}
        internal FileIntegrity(string dataRoot){data=dataRoot;folder=Path.Combine(dataRoot,"integrity");}
        string KeyPath {get{return Path.Combine(folder,"master.key.protected");}}
        string StatePath {get{return Path.Combine(folder,"chain.json");}}
        string AnchorPath {get{return Path.Combine(data,"integrity-checkpoint.json");}}
        public sealed class Checkpoint {public long Sequence{get;set;} public string Mac{get;set;}}
        readonly object gate=new object();
        const string Genesis="0000000000000000000000000000000000000000000000000000000000000000";
        static readonly StringComparer Ignore=StringComparer.OrdinalIgnoreCase;
        internal static bool Under(string path,string root){return Ignore.Equals(path,root)||path.StartsWith(root.TrimEnd('\\')+"\\",StringComparison.OrdinalIgnoreCase);}
        static string Hex(byte[] b){return BitConverter.ToString(b).Replace("-","").ToLowerInvariant();}
        static string Digest(string text){using(var h=SHA256.Create())return Hex(h.ComputeHash(Encoding.UTF8.GetBytes(text)));}
        static string Policy(IntegritySettings c){return Digest(Config.Json().Serialize(c));}
        static string Root(Dictionary<string,string> files){return Digest(Config.Json().Serialize(files.OrderBy(x=>x.Key,StringComparer.Ordinal).Select(x=>new[]{x.Key,x.Value}).ToArray()));}
        static string Mac(byte[] key,IntegrityEntry e){using(var h=new HMACSHA256(key))return Hex(h.ComputeHash(Encoding.UTF8.GetBytes(Config.Json().Serialize(new object[]{e.Sequence,e.Utc,e.Previous,e.Root,e.Policy}))));}
        static bool Equal(string a,string b){if(a==null||b==null||a.Length!=b.Length)return false;int d=0;for(int i=0;i<a.Length;i++)d|=a[i]^b[i];return d==0;}
        static void NoLinks(string path){for(string p=path;!string.IsNullOrEmpty(p);p=Path.GetDirectoryName(p)){if((File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse point not supported: "+p);}}
        byte[] Key(){NoLinks(KeyPath);var key=ProtectedData.Unprotect(File.ReadAllBytes(KeyPath),null,DataProtectionScope.LocalMachine);if(key.Length!=32)throw new InvalidDataException("Invalid master key.");return key;}
        IntegrityState Load(byte[] key){NoLinks(StatePath);var s=Config.Json().Deserialize<IntegrityState>(File.ReadAllText(StatePath));if(s==null||s.Baseline==null||s.Chain==null||s.Chain.Count==0||!Equal(s.Chain[0].Root,Root(s.Baseline)))throw new InvalidDataException("Baseline authentication failed.");string prev=Genesis;long seq=0;foreach(var e in s.Chain){if(e.Sequence!=++seq||!Equal(e.Previous,prev)||!Equal(e.Mac,Mac(key,e)))throw new InvalidDataException("Hash chain authentication failed.");prev=e.Mac;}NoLinks(AnchorPath);var checkpoint=Config.Json().Deserialize<Checkpoint>(File.ReadAllText(AnchorPath));if(checkpoint==null||checkpoint.Sequence!=seq||!Equal(checkpoint.Mac,prev))throw new InvalidDataException("Integrity checkpoint mismatch: possible truncation or rollback.");return s;}
        void Append(IntegrityState s,byte[] key,string root,string policy){var last=s.Chain.LastOrDefault();var e=new IntegrityEntry{Sequence=last==null?1:last.Sequence+1,Utc=DateTime.UtcNow.ToString("o"),Previous=last==null?Genesis:last.Mac,Root=root,Policy=policy};e.Mac=Mac(key,e);s.Chain.Add(e);Config.Save(StatePath,s);Config.Save(AnchorPath,new Checkpoint{Sequence=e.Sequence,Mac=e.Mac});}
        internal void Authorize(IntegritySettings old,IntegritySettings next){if(Policy(old)==Policy(next))return;if(!Monitor.TryEnter(gate))throw new InvalidDataException("An integrity scan is running. Retry the policy change when it finishes.");try{if(!File.Exists(KeyPath)&&!File.Exists(StatePath)&&!File.Exists(AnchorPath))return;byte[] key=Key();try{var s=Load(key);if(!Equal(s.Chain.Last().Policy,Policy(old)))throw new InvalidDataException("Integrity policy authentication failed. Investigate before changing settings.");Append(s,key,s.Chain.Last().Root,Policy(next));AppJournal.Event(LogLevel.Warning,"Integrity","policy","Authorized integrity policy change; trusted baseline preserved. Previous policy: "+Policy(old)+"; new policy: "+Policy(next));}finally{Array.Clear(key,0,key.Length);}}finally{Monitor.Exit(gate);}}
        static bool Excluded(string p,IntegritySettings c){return c.ExcludedPaths.Any(x=>Under(p,x))||c.ExcludedPatterns.Any(x=>Regex.IsMatch(Path.GetFileName(p),"^"+Regex.Escape(x).Replace(@"\*",".*").Replace(@"\?",".")+"$",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant,TimeSpan.FromMilliseconds(100)));}
        static bool InScope(string p,IntegritySettings c){return c.Paths.Any(x=>Ignore.Equals(x,p)||(Under(p,x)&&(c.Recursive||Ignore.Equals(Path.GetDirectoryName(p),x))))&&!Excluded(p,c);}
        static void Walk(string p,IntegritySettings c,Dictionary<string,string> files,List<string> errors,ref int excluded,WaitHandle stop){
            if(stop.WaitOne(0))throw new OperationCanceledException();
            if(Excluded(p,c)){excluded++;return;}
            try{var attr=File.GetAttributes(p);if((attr&FileAttributes.ReparsePoint)!=0)throw new IOException("Reparse point skipped");
                if((attr&FileAttributes.Directory)!=0){foreach(var f in Directory.EnumerateFiles(p))Walk(f,c,files,errors,ref excluded,stop);if(c.Recursive)foreach(var d in Directory.EnumerateDirectories(p))Walk(d,c,files,errors,ref excluded,stop);return;}
                if(files.ContainsKey(p))return;if(files.Count>=100000)throw new InvalidOperationException("100,000-file limit reached.");
                var before=new FileInfo(p);long length=before.Length;DateTime stamp=before.LastWriteTimeUtc;
                using(var stream=new FileStream(p,FileMode.Open,FileAccess.Read,FileShare.Read,65536,FileOptions.SequentialScan))using(var h=SHA256.Create()){byte[] buffer=new byte[65536];int n;while((n=stream.Read(buffer,0,buffer.Length))>0){if(stop.WaitOne(0))throw new OperationCanceledException();h.TransformBlock(buffer,0,n,buffer,0);}h.TransformFinalBlock(new byte[0],0,0);before.Refresh();if(before.Length!=length||before.LastWriteTimeUtc!=stamp)throw new IOException("File changed during scan");files[p]=Hex(h.Hash);}
            }catch(OperationCanceledException){throw;}catch(InvalidOperationException){throw;}catch(Exception ex){if(errors.Count<1000)errors.Add(p+" · "+ex.GetType().Name);}}
        internal object Scan(IntegritySettings c,WaitHandle stop){lock(gate){byte[] key=null;try{
            bool existing=File.Exists(KeyPath)||File.Exists(StatePath)||File.Exists(AnchorPath);IntegrityState s=null;
            if(existing){key=Key();s=Load(key);if(!Equal(s.Chain.Last().Policy,Policy(c)))throw new InvalidDataException("Integrity settings changed outside authorized workflow.");}
            if(!c.Enabled)return new {status="disabled",items=new object[0]};
            var files=new Dictionary<string,string>(Ignore);var errors=new List<string>();int excluded=0;
            foreach(var p in c.Paths){if(Excluded(p,c)){excluded++;continue;}try{NoLinks(p);}catch(FileNotFoundException){if(s!=null&&s.Baseline.Keys.Any(x=>Ignore.Equals(x,p)))continue;errors.Add(p+" · Protected path missing");continue;}catch(Exception ex){errors.Add(p+" · "+ex.GetType().Name);continue;}Walk(p,c,files,errors,ref excluded,stop);}
            bool initialized=s==null;
            if(s==null){if(errors.Count>0||files.Count==0)return new {status="partial",chainValid=(bool?)null,monitoredFiles=files.Count,excludedEntries=excluded,items=errors.DefaultIfEmpty("No readable, non-excluded files; baseline not created").Select((x,i)=>new {path=x,change="Scan incomplete",severity="warning",status="warning",id="coverage-"+i}).ToArray()};Directory.CreateDirectory(folder);NoLinks(folder);key=new byte[32];using(var rng=RandomNumberGenerator.Create())rng.GetBytes(key);using(var f=new FileStream(KeyPath,FileMode.CreateNew)) {var b=ProtectedData.Protect(key,null,DataProtectionScope.LocalMachine);f.Write(b,0,b.Length);f.Flush(true);}s=new IntegrityState{Baseline=files,Chain=new List<IntegrityEntry>()};Append(s,key,Root(files),Policy(c));AppJournal.Event(LogLevel.Warning,"Integrity","baseline","Initial trusted baseline created: "+files.Count+" files. Verify the source files were trusted at enrollment.");}
            var baseline=new Dictionary<string,string>(s.Baseline,Ignore);var rows=new List<Dictionary<string,object>>();
            Action<string,string,string,string,string> add=(p,change,expected,actual,severity)=>rows.Add(new Dictionary<string,object>{{"id",Digest(p.ToUpperInvariant())},{"path",p},{"change",change},{"expectedHash",expected},{"actualHash",actual},{"severity",severity},{"status",severity}});
            foreach(var f in files){string expected;if(!baseline.TryGetValue(f.Key,out expected))add(f.Key,"New file",null,f.Value,new[]{".exe",".dll",".sys",".ps1",".bat",".cmd",".vbs",".msi",".scr"}.Contains(Path.GetExtension(f.Key),Ignore)?"critical":"warning");else if(!Equal(expected,f.Value))add(f.Key,"Modified file",expected,f.Value,"critical");}
            if(errors.Count==0)foreach(var f in baseline)if(InScope(f.Key,c)&&!files.ContainsKey(f.Key))add(f.Key,"Missing file",f.Value,null,"critical");
            foreach(var e in errors.Distinct(Ignore))add(e,"Scan incomplete",null,null,"warning");
            if(errors.Count==0&&!initialized)Append(s,key,Root(files),Policy(c));
            AppJournal.Event(errors.Count>0?LogLevel.Warning:LogLevel.Info,"Integrity","scan","Files: "+files.Count+"; excluded entries: "+excluded+"; changes or scan errors: "+rows.Count+"; chain sequence: "+s.Chain.Last().Sequence+"; chain head: "+s.Chain.Last().Mac);
            return new {status=errors.Count>0?"partial":"ok",chainValid=true,sequence=s.Chain.Last().Sequence,chainHead=s.Chain.Last().Mac,protectedPaths=c.Paths,monitoredFiles=files.Count,excludedEntries=excluded,violations=rows.Count,items=rows.ToArray()};
        }catch(OperationCanceledException){throw;}catch(Exception ex){return new {status="unavailable",chainValid=false,items=new[]{new {id="chain",path="Integrity storage / policy",change="Integrity verification failed",severity="critical",status="critical",detail=ex.Message}}};}finally{if(key!=null)Array.Clear(key,0,key.Length);}}}
    }
}
