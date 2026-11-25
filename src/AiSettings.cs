using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace LinkScope {
    public sealed class AiProfile {
        public string Model {get;set;} public string BaseUrl {get;set;} public string ProtectedKey {get;set;}
        public AiProfile(){Model=BaseUrl=ProtectedKey="";}
        internal AiProfile Copy(bool secret){return new AiProfile{Model=Model,BaseUrl=BaseUrl,ProtectedKey=secret?ProtectedKey:""};}
    }
    public sealed class AiSettings {
        public bool Enabled {get;set;} public string Provider {get;set;}
        public Dictionary<string,AiProfile> Profiles {get;set;}
        internal static readonly Dictionary<string,string> Hosts=new Dictionary<string,string>{
            {"openai","https://api.openai.com/v1"},{"anthropic","https://api.anthropic.com/v1"},{"gemini","https://generativelanguage.googleapis.com/v1beta"},
            {"azure",""},{"bedrock",""},{"cohere","https://api.cohere.com/v2"},{"xai","https://api.x.ai/v1"},{"mistral","https://api.mistral.ai/v1"},{"deepseek","https://api.deepseek.com"},
            {"groq","https://api.groq.com/openai/v1"},{"openrouter","https://openrouter.ai/api/v1"},{"compatible",""}};
        public AiSettings(){Provider="openai";Profiles=new Dictionary<string,AiProfile>();}
        internal AiProfile Profile(string id){AiProfile p;return Profiles.TryGetValue(id,out p)?p:new AiProfile();}
        internal AiSettings PublicCopy(){return new AiSettings{Enabled=Enabled,Provider=Provider,Profiles=Profiles.ToDictionary(x=>x.Key,x=>x.Value.Copy(false))};}
        internal string Base(string id){return Hosts[id].Length==0?Profile(id).BaseUrl:Hosts[id];}
        internal void Validate(){
            if(Profiles==null||Provider==null||!Hosts.ContainsKey(Provider)||Profiles.Any(x=>!Hosts.ContainsKey(x.Key)||x.Value==null))throw new InvalidDataException("Choose a supported AI provider.");
            foreach(var entry in Profiles){
                var p=entry.Value;p.Model=(p.Model??"").Trim();p.BaseUrl=(p.BaseUrl??"").Trim().TrimEnd('/');p.ProtectedKey=p.ProtectedKey??"";
                if(p.Model.Length>180||p.Model.Any(c=>!(char.IsLetterOrDigit(c)||"-_./:@".Contains(c)))||p.Model.Contains(".."))throw new InvalidDataException("Enter the provider model ID or Azure deployment name.");
                if(Hosts[entry.Key]!=""){p.BaseUrl="";continue;}
                if(p.BaseUrl.Length==0)continue;
                Uri u;
                if(p.BaseUrl.Length>800||!Uri.TryCreate(p.BaseUrl,UriKind.Absolute,out u)||u.Scheme!="https"||u.UserInfo!=""||u.Query!=""||u.Fragment!="")
                    throw new InvalidDataException("Enter an HTTPS API base URL without credentials, query or fragment.");
                p.BaseUrl=u.AbsoluteUri.TrimEnd('/');
            }
            if(Enabled&&(Profile(Provider).Model==""||Base(Provider)==""||(Provider!="compatible"&&string.IsNullOrEmpty(Profile(Provider).ProtectedKey))))
                throw new InvalidDataException("Set the model, API key and endpoint for the selected AI provider before enabling AI Assist.");
        }
        internal static AiSettings Merge(AiSettings saved,AiEdit input){
            if(input.Ai==null)return saved;
            var next=input.Ai;
            if(next.Profiles==null||next.Provider==null||!Hosts.ContainsKey(next.Provider))throw new InvalidDataException("Invalid AI settings.");
            foreach(string id in Hosts.Keys){
                var prior=saved.Profile(id);AiProfile p;
                if(!next.Profiles.TryGetValue(id,out p)){if(saved.Profiles.ContainsKey(id))next.Profiles[id]=prior.Copy(true);continue;}
                if(p==null)throw new InvalidDataException("Invalid AI profile.");
                p.ProtectedKey=prior.ProtectedKey;
                if(id==next.Provider){
                    if(input.ClearAiKey&&!string.IsNullOrEmpty(input.NewAiKey))throw new InvalidDataException("Choose either a replacement key or Clear.");
                    if(id==next.Provider&&input.NewAiKey!=null&&input.NewAiKey.Length>4096)throw new InvalidDataException("Invalid API key.");
                    if(input.ClearAiKey)p.ProtectedKey="";
                    else if(!string.IsNullOrEmpty(input.NewAiKey)){
                        string key=input.NewAiKey.Trim();if(key.Length==0||key.Length>4096||key.Any(c=>c<33||c>126))throw new InvalidDataException("Invalid API key.");
                        byte[] b=Encoding.UTF8.GetBytes(key);try{p.ProtectedKey=Convert.ToBase64String(ProtectedData.Protect(b,null,DataProtectionScope.LocalMachine));}finally{Array.Clear(b,0,b.Length);}
                    }
                }
                if(Hosts[id]==""&&!string.IsNullOrEmpty(prior.ProtectedKey)&&p.ProtectedKey==prior.ProtectedKey&&
                    !string.Equals((p.BaseUrl??"").Trim().TrimEnd('/'),prior.BaseUrl,StringComparison.Ordinal))
                    throw new InvalidDataException("Re-enter or clear the API key when changing its endpoint.");
            }
            next.Validate();return next;
        }
        internal string Key(){
            string enc=Profile(Provider).ProtectedKey;if(string.IsNullOrEmpty(enc))return "";
            var b=ProtectedData.Unprotect(Convert.FromBase64String(enc),null,DataProtectionScope.LocalMachine);try{return Encoding.UTF8.GetString(b);}finally{Array.Clear(b,0,b.Length);}
        }
    }
    public sealed class AiEdit {public AiSettings Ai {get;set;}public string NewAiKey {get;set;}public bool ClearAiKey {get;set;}}
}
