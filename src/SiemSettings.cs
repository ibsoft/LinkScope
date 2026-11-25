using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace LinkScope {
    public sealed class SiemHttp {
        public string BaseUrl {get;set;}
        public string ProtectedKey {get;set;}
        public string Index {get;set;}
        public bool Enabled {get;set;}
        public string MinimumLevel {get;set;}
        public SiemHttp(){BaseUrl=ProtectedKey="";Index="linkscope-logs";MinimumLevel="Info";}
        internal SiemHttp PublicCopy(){var copy=(SiemHttp)MemberwiseClone();copy.ProtectedKey="";return copy;}
        internal void Validate(bool elastic){
            MinimumLevel=LogSettings.Level(MinimumLevel).ToString();
            BaseUrl=(BaseUrl??"").Trim().TrimEnd('/');ProtectedKey=ProtectedKey??"";
            if(Enabled||BaseUrl.Length!=0){
                Uri uri;
                if(BaseUrl.Length>1000||!Uri.TryCreate(BaseUrl,UriKind.Absolute,out uri)||
                   (uri.Scheme!="https"&&uri.Scheme!="http")||uri.UserInfo!=""||uri.Query!=""||uri.Fragment!=""||uri.Host=="")
                    throw new InvalidDataException("Enter the SIEM server base URL without credentials, query or fragment.");
                BaseUrl=uri.AbsoluteUri.TrimEnd('/');
                if(ProtectedKey!=""&&uri.Scheme!="https")
                    throw new InvalidDataException("Use HTTPS when sending a SIEM API key.");
            }
            if(elastic&&(string.IsNullOrEmpty(Index)||Index.Length>255||Index=="."||Index==".."||
               !char.IsLetterOrDigit(Index[0])||Index.Any(c=>!(c>='a'&&c<='z'||c>='0'&&c<='9'||c=='-'||c=='_'||c=='.'))))
                throw new InvalidDataException("Use a lowercase Elasticsearch index or data stream name, starting with a letter or digit.");
        }
        internal void MergeKey(SiemHttp saved,string replacement,bool clear){
            ProtectedKey=saved.ProtectedKey??"";
            if(clear&&!string.IsNullOrEmpty(replacement))throw new InvalidDataException("Choose either a replacement SIEM key or Clear.");
            if(clear){ProtectedKey="";return;}
            if(!string.IsNullOrEmpty(replacement)){
                if(replacement.Length>4096||replacement.Any(c=>c<33||c>126))throw new InvalidDataException("Enter the API key value without spaces or a header prefix.");
                byte[] b=Encoding.UTF8.GetBytes(replacement);
                try{ProtectedKey=Convert.ToBase64String(ProtectedData.Protect(b,null,DataProtectionScope.LocalMachine));}
                finally{Array.Clear(b,0,b.Length);}
            }else if(ProtectedKey!=""&&(BaseUrl??"").Trim().TrimEnd('/')!=saved.BaseUrl)
                throw new InvalidDataException("Re-enter or clear the SIEM key when changing the server URL.");
        }
        internal string Key(){
            if(string.IsNullOrEmpty(ProtectedKey))return "";
            var b=ProtectedData.Unprotect(Convert.FromBase64String(ProtectedKey),null,DataProtectionScope.LocalMachine);
            try{return Encoding.UTF8.GetString(b);}finally{Array.Clear(b,0,b.Length);}
        }
    }
    public sealed class WazuhReceiver {
        public bool Enabled {get;set;}
        public string Host {get;set;} public int Port {get;set;} public string Transport {get;set;}
        public string MinimumLevel {get;set;}
        public WazuhReceiver(){Host="";Port=514;Transport="tcp";MinimumLevel="Info";}
        internal void Validate(){
            Host=(Host??"").Trim();MinimumLevel=LogSettings.Level(MinimumLevel).ToString();
            if((Enabled||Host!="")&&(Host.Length>253||Uri.CheckHostName(Host)==UriHostNameType.Unknown))
                throw new InvalidDataException("Enter the Wazuh syslog receiver hostname or IP address.");
            if(Port<1||Port>65535||Transport!="udp"&&Transport!="tcp")throw new InvalidDataException("Choose a valid Wazuh TCP or UDP port.");
        }
    }
    public sealed class SiemSettings {
        internal static readonly string[] Kinds={"Seq","Wazuh","Elastic"};
        public SiemHttp Seq {get;set;} public WazuhReceiver Wazuh {get;set;} public SiemHttp Elastic {get;set;}
        public SiemSettings(){Seq=new SiemHttp();Wazuh=new WazuhReceiver();Elastic=new SiemHttp();}
        internal void Validate(){
            if(Seq==null||Elastic==null||Wazuh==null)throw new InvalidDataException("Invalid SIEM receiver settings.");
            Seq.Validate(false);Elastic.Validate(true);Wazuh.Validate();
        }
        internal static SiemSettings Merge(SiemSettings saved,SiemEdit edit){
            if(edit.Siem==null)return saved;
            var next=edit.Siem;
            if(next.Seq==null||next.Elastic==null)throw new InvalidDataException("Invalid SIEM receiver settings.");
            next.Seq.MergeKey(saved.Seq,edit.NewSeqKey,edit.ClearSeqKey);
            next.Elastic.MergeKey(saved.Elastic,edit.NewElasticKey,edit.ClearElasticKey);
            return next;
        }
        internal SiemSettings PublicCopy(){return new SiemSettings{Seq=Seq.PublicCopy(),Elastic=Elastic.PublicCopy(),Wazuh=Wazuh};}
        internal string Route(string kind){
            switch(kind){
            case "Seq":return Seq.Enabled?Seq.BaseUrl:"";
            case "Elastic":return Elastic.Enabled?Elastic.BaseUrl+"|"+Elastic.Index:"";
            case "Wazuh":return Wazuh.Enabled?Wazuh.Transport+"|"+Wazuh.Host.ToLowerInvariant()+"|"+Wazuh.Port:"";
            default:throw new InvalidDataException("Unknown SIEM receiver.");
            }
        }
        internal LogLevel Minimum(string kind){return LogSettings.Level(kind=="Seq"?Seq.MinimumLevel:kind=="Elastic"?Elastic.MinimumLevel:Wazuh.MinimumLevel);}
    }
    public sealed class SiemEdit {
        public SiemSettings Siem {get;set;} public string NewSeqKey {get;set;} public string NewElasticKey {get;set;}
        public bool ClearSeqKey {get;set;} public bool ClearElasticKey {get;set;}
    }
    public sealed class SiemTestInput {public string Receiver {get;set;}}
}
