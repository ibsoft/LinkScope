using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Web.Script.Serialization;

namespace LinkScope {
    public sealed class Target {
        public string Name {get;set;} public string Address {get;set;}
        public bool AlertsEnabled {get;set;}
        public int? FailureCount {get;set;} public int? HighRttMs {get;set;} public int? LossPercent {get;set;}
        public int LossWindowProbes {get;set;}
        public Target(){AlertsEnabled=true;LossWindowProbes=20;}
    }
    public sealed class Config {
        public EndpointSettings Endpoint {get;set;}
        public IntegritySettings Integrity {get;set;}
        public AiSettings Ai {get;set;}
        public TelemetryExportSettings TelemetryExport {get;set;}
        public DatabaseMaintenanceSettings DatabaseMaintenance {get;set;}
        public SiemSettings Siem {get;set;}
        public LogSettings Logging {get;set;}
        public DeliverySettings Delivery {get;set;}
        public string BrandLabel {get;set;}
        public string BindAddress {get;set;}
        public string[] AllowedClientIPs {get;set;}
        public bool UseHttps {get;set;}
        public string HostName {get;set;}
        public string CertificateThumbprint {get;set;}
        public int Port {get;set;}
        public int IntervalSeconds {get;set;}
        public int TimeoutMs {get;set;}
        public string InterfaceName {get;set;}
        public Target[] Targets {get;set;}
        public bool RequireLogin {get;set;}
        public int ResourceSeconds {get;set;}
        public int InventoryMinutes {get;set;}
        public int EventsPerChannel {get;set;}
        public string[] EventChannels {get;set;}
        public int CpuAlertPercent {get;set;}
        public int RamAlertPercent {get;set;}
        public int DiskAlertPercent {get;set;}
        public int ProbeAlertCount {get;set;}
        public int NetworkCardHours {get;set;}
        public int LowLifePercent {get;set;}
        public bool WriteDiskEvents {get;set;}
        public string[] ExtraCategories {get;set;}
        public static readonly string[] Core={"ram","cpu","disk_usage","smart","events","firewall","antivirus","security","data_integrity","endpoint_protection"};
        public static readonly string[] Extras={"os","computer","bios","baseboard","processors","memory_modules","graphics","network_adapters","ip_addresses","dns","routes","volumes","partitions","services","processes","hotfixes","installed_software","drivers","pnp_devices","usb","battery","shares","printers","pagefile","time_zone","event_details"};
        public static readonly string[] Channels={"System","Application","Microsoft-Windows-Windows Defender/Operational","Microsoft-Windows-Windows Firewall With Advanced Security/Firewall","Microsoft-Windows-WindowsUpdateClient/Operational","Microsoft-Windows-TaskScheduler/Operational","Microsoft-Windows-NTFS/Operational","Microsoft-Windows-Storage-Storport/Operational"};
        public Config() {
            Endpoint=new EndpointSettings();Integrity=new IntegritySettings();DatabaseMaintenance=new DatabaseMaintenanceSettings();TelemetryExport=new TelemetryExportSettings();Delivery=new DeliverySettings();Logging=new LogSettings();Ai=new AiSettings();Siem=new SiemSettings();
            AllowedClientIPs=new string[0]; BrandLabel=""; BindAddress="127.0.0.1"; HostName="localhost"; CertificateThumbprint=""; Port=9876;
            IntervalSeconds=5; TimeoutMs=1500; InterfaceName=""; RequireLogin=true; ResourceSeconds=15;
            InventoryMinutes=5; EventsPerChannel=25; EventChannels=Channels.Take(5).ToArray();
            CpuAlertPercent=90;RamAlertPercent=90;DiskAlertPercent=90;ProbeAlertCount=3;NetworkCardHours=24;LowLifePercent=10; WriteDiskEvents=true; ExtraCategories=new string[0];
        }
        public static readonly string Root=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"LinkScope");
        public static readonly string SettingsDir=Path.Combine(Root,"settings");
        public static readonly string FilePath=Path.Combine(SettingsDir,"config.json");
        public static readonly string Data=Path.Combine(Root,"data");
        public static readonly string Db=Path.Combine(Data,"history.sqlite");
        internal static JavaScriptSerializer Json() {return new JavaScriptSerializer {MaxJsonLength=64*1024*1024,RecursionLimit=32};}
        internal static void Save(string path,object value) {
            string temp=Path.Combine(Path.GetDirectoryName(path),Guid.NewGuid().ToString("N")+".tmp");
            try { File.WriteAllText(temp,Json().Serialize(value),new System.Text.UTF8Encoding(false));
                if(File.Exists(path)) File.Replace(temp,path,null); else File.Move(temp,path);
            } finally {if(File.Exists(temp)) File.Delete(temp);}
        }
        public static Config Load(){return Validate(Json().Deserialize<Config>(File.ReadAllText(FilePath)));}
        internal static bool Allowed(string[] selected,string[] allowed){return selected!=null && selected.Length<=allowed.Length && selected.All(x=>allowed.Contains(x)) && selected.Distinct().Count()==selected.Length;}
        internal string[] Categories(){return Core.Concat(ExtraCategories).ToArray();}
        internal string[] CollectedCategories(){return Categories().Concat(TelemetryExport.Enabled?TelemetryExport.Selected().Intersect(Extras):new string[0]).Distinct().ToArray();}
        internal Config PublicCopy(){var copy=(Config)MemberwiseClone();copy.Delivery=Delivery.PublicCopy();copy.Ai=Ai.PublicCopy();copy.Siem=Siem.PublicCopy();return copy;}
        internal string Origin(){return new UriBuilder(UseHttps?"https":"http",UseHttps?HostName:BindAddress,Port).Uri.GetLeftPart(UriPartial.Authority);}
        internal static Config Validate(Config c) {
            IPAddress addr;
            if(c==null || !IPAddress.TryParse(c.BindAddress,out addr) || addr.Equals(IPAddress.Any) || addr.Equals(IPAddress.IPv6Any) || addr.IsIPv6Multicast || addr.Equals(IPAddress.Broadcast))
                throw new InvalidDataException("Choose one specific local listening IP.");
            c.BindAddress=addr.ToString();
            c.RequireLogin=true; // Role-based access does not permit anonymous monitoring.
            c.AllowedClientIPs=ClientFirewall.Validate(c.AllowedClientIPs);
            if(c.Endpoint==null)c.Endpoint=new EndpointSettings();c.Endpoint.Validate();
            if(c.Integrity==null)c.Integrity=new IntegritySettings();c.Integrity.Validate();
            if(c.TelemetryExport==null)c.TelemetryExport=new TelemetryExportSettings();c.TelemetryExport.Validate();
            if(c.DatabaseMaintenance==null)c.DatabaseMaintenance=new DatabaseMaintenanceSettings();c.DatabaseMaintenance.Validate();
            if(c.Delivery==null)c.Delivery=new DeliverySettings();
            c.Delivery.Validate(false);if(c.Ai==null)c.Ai=new AiSettings();c.Ai.Validate();
            if(c.Logging==null)c.Logging=new LogSettings();c.Logging.Validate();if(c.Siem==null)c.Siem=new SiemSettings();c.Siem.Validate();
            c.BrandLabel=(c.BrandLabel??"").Trim();
            if(c.BrandLabel.Length>80||c.BrandLabel.Any(char.IsControl))throw new InvalidDataException("Use a brand label of up to 80 characters with no control characters.");
            if(string.IsNullOrEmpty(c.HostName) || c.HostName.Length>253 || Uri.CheckHostName(c.HostName)!=UriHostNameType.Dns || c.HostName.EndsWith(".") || c.HostName.Any(ch=>!(ch>='A'&&ch<='Z'||ch>='a'&&ch<='z'||ch>='0'&&ch<='9'||ch=='.'||ch=='-')))
                throw new InvalidDataException("Set HostName to localhost or a DNS name matching the certificate.");
            c.HostName=c.HostName.ToLowerInvariant();
            c.CertificateThumbprint=(c.CertificateThumbprint??"").Replace(" ","").ToUpperInvariant();
            if(c.CertificateThumbprint.Length!=0 && (c.CertificateThumbprint.Length!=40 || !c.CertificateThumbprint.All(Uri.IsHexDigit)))
                throw new InvalidDataException("Use a 40-character Windows certificate thumbprint.");
            if(!IPAddress.IsLoopback(addr) && (!c.UseHttps||c.HostName=="localhost"))
                throw new InvalidDataException("A LAN listener needs HTTPS and a DNS name matching its certificate.");
            if(c.Port<1||c.Port>65535||c.IntervalSeconds<1||c.IntervalSeconds>86400||c.TimeoutMs<100||c.TimeoutMs>30000||
                c.ResourceSeconds<5||c.ResourceSeconds>3600||c.InventoryMinutes<1||c.InventoryMinutes>1440||c.EventsPerChannel<1||c.EventsPerChannel>100||
                new[]{c.CpuAlertPercent,c.RamAlertPercent,c.DiskAlertPercent}.Any(x=>x<1||x>100)||c.NetworkCardHours<1||c.NetworkCardHours>48||c.ProbeAlertCount<1||c.ProbeAlertCount>100||c.LowLifePercent<1||c.LowLifePercent>50) throw new InvalidDataException("One or more numeric settings are outside the displayed ranges.");
            if(!Allowed(c.EventChannels,Channels)||c.EventChannels.Length==0||!Allowed(c.ExtraCategories,Extras))
                throw new InvalidDataException("Choose supported channels and categories.");
            if(c.Targets==null||c.Targets.Length<1||c.Targets.Length>128)throw new InvalidDataException("Configure 1 to 128 targets.");
            var seen=new HashSet<string>();
            foreach(var t in c.Targets){
                IPAddress ip;
                if(t==null||!IPAddress.TryParse(t.Address,out ip)||(t.Address.IndexOf('.')<0&&t.Address.IndexOf(':')<0))throw new InvalidDataException("Each target needs a unicast IP address.");
                if(ip.IsIPv4MappedToIPv6)ip=ip.MapToIPv4();
                if(ip.Equals(IPAddress.Any)||ip.Equals(IPAddress.IPv6Any)||ip.Equals(IPAddress.Broadcast)||ip.IsIPv6Multicast||
                    (ip.AddressFamily==AddressFamily.InterNetwork && (ip.GetAddressBytes()[0]&240)==224))throw new InvalidDataException("Each target needs a unicast IP address.");
                t.Address=ip.ToString(); if(!seen.Add(t.Address))throw new InvalidDataException("Duplicate target IP.");
                if(t.FailureCount<0||t.FailureCount>100||t.HighRttMs<1||t.HighRttMs>30000||t.LossPercent<1||t.LossPercent>100||
                    t.LossWindowProbes<2||t.LossWindowProbes>1000)throw new InvalidDataException("Invalid network alert rule for "+t.Address+".");
                t.Name=string.IsNullOrWhiteSpace(t.Name)?t.Address:t.Name.Trim(); if(t.Name.Length>120)throw new InvalidDataException("Target name exceeds 120 characters.");
            }
            c.InterfaceName=(c.InterfaceName??"").Trim();if(c.InterfaceName.Length>256)throw new InvalidDataException("Adapter name exceeds 256 characters.");
            return c;
        }
    }
}
