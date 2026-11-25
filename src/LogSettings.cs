using System;
using System.IO;
using System.Linq;

namespace LinkScope {
    internal enum LogLevel { Debug, Info, Warning, Error }
    public sealed class LogSettings {
        public int RetentionDays {get;set;}
        public string MinimumLevel {get;set;}
        public bool SyslogEnabled {get;set;}
        public string SyslogHost {get;set;}
        public int SyslogPort {get;set;}
        public string SyslogTransport {get;set;}
        public int SyslogFacility {get;set;}
        public string SyslogMinimumLevel {get;set;}
        public LogSettings(){
            RetentionDays=30; MinimumLevel="Info"; SyslogMinimumLevel="Info";
            SyslogHost=""; SyslogPort=514; SyslogFacility=16; SyslogTransport="udp";
        }
        internal static LogLevel Level(string text){
            foreach(LogLevel level in Enum.GetValues(typeof(LogLevel)))
                if(string.Equals(level.ToString(),text,StringComparison.OrdinalIgnoreCase))return level;
            throw new InvalidDataException("Choose Debug, Info, Warning or Error.");
        }
        internal void Validate(){
            MinimumLevel=Level(MinimumLevel).ToString();
            SyslogMinimumLevel=Level(SyslogMinimumLevel).ToString();
            if(RetentionDays<1||RetentionDays>3650)throw new InvalidDataException("Keep application logs for 1 to 3650 days.");
            SyslogHost=(SyslogHost??"").Trim();
            if(SyslogEnabled||SyslogHost.Length>0){
                if(SyslogHost.Length>253||Uri.CheckHostName(SyslogHost)==UriHostNameType.Unknown)
                    throw new InvalidDataException("Enter a syslog hostname or IP address.");
            }
            if(!new[]{"udp","tcp","tls"}.Contains(SyslogTransport)||SyslogPort<1||SyslogPort>65535||
                SyslogFacility<0||SyslogFacility>23)throw new InvalidDataException("Check the syslog transport, port and facility.");
        }
        internal string Destination(){return SyslogEnabled?SyslogTransport+"|"+SyslogHost.ToLowerInvariant()+"|"+SyslogPort+"|"+SyslogFacility:"";}
    }
    public sealed class LogSettingsInput {public LogSettings Logging {get;set;}}
}
