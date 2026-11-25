using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;

namespace LinkScope {
    public sealed class DeliverySettings {
        public bool EmailEnabled {get;set;}
        public bool EmailRecovery {get;set;}
        public string SmtpHost {get;set;}
        public int SmtpPort {get;set;}
        public string Encryption {get;set;}
        public string Authentication {get;set;}
        public string Username {get;set;}
        public string ProtectedPassword {get;set;}
        public string From {get;set;}
        public string SenderName {get;set;}
        public string To {get;set;}
        public string Cc {get;set;}
        public string Bcc {get;set;}
        public string ReplyTo {get;set;}
        public string SubjectPrefix {get;set;}
        public int TimeoutSeconds {get;set;}
        public bool JsonEnabled {get;set;}
        public string JsonDirectory {get;set;}
        public int MaxJsonFiles {get;set;}

        public DeliverySettings(){
            SmtpHost=Username=ProtectedPassword=From=To=Cc=Bcc=ReplyTo=JsonDirectory="";
            SmtpPort=587;Encryption="starttls";Authentication="none";SenderName="LinkScope";
            EmailRecovery=true;SubjectPrefix="[LinkScope]";TimeoutSeconds=20;MaxJsonFiles=100;
        }
        internal DeliverySettings PublicCopy(){var c=(DeliverySettings)MemberwiseClone();c.ProtectedPassword="";return c;}
        internal string DirectoryPath(){return JsonDirectory.Length==0?Path.Combine(Config.Data,"active-alerts"):JsonDirectory;}
        static string Field(string value,int limit,string label){
            value=value??"";
            if(value.Length>limit||value.Any(char.IsControl))throw new InvalidDataException("Invalid "+label+".");
            return value.Trim();
        }
        internal static string[] Addresses(string list){
            if(string.IsNullOrWhiteSpace(list))return new string[0];
            var parts=list.Split(new[]{',',';'}).Select(x=>x.Trim()).ToArray();
            foreach(string part in parts){
                try{
                    if(part.Length==0||part.Length>254||part.Any(c=>c<33||c>126)||part.Contains("<")||part.Contains(">")||
                        !string.Equals(new MailAddress(part).Address,part,StringComparison.Ordinal))throw new FormatException();
                }catch(FormatException){throw new InvalidDataException("Use email addresses only, separated with commas or semicolons.");}
            }
            return parts.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        }
        internal void Validate(bool requireMail){
            SmtpHost=Field(SmtpHost,253,"SMTP host");Username=Field(Username,256,"SMTP username");
            SenderName=Field(SenderName,100,"sender name");SubjectPrefix=Field(SubjectPrefix,100,"subject prefix");
            From=Field(From,254,"sender address");ReplyTo=Field(ReplyTo,254,"reply address");
            To=Field(To,4096,"To list");Cc=Field(Cc,4096,"Cc list");Bcc=Field(Bcc,4096,"Bcc list");
            JsonDirectory=Field(JsonDirectory,240,"alert directory");
            if(SmtpPort<1||SmtpPort>65535||TimeoutSeconds<3||TimeoutSeconds>120)throw new InvalidDataException("Set a valid SMTP port and a timeout of 3–120 seconds.");
            if(!new[]{"plain","starttls","tls"}.Contains(Encryption)||!new[]{"none","auto","login","plain"}.Contains(Authentication))
                throw new InvalidDataException("Choose an available SMTP connection and authentication mode.");
            if(!requireMail&&(MaxJsonFiles<1||MaxJsonFiles>10000))throw new InvalidDataException("Keep between 1 and 10000 JSON files.");
            if(!requireMail&&JsonDirectory.Length>0){
                if(!Path.IsPathRooted(JsonDirectory)||JsonDirectory.StartsWith(@"\\?\")||JsonDirectory.StartsWith(@"\\.\")||
                    !(JsonDirectory.StartsWith(@"\\")||JsonDirectory.Length>=3&&JsonDirectory[1]==':'&&(JsonDirectory[2]=='\\'||JsonDirectory[2]=='/')))
                    throw new InvalidDataException("Use a full Windows directory path, or leave it blank for the default.");
                try{JsonDirectory=Path.GetFullPath(JsonDirectory).TrimEnd(Path.DirectorySeparatorChar,Path.AltDirectorySeparatorChar);
                    if(JsonDirectory.Length<=Path.GetPathRoot(JsonDirectory).TrimEnd('\\','/').Length)throw new ArgumentException();}
                catch(ArgumentException){throw new InvalidDataException("Choose a directory below a drive or share root.");}
            }
            if(!requireMail&&!EmailEnabled)return;
            if(Uri.CheckHostName(SmtpHost)==UriHostNameType.Unknown||SmtpHost.Length==0)throw new InvalidDataException("Enter a valid SMTP hostname or IP address.");
            if(Addresses(From).Length!=1||Addresses(ReplyTo).Length>1||Addresses(To).Length==0)throw new InvalidDataException("Specify one From address, at least one To address and at most one Reply-To address.");
            if(Addresses(To).Length+Addresses(Cc).Length+Addresses(Bcc).Length>100)throw new InvalidDataException("Use at most 100 recipients per message.");
            if(Authentication!="none"&&(Username.Length==0||string.IsNullOrEmpty(ProtectedPassword)))throw new InvalidDataException("Enter the SMTP username and password.");
            if(Authentication!="none"&&Encryption=="plain")throw new InvalidDataException("Select STARTTLS or implicit TLS to send SMTP credentials.");
        }
        internal void ApplySecret(DeliverySettings previous,string replacement,bool clear){
            ProtectedPassword=previous.ProtectedPassword??"";
            if(clear&& !string.IsNullOrEmpty(replacement))throw new InvalidDataException("Choose either a new password or Clear stored password.");
            if(clear)ProtectedPassword="";
            else if(!string.IsNullOrEmpty(replacement)){
                if(replacement.Length>2048||replacement.Contains("\0"))throw new InvalidDataException("Invalid SMTP password.");
                byte[] bytes=Encoding.UTF8.GetBytes(replacement);
                try{ProtectedPassword=Convert.ToBase64String(ProtectedData.Protect(bytes,null,DataProtectionScope.LocalMachine));}
                finally{Array.Clear(bytes,0,bytes.Length);}
            }else if(ProtectedPassword.Length>0&&(!string.Equals((SmtpHost??"").Trim(),previous.SmtpHost,StringComparison.OrdinalIgnoreCase)||
                  !string.Equals((Username??"").Trim(),previous.Username,StringComparison.Ordinal))){
                throw new InvalidDataException("Re-enter or clear the stored SMTP password when changing the server or username.");
            }
        }
        internal bool SameMailSettings(DeliverySettings other){
            return other!=null&&EmailEnabled==other.EmailEnabled&&SmtpHost==other.SmtpHost&&SmtpPort==other.SmtpPort&&
                Encryption==other.Encryption&&Authentication==other.Authentication&&Username==other.Username&&ProtectedPassword==other.ProtectedPassword&&
                From==other.From&&SenderName==other.SenderName&&To==other.To&&Cc==other.Cc&&Bcc==other.Bcc&&ReplyTo==other.ReplyTo&&
                TimeoutSeconds==other.TimeoutSeconds&&SubjectPrefix==other.SubjectPrefix;
        }
        internal byte[] PasswordBytes(){return ProtectedData.Unprotect(Convert.FromBase64String(ProtectedPassword),null,DataProtectionScope.LocalMachine);}
    }
    public sealed class DeliveryInput {
        public DeliverySettings Delivery {get;set;}
        public string NewSmtpPassword {get;set;}
        public bool ClearSmtpPassword {get;set;}
    }
}
