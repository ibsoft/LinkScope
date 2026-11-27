using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace LinkScope {
    // Only the service and host administrators can access the inherited settings-directory ACL.
    public sealed class ManagedUser {
        public string Username {get;set;} public string DisplayName {get;set;} public string Email {get;set;}
        public string Role {get;set;} public string Revision {get;set;} public Credential Password {get;set;}
        public string LegacyRevision {get;set;} public string MfaProtected {get;set;} public long LastStep {get;set;}
        public string CreatedUtc {get;set;} public string UpdatedUtc {get;set;}
    }
    public sealed class UserInput {
        public string action {get;set;} public string username {get;set;} public string displayName {get;set;}
        public string email {get;set;} public string role {get;set;} public string password {get;set;}
        public string currentPassword {get;set;} public string otp {get;set;} public string enrollmentCode {get;set;}
    }
    internal sealed class AccountLogin {
        internal string Username, Role, Revision;
        internal bool ChangeRequired, MfaRequired, MfaEnabled;
    }
    internal static class Totp {
        static readonly byte[] Entropy=Encoding.UTF8.GetBytes("LinkScope.UserMfa.v1");
        internal static byte[] NewKey(){var key=new byte[20];using(var rng=RandomNumberGenerator.Create())rng.GetBytes(key);return key;}
        internal static string Protect(byte[] key){return Convert.ToBase64String(ProtectedData.Protect(key,Entropy,DataProtectionScope.LocalMachine));}
        internal static byte[] Unprotect(string value){return ProtectedData.Unprotect(Convert.FromBase64String(value),Entropy,DataProtectionScope.LocalMachine);}
        internal static string Base32(byte[] key){const string alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";var s=new StringBuilder();int bits=0,buffer=0;foreach(byte b in key){buffer=(buffer<<8)|b;bits+=8;while(bits>=5){s.Append(alphabet[(buffer>>(bits-5))&31]);bits-=5;}}if(bits>0)s.Append(alphabet[(buffer<<(5-bits))&31]);return s.ToString();}
        internal static string Code(byte[] key,long step){var b=new byte[8];for(int i=7;i>=0;i--){b[i]=(byte)(step&255);step>>=8;}using(var h=new HMACSHA1(key)){var mac=h.ComputeHash(b);int p=mac[mac.Length-1]&15;int n=((mac[p]&127)<<24)|(mac[p+1]<<16)|(mac[p+2]<<8)|mac[p+3];return (n%1000000).ToString("D6",CultureInfo.InvariantCulture);}}
        internal static long Match(byte[] key,string code,long now,long last){if(code==null||code.Length!=6||code.Any(c=>c<'0'||c>'9'))return -1;long step=now/30;for(long n=step-1;n<=step+1;n++)if(n>=0&&n>last&&Access.Equal(Code(key,n),code))return n;return -1;}
        internal static string UriFor(string username,byte[] key){return "otpauth://totp/LinkScope:"+Uri.EscapeDataString(username)+"?secret="+Base32(key)+"&issuer=LinkScope&algorithm=SHA1&digits=6&period=30";}
    }
    internal sealed class UserAccounts {
        readonly string path; readonly AdminPasswords legacy; readonly object gate=new object();
        sealed class Pending {internal byte[] Key;internal string Session,Revision;internal long Expires;}
        readonly Dictionary<string,Pending> pending=new Dictionary<string,Pending>(StringComparer.OrdinalIgnoreCase);
        internal UserAccounts(string path,AdminPasswords legacy){this.path=path;this.legacy=legacy;}
        void DropPending(string username){Pending old;if(pending.TryGetValue(username,out old)){pending.Remove(username);Array.Clear(old.Key,0,old.Key.Length);}}
        void SweepPending(){foreach(var name in pending.Where(x=>x.Value.Expires<History.Now()).Select(x=>x.Key).ToArray())DropPending(name);}
        internal static string Normalize(string name){if(name==null||!Regex.IsMatch(name,@"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\z"))return null;return name.ToLowerInvariant();}
        static string Now(){return DateTime.UtcNow.ToString("o",CultureInfo.InvariantCulture);}
        static string Text(string value,int max){value=(value??"").Trim();if(value.Length>max||value.Any(char.IsControl))throw new InvalidDataException("Invalid user information.");return value;}
        static void PasswordRules(string value){if(value==null||value.Length<12)throw new InvalidDataException("Use at least 12 characters, including upper/lowercase letters and a digit.");AdminPasswords.CheckRules(value);}
        static Credential MakePassword(string value,bool temporary){PasswordRules(value);var c=AdminPasswords.Create(value,false);c.MustChange=temporary;return c;}
        static void Touch(ManagedUser u){u.Revision=Access.Secret();u.UpdatedUtc=Now();}
        List<ManagedUser> Read(){
            if(!File.Exists(path))return new List<ManagedUser>{new ManagedUser{Username="admin",Role="Admin",DisplayName="Administrator",Revision="builtin-v1",LastStep=-1}};
            var records=Config.Json().Deserialize<List<ManagedUser>>(File.ReadAllText(path));
            if(records==null||records.Count>128||records.Any(u=>u==null||string.IsNullOrEmpty(u.Username)||Normalize(u.Username)!=u.Username||u.Revision==null||(u.Role!="Admin"&&u.Role!="Viewer")||(u.Username!="admin"&&u.Password==null))||records.Select(u=>u.Username).Distinct().Count()!=records.Count||records.Count(u=>u.Username=="admin"&&u.Role=="Admin")!=1)throw new InvalidDataException("Invalid user database. Host administrator recovery required.");
            return records;
        }
        void Save(List<ManagedUser> records){Config.Save(path,records);}
        static ManagedUser Get(List<ManagedUser> records,string username){return records.FirstOrDefault(x=>x.Username==username);}
        static ManagedUser Required(List<ManagedUser> records,string username){var u=Get(records,username);if(u==null)throw new HttpError(404,"User not found.");return u;}
        bool LegacyOverride(ManagedUser u){return u.Username=="admin"&&u.Password!=null&&u.LegacyRevision!=null&&Access.Equal(u.LegacyRevision,legacy.Revision());}
        string Revision(ManagedUser u){if(u==null)return null;if(u.Username!="admin")return u.Revision;var baseRevision=legacy.Revision();return baseRevision==null?null:baseRevision+":"+u.Revision;}
        internal string Revision(string username){lock(gate)return Revision(Get(Read(),username));}
        static object Public(ManagedUser u){return new {username=u.Username,displayName=u.DisplayName??"",email=u.Email??"",role=u.Role,mfaEnabled=!string.IsNullOrEmpty(u.MfaProtected),passwordChangeRequired=u.Password!=null&&u.Password.MustChange,builtin=u.Username=="admin",createdUtc=u.CreatedUtc,updatedUtc=u.UpdatedUtc};}
        internal object[] List(){lock(gate)return Read().Select(Public).ToArray();}
        internal object Profile(string username){lock(gate)return Public(Required(Read(),username));}
        Credential VerifyPassword(ManagedUser u,string password,string replacement,bool local){
            if(password==null||password.Length>128)return null;
            if(u.Username=="admin"&&!LegacyOverride(u))return legacy.Authenticate("admin",password,replacement,local);
            var c=u.Password;if(c==null)return null;
            return Access.Equal(c.Hash,AdminPasswords.Derive(password,Convert.FromBase64String(c.Salt)))?c:null;
        }
        long Match(ManagedUser u,string otp){if(string.IsNullOrEmpty(u.MfaProtected))return -2;byte[] key=Totp.Unprotect(u.MfaProtected);try{return Totp.Match(key,otp,History.Now(),u.LastStep);}finally{Array.Clear(key,0,key.Length);}}
        internal AccountLogin Authenticate(string username,string password,string replacement,string otp,bool local){
            username=Normalize(username);if(username==null||password==null||password.Length>128)return null;
            lock(gate){var records=Read();var u=Get(records,username);if(u==null){AdminPasswords.Derive(password,new byte[24]);return null;}
                // Legacy first-use is still localhost-only. MFA cannot be enrolled before a permanent password.
                var c=VerifyPassword(u,password,null,local);if(c==null)return null;
                if(!string.IsNullOrEmpty(u.MfaProtected)&&string.IsNullOrEmpty(otp))return new AccountLogin{Username=username,MfaRequired=true};
                long step=Match(u,otp);if(step==-1)return null;
                if(c.MustChange){if(replacement==null)return new AccountLogin{Username=username,ChangeRequired=true};PasswordRules(replacement);if(Access.Equal(password,replacement))throw new InvalidDataException("Choose a different password.");
                    if(username=="admin"&&!LegacyOverride(u)){c=legacy.Authenticate("admin",password,replacement,local);if(c==null||c.MustChange)return null;}
                    else {u.Password=MakePassword(replacement,false);Touch(u);}
                    if(step>=0)u.LastStep=step;Save(records);
                }else if(step>=0){u.LastStep=step;Save(records);}
                return new AccountLogin{Username=username,Role=u.Role,Revision=Revision(u),MfaEnabled=!string.IsNullOrEmpty(u.MfaProtected)};
            }
        }
        internal void Reauthenticate(Session session,string password,string otp){lock(gate){var records=Read();var u=Required(records,session.Username);if(!Access.Equal(Revision(u),session.Revision))throw new HttpError(401,"Sign in again.");
            var c=VerifyPassword(u,password,null,true);long step=c==null?-1:Match(u,otp);if(c==null||c.MustChange||step==-1)throw new HttpError(403,"Current password or authenticator code is incorrect or already used. Wait for a fresh code.");
            if(step>=0){u.LastStep=step;Save(records);}}}
        internal void Manage(Session actor,UserInput input){if(!actor.IsAdmin)throw new HttpError(403,"Administrator required.");string username=Normalize(input.username);if(username==null)throw new InvalidDataException("Use a username of 1–64 letters, digits, dots, underscores or hyphens.");
            lock(gate){var records=Read();if(!Access.Equal(Revision(Required(records,actor.Username)),actor.Revision))throw new HttpError(401,"Sign in again.");var u=Get(records,username);
                if(input.action=="create"){
                    if(u!=null)throw new HttpError(409,"Username already exists.");if(records.Count>=128)throw new HttpError(409,"Maximum 128 users.");
                    if(input.role!="Admin"&&input.role!="Viewer")throw new InvalidDataException("Choose Admin or Viewer.");
                    u=new ManagedUser{Username=username,Role=input.role,DisplayName=Text(input.displayName,120),Email=Text(input.email,254),Password=MakePassword(input.password,true),CreatedUtc=Now(),LastStep=-1};Touch(u);records.Add(u);
                }else{
                    if(u==null)throw new HttpError(404,"User not found.");
                    if(username=="admin"||username==actor.Username)throw new HttpError(403,"Manage your own profile in My account. The built-in admin cannot be modified by other users.");
                    switch(input.action){
                        case "edit":if(input.role!="Admin"&&input.role!="Viewer")throw new InvalidDataException("Choose Admin or Viewer.");u.Role=input.role;u.DisplayName=Text(input.displayName,120);u.Email=Text(input.email,254);Touch(u);break;
                        case "password":u.Password=MakePassword(input.password,true);Touch(u);break;
                        case "reset-mfa":u.MfaProtected=null;u.LastStep=-1;Touch(u);break;
                        case "delete":records.Remove(u);break;
                        default:throw new InvalidDataException("Unknown account action.");
                    }
                }
                DropPending(username);Save(records);
            }
        }
        internal void ChangeOwn(Session actor,UserInput input){lock(gate){var records=Read();var u=Required(records,actor.Username);if(!Access.Equal(Revision(u),actor.Revision))throw new HttpError(401,"Sign in again.");
            if(input.action=="profile"){u.DisplayName=Text(input.displayName,120);u.Email=Text(input.email,254);u.UpdatedUtc=Now();}
            else if(input.action=="password"){if(Access.Equal(input.currentPassword,input.password))throw new InvalidDataException("Choose a different password.");u.Password=MakePassword(input.password,false);if(u.Username=="admin")u.LegacyRevision=legacy.Revision();Touch(u);}
            else if(input.action=="disable-mfa"){u.MfaProtected=null;u.LastStep=-1;Touch(u);}
            else throw new InvalidDataException("Unknown account action.");DropPending(u.Username);Save(records);}}
        internal object BeginMfa(Session actor){lock(gate){var u=Required(Read(),actor.Username);if(!Access.Equal(Revision(u),actor.Revision))throw new HttpError(401,"Sign in again.");if(!string.IsNullOrEmpty(u.MfaProtected))throw new HttpError(409,"MFA is already enabled. Disable it with your current code before re-enrolling.");
            SweepPending();DropPending(u.Username);var key=Totp.NewKey();pending[u.Username]=new Pending{Key=key,Session=actor.Csrf,Revision=actor.Revision,Expires=History.Now()+600};return new {secret=Totp.Base32(key),uri=Totp.UriFor(u.Username,key),expiresSeconds=600};}}
        internal void FinishMfa(Session actor,string code){lock(gate){var records=Read();var u=Required(records,actor.Username);Pending p;if(!pending.TryGetValue(u.Username,out p)||!Access.Equal(p.Session,actor.Csrf)||!Access.Equal(p.Revision,actor.Revision)||!Access.Equal(Revision(u),actor.Revision)||p.Expires<History.Now()||!string.IsNullOrEmpty(u.MfaProtected))throw new HttpError(409,"Enrollment expired. Begin again.");long step=Totp.Match(p.Key,code,History.Now(),-1);if(step<0)throw new HttpError(400,"Authenticator code is invalid.");u.MfaProtected=Totp.Protect(p.Key);u.LastStep=step;Touch(u);Save(records);DropPending(u.Username);}}
        internal void CancelMfa(Session actor){lock(gate){Pending p;if(pending.TryGetValue(actor.Username,out p)&&Access.Equal(p.Session,actor.Csrf)){DropPending(actor.Username);}}}
        // Explicit offline recovery for a Windows administrator; service must be stopped.
        internal void ResetBuiltinMfa(){lock(gate){var records=Read();var u=Required(records,"admin");u.MfaProtected=null;u.LastStep=-1;Touch(u);Save(records);}}
    }
}
