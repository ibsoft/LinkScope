using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace LinkScope {
    public sealed class ControlReading {public string control {get;set;}public string state {get;set;}public string detail {get;set;}}
    public sealed class PostureSnapshot {public string scannedUtc {get;set;}public ControlReading[] items {get;set;}}
    internal static class SecurityPosture {
        static readonly string Cache=Path.Combine(Config.Root,"security.json");
        internal static readonly string[] Controls={"UAC","Secure Boot","TPM","BitLocker"};
        internal static void Capture(){
            var start=Telemetry.PowerShell(Encoding.UTF8.GetString(Program.Resource("security.ps1")));
            using(var process=Process.Start(start)){
                var stdout=process.StandardOutput.ReadToEndAsync();var stderr=process.StandardError.ReadToEndAsync();
                if(!process.WaitForExit(45000)){process.Kill();throw new TimeoutException("Security check timed out.");}
                if(process.ExitCode!=0||!stdout.Wait(2000)||!stderr.Wait(2000)||stdout.Result.Length>12000)throw new InvalidDataException("Security provider did not return a snapshot.");
                var snap=Config.Json().Deserialize<PostureSnapshot>(stdout.Result);
                if(!Valid(snap))throw new InvalidDataException("Incomplete security posture snapshot.");
                Config.Save(Cache,snap);
            }
        }
        static bool Valid(PostureSnapshot s){
            return s!=null&&s.items!=null&&s.items.Length==Controls.Length&&s.items.All(x=>x!=null&&Controls.Contains(x.control)&&new[]{"enabled","disabled","unavailable"}.Contains(x.state))
                &&s.items.Select(x=>x.control).Distinct().Count()==Controls.Length;
        }
        internal static object Read(){
            PostureSnapshot s=null;DateTimeOffset when=DateTimeOffset.MinValue;
            try{var file=new FileInfo(Cache);if(file.Exists&&file.Length<=24000)s=Config.Json().Deserialize<PostureSnapshot>(File.ReadAllText(Cache));}
            catch(IOException){}catch(UnauthorizedAccessException){}catch(ArgumentException){}catch(InvalidOperationException){}catch(FormatException){}
            if(!Valid(s)||!DateTimeOffset.TryParse(s.scannedUtc,CultureInfo.InvariantCulture,DateTimeStyles.AssumeUniversal,out when)||
                when>DateTimeOffset.UtcNow.AddMinutes(1)||when<DateTimeOffset.UtcNow.AddMinutes(-15))
                return new {status="unavailable",items=Controls.Select(key=>new {control=key,state="unavailable",detail="No current security scan. Check the scheduled hardware task."}).ToArray()};
            int gaps=s.items.Count(x=>x.state=="unavailable");
            return new {status=gaps==s.items.Length?"unavailable":gaps>0?"partial":"ok",scannedUtc=s.scannedUtc,items=s.items};
        }
    }
}
