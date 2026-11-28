using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace LinkScope {
    // Main service only. The standalone installer compiles ClamUpdateWorker.cs without this file.
    internal static partial class ClamUpdateWorker {
    [DllImport("kernel32.dll",SetLastError=true)] static extern SafeFileHandle OpenProcess(uint access,bool inherit,uint pid);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(SafeFileHandle process,out long created,out long exited,out long kernel,out long user);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(SafeFileHandle process,out uint code);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageName(SafeFileHandle process,int flags,StringBuilder name,ref int length);
    // Cache is optional. If identity/configuration cannot be verified, scan normally.
    // Never use a VERSION-only key across ClamD restarts or configuration edits.
    internal static string CacheGeneration(WaitHandle stop,bool privileged){
        try{
            uint pid=ClamdPid();if(pid<=4||ServiceImage("clamd")==null||!NativeService("clamd",ClamdExe)||!LoopbackOnly())return null;
            long started;using(var proc=OpenProcess(0x1000,false,pid)){
                long exited,kernel,user;uint exitCode;var image=new StringBuilder(4096);int length=image.Capacity;
                if(proc.IsInvalid||!GetProcessTimes(proc,out started,out exited,out kernel,out user)||!GetExitCodeProcess(proc,out exitCode)||exitCode!=259||!QueryFullProcessImageName(proc,0,image,ref length)||!SamePath(image.ToString(),ClamdExe))return null;
            }
            VerifyClamPath(ClamdConfig);string configHash;
            using(var f=new FileStream(ClamdConfig,FileMode.Open,FileAccess.Read,FileShare.Read)){
                if(f.Length>1048576)return null;EndpointResponse.VerifyHandle(f.SafeFileHandle,ClamdConfig);configHash=EndpointProtection.FileHash(f);
                var cfg=ReadClamConfig(ClamdConfig);if(cfg.Missing||cfg.Sample||!StandardConfig(cfg,false,TextWriter.Null)||!SamePath(cfg.One("DatabaseDirectory"),ClamDatabase)||!string.Equals(cfg.One("AlertExceedsMax"),"yes",StringComparison.OrdinalIgnoreCase))return null;
            }
            // VERSION does not uniquely identify third-party signature feeds.
            // Refuse caching when custom or unrecognized database files are present.
            VerifyClamPath(ClamDatabase);var dbFiles=Directory.EnumerateFileSystemEntries(ClamDatabase).Take(32).ToArray();
            if(dbFiles.Length==0||dbFiles.Length>=32||dbFiles.Any(x=>!Regex.IsMatch(Path.GetFileName(x),@"^(?:(main|daily|bytecode)\.(cvd|cld)|freshclam\.dat|mirrors\.dat)$",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant)||(File.GetAttributes(x)&(FileAttributes.Directory|FileAttributes.ReparsePoint))!=0))return null;
            var definitions=dbFiles.Where(x=>Regex.IsMatch(Path.GetFileName(x),@"^(main|daily|bytecode)\.(cvd|cld)$",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant)).Select(x=>new FileInfo(x)).OrderBy(x=>x.Name,StringComparer.OrdinalIgnoreCase).ToArray();
            foreach(var entry in definitions)VerifyClamPath(entry.FullName);
            if(!definitions.Any(x=>x.Name.StartsWith("main.",StringComparison.OrdinalIgnoreCase))||!definitions.Any(x=>x.Name.StartsWith("daily.",StringComparison.OrdinalIgnoreCase)))return null;
            // A main/bytecode change may not alter the daily version exposed by VERSION.
            // Until a restart proves the engine loaded those definitions, do not cache.
            if(definitions.Any(x=>!x.Name.StartsWith("daily.",StringComparison.OrdinalIgnoreCase)&&x.LastWriteTimeUtc.ToFileTimeUtc()>started))return null;
            string definitionsKey=string.Join("|",definitions.Select(x=>x.Name.ToLowerInvariant()+":"+x.Length.ToString(CultureInfo.InvariantCulture)+":"+x.LastWriteTimeUtc.Ticks.ToString(CultureInfo.InvariantCulture)));
            string version=EndpointProtection.Command(ClamPort,"VERSION",null,stop,privileged?(Action<TcpClient>)VerifyPrivilegedScanPeer:VerifyScanServiceOwner);
            if(!Regex.IsMatch(version??"",@"^ClamAV [^/]+/[0-9]+/[^/]+$")||ClamdPid()!=pid)return null;
            return EndpointProtection.Hash(Encoding.UTF8.GetBytes(pid.ToString(CultureInfo.InvariantCulture)+"|"+started.ToString(CultureInfo.InvariantCulture)+"|"+configHash+"|"+definitionsKey+"|"+version));
        }catch(OperationCanceledException){throw;}catch(Exception){return null;}
    }

    }
}
