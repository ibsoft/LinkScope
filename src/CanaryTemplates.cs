using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;

namespace LinkScope {
    // Compiled into the main application and GUI installer. Fixed, macro-free OOXML
    // and text bytes; no Office installation or internet connection required.
    internal static class CanaryTemplates {
        internal const string FolderName="LinkScope Canary Documents";
        static readonly Dictionary<string,string> templates=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase) {
            {"Reference_Document.docx", "UEsDBBQAAAAIAAAAIVx5bjPX6AAAAK0BAAATAAAAW0NvbnRlbnRfVHlwZXNdLnhtbH1QyU7DMBD9FWuuKHHggBCK0wPLETiUDxjZk8SqN3nc0v49Tlt6QIXjzFv1+tXeO7GjzDYGBbdtB4KCjsaGScHn+rV5AMEFg0EXAyk4EMNq6NeHRCyqNrCCuZT0KCXrmTxyGxOFiowxeyz1zJNMqDc4kbzrunupYygUSlMWDxj6Zxpx64p42df3qUcmxyCeTsQlSwGm5KzGUnG5C+ZXSnNOaKvyyOHZJr6pBJBXExbk74Cz7r0Ok60h8YG5vKGvLPkVs5Em6q2vyvZ/mys94zhaTRf94pZy1MRcF/euvSAebfjpL49zD99QSwMEFAAAAAgAAAAhXJv9N+qtAAAAKQEAAAsAAABfcmVscy8ucmVsc43POw7CMAwG4KtE3mlaBoRQ0y4IqSsqB7ASN61oHkrCo7cnAwNFDIy2f3+W6/ZpZnanECdnBVRFCYysdGqyWsClP232wGJCq3B2lgQsFKFt6jPNmPJKHCcfWTZsFDCm5A+cRzmSwVg4TzZPBhcMplwGzT3KK2ri27Lc8fBpwNpknRIQOlUB6xdP/9huGCZJRydvhmz6ceIrkWUMmpKAhwuKq3e7yCzwpuarF5sXUEsDBBQAAAAIAAAAIVz9Xu//9QAAAHQBAAARAAAAd29yZC9kb2N1bWVudC54bWxtkE1OxDAMha9iZQ1NYYFQ1XY2CLFggfg5QCbxTCMSu3I8lN6edBBCQmyeZUd+34v73WdO8IFSItNgrprWAJLnEOk4mLfX+8tbA0UdBZeYcDArFrMb+6UL7E8ZSaEaUOmWwUyqc2dt8RNmVxqekerbgSU7ra0c7cISZmGPpVT/nOx1297Y7CKZzXLPYd3qvIlsouMzHlBqIoQfYG+3+aZy1vnvymOk9xdf8VDQnyTqCgE9rw08OMmpwqGspBNq9BCcugbuGIgVMES9gIpzGYGlriVUhGWKCSEzRWWpwSGWeiS3Txiaf9NUrj6JPQ++P2V/DzZ+AVBLAQIUAxQAAAAIAAAAIVx5bjPX6AAAAK0BAAATAAAAAAAAAAAAAACAAQAAAABbQ29udGVudF9UeXBlc10ueG1sUEsBAhQDFAAAAAgAAAAhXJv9N+qtAAAAKQEAAAsAAAAAAAAAAAAAAIABGQEAAF9yZWxzLy5yZWxzUEsBAhQDFAAAAAgAAAAhXP1e7//1AAAAdAEAABEAAAAAAAAAAAAAAIAB7wEAAHdvcmQvZG9jdW1lbnQueG1sUEsFBgAAAAADAAMAuQAAABMDAAAAAA=="},
            {"Reference_Inventory.xlsx", "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"},
            {"Reference_Notes.txt", "TGlua1Njb3BlIHNlY3VyaXR5IGRlY295LiBIYXJtbGVzcyBzeW50aGV0aWMgZGF0YS4gRG8gbm90IGVkaXQsIHJlbmFtZSBvciBkZWxldGUgd2hpbGUgbW9uaXRvcmluZyBpcyBlbmFibGVkLg0K"},
        };
        internal static IEnumerable<string> Names {get{return templates.Keys;}}
        internal static byte[] Bytes(string name){return Convert.FromBase64String(templates[name]);}
        internal static string ExpectedHash(string name){using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(Bytes(name))).Replace("-","").ToLowerInvariant();}
        internal static string ExpectedForPath(string path){string parent=Path.GetDirectoryName(path),name=Path.GetFileName(path);return parent!=null&&string.Equals(Path.GetFileName(parent),FolderName,StringComparison.OrdinalIgnoreCase)&&templates.ContainsKey(name)?ExpectedHash(name):null;}
        internal static string HashFile(string path){using(var sha=SHA256.Create())using(var f=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read))return BitConverter.ToString(sha.ComputeHash(f)).Replace("-","").ToLowerInvariant();}
        internal static SecurityIdentifier ServiceSid(){using(var sha=SHA1.Create()){var hash=sha.ComputeHash(Encoding.Unicode.GetBytes("LINKSCOPE"));var parts=new string[5];for(int i=0;i<5;i++)parts[i]=BitConverter.ToUInt32(hash,i*4).ToString(System.Globalization.CultureInfo.InvariantCulture);return new SecurityIdentifier("S-1-5-80-"+string.Join("-",parts));}}
        static string RegistryPath(string sid){return @"SOFTWARE\IBSoft\LinkScope\SetupCanaries\"+new SecurityIdentifier(sid).Value;}
        internal static bool Registered(string sid){using(var k=Registry.LocalMachine.OpenSubKey(RegistryPath(sid)))return k!=null&&k.GetValue("Folder") is string;}
        internal static void Register(string sid,string folder){using(var k=Registry.LocalMachine.CreateSubKey(RegistryPath(sid)))k.SetValue("Folder",folder,RegistryValueKind.String);}
        internal static string UserFolder(){string docs=Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);if(string.IsNullOrWhiteSpace(docs))throw new IOException("Documents folder unavailable.");return Path.Combine(docs,FolderName);}
        internal static void CheckLocal(string path){if(string.IsNullOrWhiteSpace(path)||path.Length<3||path[1]!=':'||path[2]!='\\'||!string.Equals(Path.GetFullPath(path),path,StringComparison.OrdinalIgnoreCase)||path.Substring(2).Contains(":"))throw new IOException("Use a local absolute Documents folder.");for(string q=path;!string.IsNullOrEmpty(q);q=Path.GetDirectoryName(q))if((File.GetAttributes(q)&FileAttributes.ReparsePoint)!=0)throw new IOException("Redirected/reparse folders require manual canary enrollment.");}
        internal static void Verify(string folder){CheckLocal(folder);if(!string.Equals(Path.GetFileName(folder),FolderName,StringComparison.Ordinal))throw new IOException("Invalid canary folder.");foreach(var name in Names){string path=Path.Combine(folder,name);CheckLocal(path);if(new FileInfo(path).Length!=Bytes(name).Length||HashFile(path)!=ExpectedHash(name))throw new IOException("Existing canary does not match the embedded original: "+name+". No file will be replaced.");}}
        // Run in the wizard's original user context. Never write using alternate UAC credentials.
        static void AllowParentMetadata(string folder){
            string profile=Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if(string.IsNullOrWhiteSpace(profile))throw new IOException("User profile folder unavailable.");
            profile=Path.GetFullPath(profile).TrimEnd('\\');
            for(string q=Path.GetDirectoryName(folder);q!=null&&(string.Equals(q,profile,StringComparison.OrdinalIgnoreCase)||q.StartsWith(profile+"\\",StringComparison.OrdinalIgnoreCase));q=Path.GetDirectoryName(q)){
                CheckLocal(q);var dir=new DirectoryInfo(q);var acl=dir.GetAccessControl();
                // This object only: no inheritance, no ReadData/ListDirectory, no write rights.
                acl.AddAccessRule(new FileSystemAccessRule(ServiceSid(),FileSystemRights.Traverse|FileSystemRights.ReadAttributes,InheritanceFlags.None,PropagationFlags.None,AccessControlType.Allow));dir.SetAccessControl(acl);
            }
        }
        internal static int Prepare(){using(var user=WindowsIdentity.GetCurrent()){
            if(Registered(user.User.Value))return 12;
            if(new WindowsPrincipal(user).IsInRole(WindowsBuiltInRole.Administrator))throw new IOException("Open LinkScope Setup normally (not Run as administrator) to create canaries in your own Documents. Setup will request elevation only for service installation and enrollment."); // Never recreate a deleted enrolled decoy on upgrade.
            string folder=UserFolder();CheckLocal(Path.GetDirectoryName(folder));
            if(Directory.Exists(folder)){Verify(folder);AllowParentMetadata(folder);return 0;} // retry intact, unregistered files only
            var sec=new DirectorySecurity();sec.SetAccessRuleProtection(true,false);
            var inherit=InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit;
            foreach(var sid in new[]{user.User,new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null),new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null)})sec.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,inherit,PropagationFlags.None,AccessControlType.Allow));
            sec.AddAccessRule(new FileSystemAccessRule(ServiceSid(),FileSystemRights.ReadAndExecute,inherit,PropagationFlags.None,AccessControlType.Allow));
            // Directory.CreateDirectory may return an existing directory in a race. Never change its ACL or overwrite files.
            Directory.CreateDirectory(folder,sec);CheckLocal(folder);
            foreach(var name in Names){using(var f=new FileStream(Path.Combine(folder,name),FileMode.CreateNew,FileAccess.Write,FileShare.None)){var b=Bytes(name);f.Write(b,0,b.Length);f.Flush(true);}}
            Verify(folder);AllowParentMetadata(folder);return 0;
        }}
    }
}
