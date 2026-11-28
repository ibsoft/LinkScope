using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Web.Script.Serialization;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using System.Threading.Tasks;

internal static partial class Setup {
    // Official release key linked by https://docs.clamav.net/manual/Installing.html.
    // A new vendor signing key requires a reviewed setup source update, never trust a key beside the MSI.
    const string TalosFingerprint="5BADCA2665EF59DCF8A23D8B707F0DB480836771";
    const int ClamSignatureRejected=10;
    static readonly string MsiSignaturePath=MsiPath+".sig";

    static string FindTrustedGpg() {
        // Only use a separately installed, administrator-managed GnuPG. Never execute a tool from deploy, PATH or a user profile.
        foreach(string root in new[]{ProgramFiles,Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)}) {
            if(String.IsNullOrEmpty(root))continue;
            foreach(string relative in new[]{@"GnuPG\bin\gpg.exe",@"Gpg4win\bin\gpg.exe"}) {
                string candidate=Path.Combine(root,relative);
                if(!File.Exists(candidate))continue;
                VerifyClamPath(root);
                VerifyClamTree(Path.Combine(root,relative.Split('\\')[0]));
                return candidate;
            }
        }
        throw new IOException("Trusted GnuPG not found. Install Gpg4win from https://www.gpg4win.org/ in its standard Program Files location, then retry. No MSI was executed.");
    }

    static string GpgCommand(string exe,string home,string arguments,TextWriter log) {
        var start=new ProcessStartInfo(exe,"--no-options --homedir \""+home+"\" --batch --no-tty --no-autostart --no-auto-key-retrieve --no-auto-key-import --auto-key-locate clear --status-fd 1 "+arguments) {
            UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=Path.GetDirectoryName(exe),RedirectStandardOutput=true,RedirectStandardError=true
        };
        // Override inherited GnuPG home; don't search for executables in the deployment directory.
        start.EnvironmentVariables["GNUPGHOME"]=home;
        start.EnvironmentVariables["PATH"]=Path.GetDirectoryName(exe)+";"+Environment.SystemDirectory+";"+Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        using(var child=Process.Start(start)) {
            var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();
            if(!child.WaitForExit(120000)) {
                try{child.Kill();child.WaitForExit(5000);}catch(Exception){}
                throw new System.TimeoutException("GnuPG verification exceeded its time limit.");
            }
            if(!Task.WaitAll(new Task[]{stdout,stderr},10000))throw new IOException("GnuPG output did not close.");
            log.WriteLine(stdout.Result);log.WriteLine(stderr.Result);log.WriteLine("GnuPG exit code: "+child.ExitCode);log.Flush();
            if(child.ExitCode!=0)throw new InvalidDataException("GnuPG rejected the signature or key (exit "+child.ExitCode+").");
            return stdout.Result;
        }
    }

    static string RequireTalosSignature(string output) {
        // Parse machine-readable status records, not translated human text or a claimed signer name.
        string[][] records=output.Split(new[]{'\r','\n'},StringSplitOptions.RemoveEmptyEntries)
            .Where(line=>line.StartsWith("[GNUPG:] ",StringComparison.Ordinal))
            .Select(line=>line.Substring(9).Split(new[]{' '},StringSplitOptions.RemoveEmptyEntries)).Where(parts=>parts.Length>0).ToArray();
        string[] rejected={"BADSIG","ERRSIG","NO_PUBKEY","EXPSIG","EXPKEYSIG","REVKEYSIG","KEYEXPIRED","SIGEXPIRED","KEYREVOKED","NODATA","FAILURE","ERROR","BADARMOR","UNEXPECTED"};
        if(records.Any(r=>rejected.Contains(r[0],StringComparer.Ordinal)))throw new InvalidDataException("GnuPG reported an invalid, expired, revoked or unsupported signature.");
        var signatures=records.Where(r=>r[0]=="VALIDSIG").ToArray();
        if(signatures.Length!=1||records.Count(r=>r[0]=="GOODSIG")!=1)throw new InvalidDataException("Expected exactly one valid release signature.");
        // VALIDSIG <signing fingerprint> <date> <timestamp> <expiry> <version> <reserved> <pk algo> <hash algo> <sig class> [primary fingerprint]
        var valid=signatures[0];
        if(valid.Length<10)throw new InvalidDataException("Incomplete GnuPG signature status.");
        string primary=valid.Length>=11?valid[10]:valid[1];
        if(!String.Equals(primary,TalosFingerprint,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("The signature is not from the pinned Cisco Talos release key.");
        // OpenPGP hash IDs: SHA-256=8, SHA-384=9, SHA-512=10, SHA-224=11.
        // SHA-224 is a SHA-2 algorithm, not SHA-1. Retain binary-document enforcement.
        if(valid[9]!="00")throw new InvalidDataException("Expected a binary document signature (class 00); GnuPG reported class "+valid[9]+". Download the matching official MSI and detached signature.");
        if(!new[]{"2","8","9","10","11"}.Contains(valid[8]))throw new InvalidDataException("Unsupported OpenPGP hash algorithm ID "+valid[8]+".");
        return valid[8];
    }

    // A SHA-1 signature is never sufficient by itself. Match the exact staged bytes
    // against the SHA-256 digest published by the official Cisco-Talos GitHub repository.
    static void RequireOfficialReleaseDigest(string package,TextWriter log) {
        string hash;
        using(var sha=SHA256.Create())using(var stream=File.OpenRead(package))hash=BitConverter.ToString(sha.ComputeHash(stream)).Replace("-","");
        string url="https://api.github.com/repos/Cisco-Talos/clamav/releases?per_page=20";
        try {
            var request=(HttpWebRequest)WebRequest.Create(url);
            request.Method="GET";request.UserAgent="LinkScope-Setup/4";request.Accept="application/vnd.github+json";
            request.Timeout=15000;request.ReadWriteTimeout=15000;request.AllowAutoRedirect=false;
            using(var response=(HttpWebResponse)request.GetResponse()) {
                if(response.StatusCode!=HttpStatusCode.OK)throw new IOException("GitHub returned "+response.StatusCode);
                using(var stream=response.GetResponseStream())using(var reader=new StreamReader(stream)) {
                    var data=new System.Text.StringBuilder();var buffer=new char[4096];int read;
                    while((read=reader.Read(buffer,0,buffer.Length))>0){data.Append(buffer,0,read);if(data.Length>8000000)throw new IOException("Release metadata too large.");}
                    var serializer=new JavaScriptSerializer{MaxJsonLength=8000000,RecursionLimit=64};
                    var releases=serializer.DeserializeObject(data.ToString()) as object[];
                    if(releases==null)throw new IOException("Unexpected release metadata.");
                    foreach(var item in releases) {
                        var release=item as Dictionary<string,object>;object assets,draft;
                        if(release==null||!release.TryGetValue("draft",out draft)||!(draft is bool)||(bool)draft||!release.TryGetValue("assets",out assets))continue;
                        var list=assets as object[];if(list==null)continue;
                        foreach(var entry in list) {
                            var asset=entry as Dictionary<string,object>;object name,digest;
                            if(asset==null||!asset.TryGetValue("name",out name)||!asset.TryGetValue("digest",out digest))continue;
                            string file=name as string;string value=digest as string;
                            if(file==null||!Regex.IsMatch(file,@"^clamav-[0-9][0-9A-Za-z.\-]*\.win\.x64\.msi$",RegexOptions.CultureInvariant)||value==null)continue;
                            if(String.Equals(value,"sha256:"+hash,StringComparison.OrdinalIgnoreCase)) {
                                log.WriteLine("PASS: official Cisco-Talos release asset SHA-256 matched: "+file+" ("+hash+")");log.Flush();return;
                            }
                        }
                    }
                }
            }
            log.WriteLine("No matching official x64 MSI SHA-256 digest in the 20 most recent releases.");
        }catch(Exception ex){log.WriteLine("Official release digest lookup failed: "+ex.Message);}
        log.Flush();
        // Offline fallback: administrator must independently obtain a trusted digest.
        using(var form=new Form{Text="LinkScope Setup | Independent SHA-256 verification",Width=710,Height=245,StartPosition=FormStartPosition.CenterScreen,FormBorderStyle=FormBorderStyle.FixedDialog,MaximizeBox=false,MinimizeBox=false}) {
            var label=new Label{Left=15,Top=15,Width=665,Height=90,Text="The Talos signature is valid but uses SHA-1. Automatic official SHA-256 lookup did not succeed. Obtain the expected SHA-256 independently from the official Cisco-Talos release metadata or your trusted release administrator. Do not copy the hash from this local MSI or its setup log. Paste the trusted digest below."};
            var input=new TextBox{Left=15,Top=110,Width=665,MaxLength=71};
            var ok=new Button{Text="Verify digest",Left=440,Top=150,Width=115,DialogResult=DialogResult.OK};
            var cancel=new Button{Text="Cancel",Left=565,Top=150,Width=115,DialogResult=DialogResult.Cancel};
            form.Controls.AddRange(new Control[]{label,input,ok,cancel});form.AcceptButton=ok;form.CancelButton=cancel;
            if(form.ShowDialog()!=DialogResult.OK)throw new InvalidDataException("Independent SHA-256 verification cancelled. No MSI was executed.");
            string expected=input.Text.Trim();if(expected.StartsWith("sha256:",StringComparison.OrdinalIgnoreCase))expected=expected.Substring(7);
            if(!Regex.IsMatch(expected,@"\A[0-9a-fA-F]{64}\z")||!String.Equals(expected,hash,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Independent SHA-256 digest does not match the staged MSI.");
            log.WriteLine("PASS: administrator-supplied independent SHA-256 matched the staged MSI.");log.Flush();
        }
    }

    // Online acquisition is only available to the explicitly selected automatic workflow.
    // Metadata and asset locations are fixed to Cisco-Talos' official repository; TLS defaults remain intact.
    static HttpWebRequest ClamDownloadRequest(Uri uri) {
        var request=(HttpWebRequest)WebRequest.Create(uri);
        request.UserAgent="LinkScope-Setup/69";request.AllowAutoRedirect=false;
        request.Timeout=30000;request.ReadWriteTimeout=30000;return request;
    }
    static bool AllowedClamAssetUri(Uri uri) {
        if(uri==null||!uri.IsAbsoluteUri||uri.Scheme!="https"||!uri.IsDefaultPort||uri.UserInfo.Length!=0||uri.Fragment.Length!=0)return false;
        if(uri.Host.Equals("github.com",StringComparison.OrdinalIgnoreCase))return uri.AbsolutePath.StartsWith("/Cisco-Talos/clamav/releases/download/",StringComparison.Ordinal);
        return uri.Host.Equals("release-assets.githubusercontent.com",StringComparison.OrdinalIgnoreCase)||uri.Host.Equals("objects.githubusercontent.com",StringComparison.OrdinalIgnoreCase);
    }
    static Dictionary<string,object> ClamReleaseAsset(object[] assets,string name) {
        var matches=assets.OfType<Dictionary<string,object>>().Where(x=>x.ContainsKey("name")&&String.Equals(x["name"] as string,name,StringComparison.Ordinal)).ToArray();
        if(matches.Length!=1)throw new InvalidDataException("Missing or ambiguous official release asset: "+name);
        return matches[0];
    }
    static void DownloadClamAsset(Dictionary<string,object> asset,string dest,long limit,bool requireDigest,TextWriter log) {
        object u,n,d;Uri uri;
        if(!asset.TryGetValue("browser_download_url",out u)||!Uri.TryCreate(u as string,UriKind.Absolute,out uri)||!AllowedClamAssetUri(uri)||!uri.Host.Equals("github.com",StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Untrusted official asset URL.");
        long expected;if(!asset.TryGetValue("size",out n)||!Int64.TryParse(Convert.ToString(n,System.Globalization.CultureInfo.InvariantCulture),out expected)||expected<1||expected>limit)throw new InvalidDataException("Invalid official asset size.");
        string digest=asset.TryGetValue("digest",out d)?d as string:null;
        if(requireDigest&&!Regex.IsMatch(digest??"",@"\Asha256:[0-9a-fA-F]{64}\z"))throw new InvalidDataException("Official MSI SHA-256 metadata unavailable. Use a verified offline package instead.");
        var clock=Stopwatch.StartNew();
        for(int hop=0;hop<5;hop++) {
            if(!AllowedClamAssetUri(uri))throw new InvalidDataException("Blocked release download redirect.");
            using(var response=(HttpWebResponse)ClamDownloadRequest(uri).GetResponse()) {
                int status=(int)response.StatusCode;
                if(status==301||status==302||status==303||status==307||status==308) {
                    Uri next;if(!Uri.TryCreate(uri,response.Headers["Location"],out next))throw new IOException("Invalid download redirect.");uri=next;continue;
                }
                if(status!=200||(response.ContentLength>=0&&response.ContentLength!=expected))throw new IOException("Unexpected asset response length or status.");
                using(var input=response.GetResponseStream())using(var output=new FileStream(dest,FileMode.CreateNew,FileAccess.Write,FileShare.None)) {
                    long total=0;byte[] buffer=new byte[65536];int read;
                    while((read=input.Read(buffer,0,buffer.Length))>0){total+=read;if(total>expected||clock.Elapsed>TimeSpan.FromMinutes(15))throw new IOException("Asset download exceeded its bound.");output.Write(buffer,0,read);}
                    if(total!=expected)throw new IOException("Incomplete official asset download.");output.Flush(true);
                }
                if(!String.IsNullOrEmpty(digest)) {
                    string actual;using(var sha=SHA256.Create())using(var stream=File.OpenRead(dest))actual="sha256:"+BitConverter.ToString(sha.ComputeHash(stream)).Replace("-","");
                    if(!String.Equals(actual,digest,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Official release asset digest mismatch.");
                }
                log.WriteLine("Official release asset staged: "+Path.GetFileName(dest)+" ("+expected+" bytes)");log.Flush();return;
            }
        }
        throw new IOException("Too many official release redirects.");
    }
    static void DownloadOfficialClamPair(string stage,TextWriter log) {
        var request=ClamDownloadRequest(new Uri("https://api.github.com/repos/Cisco-Talos/clamav/releases/latest"));request.Accept="application/vnd.github+json";
        Dictionary<string,object> release;
        using(var response=(HttpWebResponse)request.GetResponse())using(var reader=new StreamReader(response.GetResponseStream())) {
            if(response.StatusCode!=HttpStatusCode.OK)throw new IOException("Official release metadata unavailable.");
            var text=new System.Text.StringBuilder();char[] buffer=new char[4096];int read;var clock=Stopwatch.StartNew();
            while((read=reader.Read(buffer,0,buffer.Length))>0){text.Append(buffer,0,read);if(text.Length>2000000||clock.Elapsed>TimeSpan.FromSeconds(60))throw new IOException("Release metadata exceeded its bound.");}
            release=new JavaScriptSerializer{MaxJsonLength=2000000,RecursionLimit=32}.DeserializeObject(text.ToString()) as Dictionary<string,object>;
        }
        object draft,pre,raw;
        if(release==null||!release.TryGetValue("draft",out draft)||!Object.Equals(draft,false)||!release.TryGetValue("prerelease",out pre)||!Object.Equals(pre,false)||!release.TryGetValue("assets",out raw))throw new InvalidDataException("Expected a published stable ClamAV release.");
        var assets=raw as object[];if(assets==null)throw new InvalidDataException("Missing official release assets.");
        var names=assets.OfType<Dictionary<string,object>>().Where(x=>x.ContainsKey("name")).Select(x=>x["name"] as string).Where(x=>x!=null&&Regex.IsMatch(x,@"\Aclamav-[0-9]+\.[0-9]+\.[0-9]+\.win\.x64\.msi\z")).ToArray();
        if(names.Length!=1)throw new InvalidDataException("Expected exactly one stable x64 MSI in the official release.");
        log.WriteLine("Selected official stable release asset: "+names[0]);log.Flush();
        var msi=ClamReleaseAsset(assets,names[0]);var signature=ClamReleaseAsset(assets,names[0]+".sig");
        DownloadClamAsset(signature,Path.Combine(stage,"clamav-latest.msi.sig"),65536,false,log);
        DownloadClamAsset(msi,Path.Combine(stage,"clamav-latest.msi"),512L*1024*1024,true,log);
    }

    static void VerifyClamPackage(string stage,string package,TextWriter log) {
        string signature=Path.Combine(stage,"clamav-latest.msi.sig");
        if(!File.Exists(signature)) {
            if(!File.Exists(MsiSignaturePath))throw new FileNotFoundException("Missing matching detached signature.");
            using(var input=new FileStream(MsiSignaturePath,FileMode.Open,FileAccess.Read,FileShare.Read)) {
                if(input.Length<1||input.Length>65536)throw new InvalidDataException("Invalid detached signature file size.");
                using(var dest=new FileStream(signature,FileMode.CreateNew,FileAccess.Write,FileShare.None))input.CopyTo(dest);
            }
        }
        if(new FileInfo(signature).Length<1||new FileInfo(signature).Length>65536)throw new InvalidDataException("Invalid staged signature size.");
        string gpg=FindTrustedGpg();
        string home=Path.Combine(stage,"gnupg");SecureDirectory(home);
        string key=Path.Combine(stage,"cisco-talos.gpg");
        using(var source=Resource("cisco-talos.gpg"))using(var dest=new FileStream(key,FileMode.CreateNew,FileAccess.Write,FileShare.None))source.CopyTo(dest);
        log.WriteLine("Verifying detached OpenPGP signature with "+gpg+"; expected primary fingerprint: "+TalosFingerprint);log.Flush();
        GpgCommand(gpg,home,"--import \""+key+"\"",log);
        string result=GpgCommand(gpg,home,"--verify \""+signature+"\" \""+package+"\"",log);
        string algorithm=RequireTalosSignature(result);
        if(algorithm=="2") {
            log.WriteLine("Legacy SHA-1 Talos signature: independent SHA-256 required.");log.Flush();
            RequireOfficialReleaseDigest(package,log);
        }
        log.WriteLine("PASS: detached OpenPGP release signature authenticated against pinned Cisco Talos key.");log.Flush();
    }
}
