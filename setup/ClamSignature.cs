using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
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

    static void RequireTalosSignature(string output) {
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
        if(!new[]{"8","9","10"}.Contains(valid[8])||valid[9]!="00")throw new InvalidDataException("Expected a binary document signature using SHA-256, SHA-384 or SHA-512.");
    }

    static void VerifyClamPackage(string stage,string package,TextWriter log) {
        if(!File.Exists(MsiSignaturePath))throw new FileNotFoundException("Missing deploy\\clamav-latest.msi.sig. Download the matching official release signature and place it beside the MSI.");
        string signature=Path.Combine(stage,"clamav-latest.msi.sig");
        using(var input=new FileStream(MsiSignaturePath,FileMode.Open,FileAccess.Read,FileShare.Read)) {
            if(input.Length<1||input.Length>65536)throw new InvalidDataException("Invalid detached signature file size.");
            using(var dest=new FileStream(signature,FileMode.CreateNew,FileAccess.Write,FileShare.None))input.CopyTo(dest);
        }
        string gpg=FindTrustedGpg();
        string home=Path.Combine(stage,"gnupg");SecureDirectory(home);
        string key=Path.Combine(stage,"cisco-talos.gpg");
        using(var source=Resource("cisco-talos.gpg"))using(var dest=new FileStream(key,FileMode.CreateNew,FileAccess.Write,FileShare.None))source.CopyTo(dest);
        log.WriteLine("Verifying detached OpenPGP signature with "+gpg+"; expected primary fingerprint: "+TalosFingerprint);log.Flush();
        GpgCommand(gpg,home,"--import \""+key+"\"",log);
        string result=GpgCommand(gpg,home,"--verify \""+signature+"\" \""+package+"\"",log);
        RequireTalosSignature(result);
        log.WriteLine("PASS: detached OpenPGP release signature authenticated against pinned Cisco Talos key.");log.Flush();
    }
}
