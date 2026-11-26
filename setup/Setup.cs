using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Windows.Forms;

internal static class Setup {
    static Stream Resource(string name) {
        Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream(name);
        if (s == null) throw new InvalidOperationException("Missing installer resource: " + name);
        return s;
    }
    static int Wizard() {
        string script;
        using (var reader = new StreamReader(Resource("wizard.ps1"))) script = reader.ReadToEnd();
        string ps = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
        var start = new ProcessStartInfo(ps, "-NoLogo -NoProfile -NonInteractive -STA -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(script)));
        start.UseShellExecute = false;
        start.CreateNoWindow = true;
        start.EnvironmentVariables["LINKSCOPE_SETUP_EXE"] = Assembly.GetExecutingAssembly().Location;
        using (var child = Process.Start(start)) { child.WaitForExit(); return child.ExitCode; }
    }
    static int Execute(string verb) {
        using (var identity = WindowsIdentity.GetCurrent()) {
            if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) {
                Console.Error.WriteLine("Run this operation from an elevated Administrator terminal, or open the setup wizard.");
                return 1;
            }
        }
        string stage = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "LinkScope-setup-" + Guid.NewGuid().ToString("N"));
        var acl = new DirectorySecurity();
        acl.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { WellKnownSidType.BuiltinAdministratorsSid, WellKnownSidType.LocalSystemSid }) {
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        }
        Directory.CreateDirectory(stage, acl);
        string exe = Path.Combine(stage, "LinkScope.exe");
        try {
            using (var input = Resource("LinkScope.exe"))
            using (var output = new FileStream(exe, FileMode.CreateNew, FileAccess.Write, FileShare.None)) input.CopyTo(output);
            var start = new ProcessStartInfo(exe, verb) { UseShellExecute = false, WorkingDirectory = stage };
            using (var child = Process.Start(start)) { child.WaitForExit(); return child.ExitCode; }
        } finally {
            try { File.Delete(exe); Directory.Delete(stage); }
            catch (Exception ex) { Console.Error.WriteLine("Could not clean installer staging directory: " + ex.Message); }
        }
    }
    [STAThread]
    static int Main(string[] args) {
        try {
            if (args.Length == 0) return Wizard();
            if (args.Length == 1) {
                string verb = args[0].ToLowerInvariant();
                if (verb == "-install") verb = "--install";
                if (verb == "--install" || verb == "--upgrade" || verb == "--uninstall") return Execute(verb);
            }
            Console.Error.WriteLine("Usage: LinkScopeSetup.exe [--install | --upgrade | --uninstall]");
            return 2;
        } catch (Exception ex) {
            Console.Error.WriteLine(ex);
            if (args.Length == 0) MessageBox.Show(ex.Message, "LinkScope Setup", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }
}
