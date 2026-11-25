using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace LinkScope {
    public sealed class Credential {
        public string Salt { get; set; }
        public string Hash { get; set; }
        public bool MustChange { get; set; }
        public string EnrollmentId { get; set; }
    }

    internal sealed class AdminPasswords {
        internal const string Starter = "Un1xf0r";
        internal const string Rules = "Use 7–128 characters with at least one A–Z, one a–z and one digit (0–9). Symbols are optional.";
        internal static readonly AdminPasswords Installed = new AdminPasswords(Config.Root, Config.SettingsDir);
        readonly string adminFile, settingsDir;
        readonly object changeGate = new object();

        internal AdminPasswords(string root, string settings) {
            adminFile = Path.Combine(root, "admin.json");
            settingsDir = settings;
        }

        internal static void CheckRules(string password) {
            if (password == null || password.Length < 7 || password.Length > 128 ||
                !password.Any(c => c >= 'A' && c <= 'Z') || !password.Any(c => c >= 'a' && c <= 'z') ||
                !password.Any(c => c >= '0' && c <= '9') || password.Any(char.IsControl))
                throw new InvalidDataException(Rules);
        }

        static string Derive(string password, byte[] salt) {
            using (var hash = new Rfc2898DeriveBytes(password, salt, 600000, HashAlgorithmName.SHA256))
                return Convert.ToBase64String(hash.GetBytes(32));
        }

        static Credential Create(string password, bool starter) {
            CheckRules(password);
            if (!starter && Access.Equal(password, Starter))
                throw new InvalidDataException("Choose a password different from the starter password.");
            byte[] salt = new byte[24];
            using (var random = RandomNumberGenerator.Create()) random.GetBytes(salt);
            return new Credential {Salt = Convert.ToBase64String(salt), Hash = Derive(password, salt), MustChange = starter};
        }

        string EnrollmentPath(string id) {
            Guid valid;
            if (!Guid.TryParseExact(id, "N", out valid)) throw new InvalidDataException("Invalid credential record.");
            return Path.Combine(settingsDir, "admin-" + valid.ToString("N") + ".json");
        }

        // Only the elevated installer creates the reference in the protected root. Existing
        // admin.json verifiers from previous versions remain authoritative and readable as-is.
        internal void Initialize() {
            if (File.Exists(adminFile)) return;
            string id = Guid.NewGuid().ToString("N");
            string slot = EnrollmentPath(id);
            string stage = Path.Combine(Path.GetDirectoryName(adminFile), id + ".tmp");
            bool published = false;
            try {
                Config.Save(slot, Create(Starter, true));
                File.WriteAllText(stage, Config.Json().Serialize(new Credential {EnrollmentId = id}), new UTF8Encoding(false));
                try { File.Move(stage, adminFile); published = true; }
                catch (IOException) { if (!File.Exists(adminFile)) throw; }
            } finally {
                if (File.Exists(stage)) File.Delete(stage);
                if (!published && File.Exists(slot)) File.Delete(slot);
            }
        }

        static Credential ReadFile(string path) {
            using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete))
            using (var reader = new StreamReader(file, Encoding.UTF8))
                return Config.Json().Deserialize<Credential>(reader.ReadToEnd());
        }

        Credential Read(out string slot) {
            slot = null;
            if (!File.Exists(adminFile)) return null;
            var credential = ReadFile(adminFile);
            if (credential.EnrollmentId != null) {
                slot = EnrollmentPath(credential.EnrollmentId);
                credential = ReadFile(slot);
            }
            if (string.IsNullOrEmpty(credential.Salt) || string.IsNullOrEmpty(credential.Hash))
                throw new InvalidDataException("Incomplete credential record. Reset the password on the host.");
            return credential;
        }

        internal string Revision() {
            string ignored;
            var credential = Read(out ignored);
            return credential == null || credential.MustChange ? null : credential.Hash;
        }

        internal void Reset(string password) {
            Config.Save(adminFile, Create(password, false));
        }

        // A starter-password match authorizes only the local first-use change. The caller
        // issues a session exclusively for a completed, permanent credential.
        internal Credential Authenticate(string user, string password, string replacement, bool local) {
            if (user != "admin" || password == null || password.Length > 128) return null;
            string slot;
            var credential = Read(out slot);
            if (credential == null || (credential.MustChange && !local)) return null;
            if (!Access.Equal(credential.Hash, Derive(password, Convert.FromBase64String(credential.Salt)))) return null;
            if (!credential.MustChange || replacement == null) return credential;
            var next = Create(replacement, false);
            lock (changeGate) {
                string currentSlot;
                var current = Read(out currentSlot);
                if (slot == null || currentSlot != slot || current == null || !current.MustChange ||
                    !Access.Equal(current.Hash, credential.Hash)) return null;
                Config.Save(slot, next);
                return next;
            }
        }
    }
}
