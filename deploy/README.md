# Optional ClamAV Windows prerequisite

Download the official **Windows x64** MSI and the corresponding detached OpenPGP signature from https://www.clamav.net/downloads. Rename the pair:

- `clamav-latest.msi`
- `clamav-latest.msi.sig`

Install trusted Gpg4win/GnuPG system-wide from https://www.gpg4win.org/ (standard Program Files or Program Files (x86) installation). The setup uses that verifier offline, with an isolated keyring and the embedded Cisco Talos public key. It displays the verified signer fingerprint and SHA-256 of the staged MSI, then requests administrator confirmation. Missing or incorrect signatures, untrusted signers, and unavailable verification tools block MSI execution. No MSI, GnuPG binaries or signature file are bundled or downloaded automatically. The signature proves authenticity of the exact MSI, not that it is the newest release or appropriate for your architecture.

Build.cmd uses this folder alongside the root setup executable. Visual Studio builds copy both optional files to `bin\Debug\deploy` or `bin\Release\deploy` beside `LinkScopeSetup.exe`. Distribute the setup EXE and matching pair together. Remove stale output files manually when replacing or withdrawing a package.

Setup distinguishes missing, incomplete, configured, running and responding ClamAV states. Standard x64 installations can be provisioned or repaired from the wizard without reinstalling LinkScope. Existing incompatible/custom configurations are preserved and require manual review; arbitrary portable installations may not be detected.

The installer uses Windows Installer with quiet UI, logging, and no automatic restart. If Windows reports a reboot is required, schedule it separately. After MSI installation, setup offers automatic standard ClamD/FreshClam configuration, initial official signatures, automatic service startup and local readiness verification. Approved existing third-party feeds are preserved, not added automatically. Internet access (or pre-provisioned definitions) is needed. See [CLAMAV-SETUP.md](../CLAMAV-SETUP.md). Endpoint Protection and automatic response modes are not enabled by setup. Uninstalling LinkScope does not uninstall ClamAV.
