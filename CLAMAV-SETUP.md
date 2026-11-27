# ClamAV setup and removal

Build the current managed x64 installer on Windows with `Build-VisualStudio.cmd Release` or `Build.cmd`. The old native bootstrap is retired.

In the wizard select **Uninstall ClamAV** and confirm the elevated prompt. Alternatively run `LinkScopeSetup.exe --uninstall-clamav` in an elevated terminal. This stops services registered against the standard ClamAV clamd.exe and freshclam.exe paths, removes registered ClamAV MSI products through Windows Installer, and deletes verified remaining native service registrations. Other applications may depend on the engine. LinkScope itself remains installed. Nonstandard/portable installations, unrelated services and remaining data/configuration files are not manually deleted. MSI itself may remove files. A restart may be needed. Logs are in `%ProgramFiles%\LinkScope Setup Logs`.

If removal fails, review the logs before retrying; services may already be stopped. Custom service wrappers or nonstandard install paths require manual review.

### Recovery after an uninstall (revision 2)

Configuration and database files left by MSI removal do not by themselves mean the engine is installed. A remaining executable, service registration or uninstall registration is an incomplete installation. The wizard offers signed-MSI repair for this state; custom installations are still protected from automatic takeover. Check again requests elevation and records diagnostics under `C:\Program Files\LinkScope Setup Logs`. Wizard UI exceptions are reported and logged in `%TEMP%\LinkScope-Wizard-errors.log`. The readiness wait pumps UI messages with action buttons disabled and a 25-second deadline after child launch. A UAC prompt can still require user interaction. This revision has static tests only; Windows 11 runtime validation is required.

### Signature verification compatibility (V4)

Binary SHA-2 signatures remain accepted with a successful GnuPG result and the pinned Talos primary fingerprint. A binary SHA-1 signature (OpenPGP ID 2) additionally requires an independent SHA-256 match against the official Cisco-Talos GitHub release asset digest. Setup checks the 20 most recent releases using HTTPS and does not download the MSI. If the digest is unavailable, an administrator may enter an independently obtained trusted SHA-256 digest; cancellation or mismatch blocks installation. Never use the local file's own hash as the expected digest. MD5, invalid signatures and wrong signers remain blocked. GnuPG's own policy is not overridden. Windows runtime and actual vendor MSI were not tested.


### V5 wizard responsiveness
Readiness checks use a separate Windows Forms timer and a 25-second deadline rather than a nested DoEvents loop. Operation completion and optional LinkScope continuation occur after the readiness result. Closing during a read-only readiness check cancels that check; active maintenance is not interrupted. Windows runtime validation remains required.

### V6 wizard canary recovery
Canary preparation runs in a separate noninteractive process, polled by a UI timer with a 30-second deadline. Close cancels preparation. Failure offers installation without new canaries; existing canaries are not overwritten. Details: `%TEMP%\LinkScope-Canary-errors.log`. Redirected Documents, modified existing canaries and elevated user context remain intentionally restricted. Windows runtime verification is required.


### V7 diagnostics and canary preparation

Launch Setup normally (not as administrator). The canary worker uses direct process execution with an explicit asInvoker manifest; service installation alone requests elevation. Canary creation remains selected after a failure, rather than silently skipping protection. The wizard uses the existing multi-resolution linkscope.ico in its title and header. Open debug log opens `%TEMP%\LinkScope-Setup-debug.log`, which records process IDs, readiness results, worker exit codes and canary file/ACL steps. `%TEMP%\LinkScope-Canary-errors.log` retains worker diagnostics. Logs may contain local paths; review before sharing. Windows runtime testing is still required.

### V8 canary ACL recovery
The V7 diagnostic trace stopped in SetAccessControl on the user's Documents directory. V8 removes all parent ACL writes from canary preparation. Existing intact originals can be reused; new originals retain the dedicated folder's service read ACL. For fixed canary files only, the scanner validates the opened handle's final path, link count and file type rather than requiring metadata access on all ancestors. Other scan paths and automatic response retain their existing checks. The periodic canary scan remains active if a real-time watcher cannot be installed; watcher failures remain visible. No previous parent ACL entries are automatically removed. Verify all three canaries are enrolled and readable by the service on Windows after installation.


### V9 installation handoff diagnostics
Existing intact canaries remain selected and are reused. The elevated worker now streams stdout/stderr into the protected setup log as operations happen. Setup logs configuration, permission checks, deployment, certificate/task registration, baseline enrollment and service startup. Identical directory ACLs are not reapplied. The wizard reports elapsed time after 60 seconds; it does not forcibly kill an active MSI or service mutation. Windows runtime validation remains required.

### V10: explicit recovery of deleted setup canaries

Run Setup normally and choose Upgrade / repair with canaries selected. For an existing enrollment, explicitly approve restoration of missing originals. Only missing fixed-template files are created; modified survivors are rejected and never overwritten. The registered folder must match the current user's Documents folder. Existing SHA-256 baselines and incident history are retained. The installer revalidates enrollment before service startup. Monitoring itself never recreates missing files. Investigate unexpected deletion before approving recovery. No parent Documents ACL changes are made.

The Security log attribution warning is separate: configure the Windows File System audit policy, narrowly scoped SACLs on the canary folder/files, and authorized Security log access for the LinkScope service under your organization's policy. This revision does not grant broad Security log access or change system audit policy automatically. Runtime validation on Windows is required.
