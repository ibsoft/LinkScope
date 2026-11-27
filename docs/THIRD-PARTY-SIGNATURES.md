# Third-party ClamAV signatures and header refinements

## Install / upgrade

Build `LinkScope.sln` (Release | x64) in Visual Studio, or use `Build.cmd`.
Run the new `LinkScopeSetup.exe`. Upgrading installs the updated dashboard and
embedded assets. The setup utility also includes a local signature-source editor.
The signed MSI verification requirement is unchanged.

## Add a signature provider

1. On the monitored Windows host, open LinkScope Setup. If necessary, first use
   **Configure / repair ClamAV** to prepare the standard ClamAV installation.
2. Click **Third-party signature sources...** and approve UAC. If the standard
   updater is not configured or running, repair it first.
3. Paste the provider's supplied `DatabaseCustomURL` lines, one per line. Plain
   HTTPS URLs are also accepted. For example (illustrative URLs only):

   ```ini
   DatabaseCustomURL https://provider.example/subscription/malware.hdb
   DatabaseCustomURL https://provider.example/subscription/javascript.ndb
   ```

4. Verify the provider's identity and your subscription. For `.ign2` and `.wdb`
   databases, explicitly approve the allow/ignore-list warning only if you trust
   the provider and understand that these databases may suppress detections.
5. Click **Save sources**, then approve the confirmation. Setup updates
   `freshclam.conf`, preserves the other approved configuration settings and
   restarts only FreshClam. The scanning service remains running.
6. Use **Endpoint Protection > Update signatures now** when eligible (the existing
   60-minute manual update cooldown applies), or let the automatic updater run.
   Check the native FreshClam log for each provider's download/validation result.
   FreshClam's successful process startup alone is not proof that every feed loaded.

The editor adds new feeds or replaces the URL for an existing provider/filename
pair. It preserves unmentioned feeds and official definitions. It rejects duplicate
database names, conflicting filenames across different providers, non-HTTPS URLs,
explicit credentials in URL userinfo, unexpected ports, malformed names, executable
bytecode feeds and unsupported extensions. The UI accepts up to 100 feeds. Removing
old feeds and removing their already downloaded database files is a separate,
host-local administration operation; this editor does not delete them.

Accepted third-party filename extensions: `.ndb`, `.ldb`, `.hdb`, `.hsb`, `.mdb`,
`.msb`, `.pdb`, `.gdb`, `.wdb`, `.ign2`, `.yar`, `.yara`. Engine compatibility still
depends on the actual database contents and installed ClamAV version.

## Credential handling

Subscription URLs may contain secrets in the path or query. Paste them only in the
local elevated editor. No actual subscription URLs are included in this source
archive. The editor displays previously configured hostnames and database filenames,
not the subscription URL. It stores the complete URL in the native FreshClam
configuration, not in browser settings or the LinkScope JSON configuration.
The file is plaintext because FreshClam must read it; its ACL is restricted to
Administrators and SYSTEM. Setup keeps a restricted backup of the previous config.
Native FreshClam logs may contain credentials and are redirected to the protected
`ClamAV\signature-logs` directory. Administrators, SYSTEM and the LinkScope service
identity have the required access. Do not distribute those logs or backups.
The LinkScope service reports recognized update timestamps only, not raw log lines.
The custom URLs are not returned via API, PDF reports or AI evidence. If a provider
credential has been pasted into an external conversation, rotate it when possible.

FreshClam validates database contents. The editor accepts an omitted TestDatabases
directive and explicitly sets `TestDatabases yes` after confirmation; an explicit
unsafe `TestDatabases no` still requires host-local review. HTTPS protects the connection; it does not make unsigned third-party
signatures equivalent to Talos-signed official definitions. Test new feeds in Monitor
mode, especially before enabling automatic quarantine or process containment.

## UI changes

- Header bell, theme and logout artwork reduced to 13px, with compact 34px desktop
  buttons and existing 44px compact/mobile touch targets. Main menu text remains 13px.
- The login descriptor is `SYSTEM & NETWORK MONITORING & ENDPOINT PROTECTION`.
  Endpoint protection and ransomware detection also appear as a dedicated feature
  in the login introduction.
- On Endpoint Protection, summary cards precede the Protection Activity / Signature
  Maintenance / Canary Manager panel. Existing live refresh and controls are preserved.
- A versioned CSS asset path ensures newly deployed styling is requested.

## Validation and remaining Windows checks

Portable checks are source/static checks, not a Windows build or live provider test.
Before production deployment, test the following on an isolated Windows VM:

- Build LinkScope and LinkScopeSetup from Visual Studio and the standalone build.
- Use a standard installed ClamAV with the native LocalSystem FreshClam service.
- Save a valid test feed; verify that official settings remain, subscription URLs are
  not in LinkScope telemetry, and the new database actually downloads and loads.
- Paste the same provider and filename with a rotated subscription URL; verify that
  the config contains just one entry for that database.
- Reject malformed URLs, duplicate names, different-provider collisions, and an
  unapproved `.ign2` or `.wdb` feed without changing the prior config.
- Confirm native logs and configuration ACLs, including rotated logs and backups.
- Test a failing feed, interrupted update, stopped updater, and incompatible custom
  setup; verify the appropriate errors and inspect protected logs.
- Test desktop, tablet and phone header sizes in both themes. Verify the live
  Endpoint Protection panel stays functional below the cards.

## Provider configuration repair

This revision checks the static installation/configuration paths before displaying
the editor, and traverses the mutable signature directory only after FreshClam
has stopped. The native signature log ACL uses the actual LinkScope service SID.
The editor compares the saved configuration with the original before replacement,
retains a restricted backup and attempts to restore and restart the previous
configuration if an operation fails. No signature-check bypass is introduced.

If the provider editor fails, the dialog now reports the failed operation,
exception type, HRESULT, native Windows error code when available, and exact setup
log location. URL/token redaction is applied to diagnostic messages. Do not share
native FreshClam logs or configuration backups without removing credentials.

Build both executables, open the new Setup wizard, select Third-party signature
sources, paste the provider's lines and approve the requested trust options. If
it still fails, record the failed step and error code from the new dialog. Test
that FreshClam continues to run after a failure, and confirm each database
download separately. These checks need a Windows host; portable source tests
do not establish that the original screenshot's failure has been reproduced.
