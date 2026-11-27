# LinkScope Setup — automatic ClamAV configuration and readiness checks

## Build and run

Build `LinkScope.sln` in Visual Studio (Debug or Release, x64, .NET Framework 4.8 targeting pack), or run `Build.cmd`. Both paths compile `setup/Setup.cs`, `setup/ClamSetup.cs` and `setup/ClamSignature.cs` into the GUI installer and embed the current application and wizard. For a new ClamAV installation, place the official Windows x64 MSI and its matching detached signature at `deploy\clamav-latest.msi` and `deploy\clamav-latest.msi.sig` beside the setup executable. Visual Studio copies both source files when present. Install trusted Gpg4win/GnuPG in a standard system-wide Program Files location before running the setup. ClamAV/GnuPG binaries and package signature files are not bundled. Setup never fetches an executable/MSI automatically. It verifies the detached signature before reading MSI product metadata or executing Windows Installer. See [CLAMAV-PACKAGE-VERIFICATION.md](CLAMAV-PACKAGE-VERIFICATION.md).

Run `LinkScopeSetup.exe`. Choose **Install and configure ClamAV** for a missing installation, **Configure / repair ClamAV** for a standard installed but incomplete installation, or **Check again** for a fresh read-only readiness check. Install / Upgrade LinkScope also offers optional ClamAV provisioning when applicable. You can use the repair action without reinstalling LinkScope. Windows UAC remains enabled. Child console processes remain hidden, and the wizard displays an indeterminate progress bar.

## What is checked

A registry entry alone is not sufficient. The setup checks both registry views, standard x64 binaries, configuration search paths, native service registrations, both configuration files, required main/daily database files, service state and automatic startup, local TCP binding, the ClamD Windows service PID and the TCP peer process, and PING/VERSION responses. A recognized database date must be less than three days old and not implausibly in the future for a Ready result. This is an approximate engine-reported date, not proof of current definitions for each third-party feed. A benign INSTREAM scan is also performed when provisioning or repairing an engine. The read-only status check is not a malware detection test or binary-signature attestation.

| Exit code of `--check-clamav` | Meaning |
|---|---|
| 0 | Standard installation/configuration, definitions reported current, loopback PING and VERSION, both services running and automatic |
| 3 | No installation detected |
| 4 | Standard binaries present, missing configuration or untouched example |
| 5 | Standard configuration present, definitions/service/protocol not ready |
| 6 | Custom, unsupported or incompatible configuration/service; no automatic changes |
| 7 | Engine responding; updater or automatic service startup needs attention |
| 8 | Registry/partial/custom installation without both standard x64 binaries |
| 9 | Engine responding, but database date is stale or unverified |
| 1 | Check failed or access denied; investigate locally |

## What the repair does

After explicit administrator consent, it validates the standard `%ProgramFiles%\ClamAV` installation tree and ACLs (no reparse points, unexpected owners or non-admin write permissions). It does not take over other software's listener on port 3310 or edit a custom service registration. It creates the standard database directory and missing `clamd.conf` / `freshclam.conf` files. Empty or untouched vendor example configurations may be replaced only with a unique backup retained. Existing non-example configurations are preserved; a conservative subset of compatible settings is eligible for automatic service startup. Unsupported directives, custom paths or custom service registrations cause manual review rather than silent replacement.

New ClamD settings include IPv4 loopback `127.0.0.1:3310`, 100M maximum individual/stream size, 200M total scan limit, limit alerts, signed-bytecode trust policy and rotating logs. New FreshClam settings use the same database directory, official mirror, database testing, twelve checks per day, and ClamD reload notifications. The initial signature fetch uses the installed FreshClam executable, not a custom downloader. Existing signature databases are reused, and the updater is not run concurrently with a detected FreshClam process. Existing compatible approved HTTPS third-party `DatabaseCustomURL` feeds are preserved; no third-party source is enabled automatically. Review existing custom feeds before accepting the setup prompt. No unsigned-bytecode, arbitrary hook, private mirror, proxy credential or custom service configuration is adopted automatically.

The native `clamd --install-service` / `freshclam --install-service` commands are used only for missing registrations. Both standard services are configured for automatic startup after explicit consent. Existing service identities are not changed. Setup waits for ClamD to respond and checks a harmless stream scan before starting the updater service. Definition downloads and startup waits are bounded. An update failure, stale definitions, service failure, unexpected peer or scan failure is not reported as a successful configuration. Partial work is retained for inspection/retry; no transactional rollback is claimed. Setup never automatically restarts Windows. If the MSI returns a reboot-required code, restart Windows before selecting repair. Setup does not disable Microsoft Defender, modify Windows firewall policies, change LinkScope's listening port, enable Endpoint Protection, or enable quarantine/containment.

If the host has no Internet access, use an independently verified offline database distribution procedure for the required ClamAV files. Setup does not bypass TLS or vendor update restrictions. A failed download is recorded, and you may still install LinkScope without a ready engine.

## Diagnostics and logs

The installer keeps administrator-only operation logs under `%ProgramFiles%\LinkScope Setup Logs`. ClamD/FreshClam logs configured by setup are `%ProgramFiles%\ClamAV\clamd.log` and `freshclam.log`. Consult these logs for service startup, database download, permissions, or compatibility failures. Existing compatible configurations may choose not to log to those files. Logs may include trusted feed URLs supplied by the administrator; protect them accordingly.

Read-only readiness check from PowerShell:

```powershell
$p = Start-Process .\LinkScopeSetup.exe -ArgumentList '--check-clamav' -Wait -PassThru
$p.ExitCode
Get-Service clamd,freshclam -ErrorAction SilentlyContinue
Test-NetConnection 127.0.0.1 -Port 3310
```

`--configure-clamav` is an elevated, interactive configuration operation (it still asks for consent). `--install-clamav` installs the locally verified package only if missing, then runs the same configuration operation. `--check-clamav` never installs, updates, starts or stops a service. A custom or nonstandard installation requires manual review, even if its separate configuration works.

Once ready, use LinkScope Settings > Endpoint Protection, local port 3310, Monitor mode, and your own protected paths/exclusions. Save and select Scan now. Allow up to the existing engine status polling interval for the dashboard to refresh. Do not enable Protect/Contain without the isolated Windows acceptance tests and independently verified engine pin.

## Windows acceptance checklist (not run in the delivery environment)

1. Clean test VM, no MSI: wizard reports not installed and offers to continue without ClamAV.
2. Verified local MSI: install/initialize definitions, both services run automatically, PING/VERSION and benign stream tests succeed. No visible command windows; UAC remains visible.
3. Already installed but no configs: use Configure / repair without reinstalling MSI or LinkScope. Verify standard config and definitions.
4. Untouched copied sample configs: verify uniquely named backups. Run again; config hashes unchanged.
5. Existing valid configuration and trusted third-party database URLs: verify source files and feeds remain unchanged; no duplicate service/update process.
6. Custom port, registry ConfDir/DataDir, unsupported directive or unrelated service name: verify no automatic mutation.
7. Another process owns 3310 or listener is exposed beyond loopback: verify repair refuses to change services/configuration.
8. Network blocked, no signatures: verify setup reports incomplete provisioning, records logs and allows LinkScope-only install. Re-enable approved connectivity and retry.
9. Stale definitions or stopped updater: readiness check reports not fully ready. Repair or let the running updater finish, then check again.
10. MSI reboot-required outcome: verify no subsequent automatic configuration before reboot.
11. Stop ClamD, run Check again, repair; verify service status and LinkScope dashboard change.
12. Rebuild Debug/Release; verify fresh setup embeds exact payload and deploy MSI copy. Test PING/VERSION against actual installed ClamAV version. Test EICAR separately on an isolated VM and verify central alerts/reports/API.

## Verification performed here

Portable source assertions, C# lexer delimiter checks, project XML/build inclusion, existing endpoint SQL and JavaScript checks, navigation checks and final ZIP integrity were performed. This does not establish Windows compilation or installer success. Windows Service Control Manager, ClamD, FreshClam, MSI/UAC, Windows ACL and GUI tests require a Windows VM. The setup binary is unsigned. This is source delivery, not a tested executable.

Official reference: https://docs.clamav.net/manual/Usage/Configuration.html and https://docs.clamav.net/manual/Usage/Services.html .
