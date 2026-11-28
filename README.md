# Build notice — Windows 11 installer update

This source archive intentionally excludes old compiled executables. Rebuild using `Build-VisualStudio.cmd Release` (Visual Studio with .NET Framework 4.8 targeting pack) or `Build.cmd` before running setup. The legacy native bootstrap is retired. See [ClamAV removal](CLAMAV-SETUP.md).

# LinkScope

Read the [administrator guide](docs/README.md) for installation, uninstallation, network alert rules, searching and paging alert history, module logging, syslog and SIEM forwarding (Seq, Wazuh, Elasticsearch), dashboard service restart, AI Assist, security posture, SMTP email and test delivery, JSON file retention, System health graphs, the full PDF report, HTTPS and the API.

Extract the package, open **64-bit PowerShell as Administrator**, and run:

```powershell
.\LinkScopeSetup.exe --install
```

On a fresh installation open **http://127.0.0.1:9876/** on the monitoring computer. To upgrade, follow [Reinstall or upgrade](docs/README.md#reinstall-or-upgrade).

The [Postman collection](docs/LinkScope.postman_collection.json) and [environment](docs/LinkScope.postman_environment.json) are ready to import.

Recent probe failures include searchable, plain-language descriptions of ICMP statuses and local probe errors. Suggested causes are diagnostic hints, not confirmed root causes.

Fresh installations use `admin` / `admin` for local first-use enrollment only. A new password of 12–128 characters meeting complexity rules is required before access. Upgrades preserve existing credentials. See USER-MANAGEMENT-MFA.md for role-based accounts and authenticator enrollment.

### AI verdict network assessment
System verdicts include a deterministic per-target 1-hour and 24-hour network probe assessment, independent of AI summarization. Loss excludes local probe errors; timeouts are included in lost probes. Missing/stale data is explicitly identified. The same exact measurements are supplied to the AI for interpretation.

### Complete AI system verdict
The verdict evaluates all collected core and enabled optional Windows categories, SMART attributes, event metadata, network probe history, resource and adapter history, active connection snapshots, alerts, delivery, application logging and SIEM status. It includes direct measured facts and coverage alongside the AI interpretation; disabled, stale and unavailable categories are identified. Collection limits remain in effect (including up to 2,000 connection rows and configured event limits). Raw event messages, application log message bodies, credentials and selected identifying fields are not sent to providers. Review internal telemetry disclosure before enabling a cloud provider. Large evidence sets require multiple AI calls and may hit provider context, quota or time limits.

### AI verdict in PDF reports
When AI Assist is enabled, the latest successful system verdict (not an ordinary chat reply) appears on the report cover and continuation pages before network/system data, and in the attached JSON. The original AI interpretation, evidence timestamp, completion timestamp, provider and model are retained in the protected service data directory (`ai-verdict.json`). Export does not call the AI provider. Disabling AI hides the verdict; clearing chat does not erase the saved system verdict. The report labels the interpretation as historical; compare it with the current report readings. A failed analysis leaves the last successful verdict unchanged.

### Graphical installation wizard
Double-click `LinkScopeSetup.exe` without arguments to open the embedded Windows Forms wizard (Windows PowerShell 5.1, no separate installer runtime). Choose Install, Upgrade / repair, or Uninstall service. Windows requests UAC elevation for the selected operation; progress is indeterminate until the elevated command finishes. The wizard and elevated setup executable use the Windows GUI subsystem; child console programs run without visible windows. Detailed elevated operation logs are kept in `%ProgramFiles%\LinkScope Setup Logs` (administrator access). The dashboard shortcut opens the fresh-install default URL only; use your configured URL for custom ports or HTTPS.

For automation, run from an elevated 64-bit terminal:

```powershell
.\LinkScopeSetup.exe --install
.\LinkScopeSetup.exe --upgrade
.\LinkScopeSetup.exe --uninstall
```

`--upgrade` extracts the already compiled service embedded in Setup, then deploys and starts it using the existing installer. `--install` retains its original behavior. Uninstall removes the service and hardware task while retaining settings, history, and installed files. Installation remains in the standard Program Files location; port, bind address and HTTPS are configured in the dashboard. Back up data before upgrading. An unsuccessful deployment after stopping the service may require manual recovery; this is not a transactional rollback installer. The setup binary is unsigned. Windows GUI, UAC and service installation require runtime validation on Windows. The optional ClamAV prerequisite is described in `deploy/README.md`. For command-line use, run `Start-Process .\LinkScopeSetup.exe -ArgumentList '--upgrade' -Wait -PassThru` from elevated PowerShell and inspect `.ExitCode`; the GUI subsystem does not print console output.

### Scheduled telemetry JSON export
In Settings → Scheduled telemetry JSON export, enable export, set the interval (default 300 seconds), choose categories or Full telemetry, and specify an absolute local Windows directory. Leave the directory empty for `%ProgramData%\LinkScope\data\telemetry`. The service writes `telemetry.json`, atomically replacing its previous export; no historical files are kept. The first export runs on enable/start; optional inventory can initially be collecting. Export uses the latest sampled values, not a forced system scan every interval. Full includes all supported Windows inventory, day network reports, active connections and the saved AI verdict if available. API scopes are unchanged. Export is disabled by default. Custom folders must be restricted and writable by the service identity (LocalService); network shares and junctions are not supported. Moving or disabling export does not delete the last file in the old location. Export failures are logged and the previous successful file is retained. Refresh Settings to see the latest export status.

### Build application and setup together (Windows)

Run `Build.cmd` to generate both `LinkScope.exe` and `LinkScopeSetup.exe` in the project root. Alternatively, build or rebuild `LinkScope.sln` in Visual Studio with the .NET Framework 4.8 targeting pack; both executables appear in `bin\Debug` or `bin\Release`. The main project invokes `setup/LinkScope.Setup.csproj` through MSBuild after each successful normal build (not design-time builds), rebuilding the GUI installer from the exact compiled application and existing wizard. No batch file is required for this Visual Studio build. See [Visual Studio setup builds](VISUAL-STUDIO-SETUP.md). Setup generation errors fail the build. The setup is unsigned and requires Windows .NET Framework 4.8 and Windows PowerShell 5.1 for its wizard; no Python, Linux, or C++ toolchain is required. The older native Linux setup builder is retained for reference only.

### Application branding
The root `linkscope.ico` is the single icon source for the application and setup executables, setup wizard, all web page headers and favicons, and PDF report branding. Replace it and rebuild both executables to change the icon. The web icon is embedded and requires no external file at runtime. Windows shell icon caching may delay visible changes. The service has no tray UI.

## Database cleanup (maintenance)

In Settings, choose a retention amount and Days, Months or Years. Automatic maintenance is opt-in (default: disabled, one year). Latest-month protection defaults to on and protects the rolling calendar month in UTC, even under the legacy retention rules. With maintenance enabled, the chosen retention overrides raw probe, aggregate and application-log retention and also prunes resolved alerts (by resolution time, or opening time if unavailable). Active alerts and alerts with queued email remain protected. Aggregate buckets that overlap the cutoff are preserved. Old queued SIEM records follow application log retention. Automatic cleanup runs at startup, after a changed policy is saved, and hourly; Run cleanup now uses the saved enabled policy. The UI displays the cutoff, status and counts from the most recent run (in memory). Cleanup is permanent and cannot restore previously removed history. Back up the SQLite databases before enabling it. Batches commit independently; failure may leave some batches already deleted. SQLite reuses freed pages; no automatic VACUUM is performed. Native Windows event logs, settings, tokens and telemetry.json are not deleted. When disabled, original network history retention (2/35/400 days) and independent application log retention apply, with the optional month floor; resolved alert cleanup stops.

### Application confirmation dialogs
Service restart, manual database cleanup and retention-policy activation use accessible in-page modals instead of native browser confirmations. Cancel and Escape dismiss without performing the operation. Destructive actions use a red confirmation button; existing toast notifications are retained.


## User audit logs and installable web app
Open User audit in the navigation (administrator sign-in required). The separate `user-audit.sqlite` database under the protected application data directory records browser POST actions, login outcomes, audit page access and denied audit queries. It records UTC Unix timestamps, authenticated username or unauthenticated status, source IP, known route and HTTP outcome. Request bodies, credentials, tokens and cookies are never stored. HTTP success means the request was accepted, not that a background job completed. Search supports date ranges, outcome and text, with 100 records per page. Audit records are not removed by existing history maintenance; plan separate retention and backups. This is a local audit trail, not tamper-proof. User management actions include the target username, and login attempts include the validated account name. Failed audit writes are reported through service logging.

LinkScope provides a web app manifest, icons and a network-only service worker. Open the dashboard in a compatible browser using localhost or trusted HTTPS and use its Install app menu when available. No authenticated pages, telemetry or credentials are cached for offline use. If disconnected, navigation displays an offline message. Browser support and install eligibility vary.

### Incoming IP firewall
Settings → IP firewall accepts one IPv4/IPv6 address or CIDR subnet per line (for example `192.168.1.0/24` or `2001:db8:1::/64`). Subnet rules are normalized to their network addresses; `/0` is deliberately refused. By default only loopback peers are allowed (including mapped IPv4 loopback). All other clients receive HTTP 403 before application routing. Forwarded IP headers are ignored. Denials are recorded in user audit logs. Saving applies immediately; remote administrators cannot remove their own IP via the UI. Authentication and HTTPS rules remain unchanged. Existing installations with no AllowedClientIPs property default to localhost-only: before upgrading a remotely managed installation, add the required client IPs to `%ProgramData%\LinkScope\settings\config.json` under `AllowedClientIPs` (JSON string array). If locked out, stop the service, edit the file as a Windows administrator, then restart. A listener bound to a LAN address is not automatically bound to localhost. This is application-layer filtering, not a Windows Firewall rule; use Windows Firewall too for transport-level filtering. Reverse proxies are evaluated by their actual TCP peer address; do not allow a shared proxy unless it enforces its own client access policy.

### Notification behavior
Monitoring alerts and routine success, warning and error messages use non-blocking toast notifications. All toast notifications disappear after seven seconds; expiry does not mark monitoring alerts as read. Action confirmations and interactive dialogs remain modals. No browser-native alert/confirm/prompt is used.

### Network card counters
Packet loss and timeouts display new observations since the per-target, per-metric acknowledgement cutoff, bounded by the configured dashboard window. Packet loss uses eligible probes after that cutoff (local probe errors excluded). After acknowledgement the displayed counters reset to zero; historical totals for the selected range remain underneath. Active probe failures and active loss alerts retain their severity. History, reports and alert records are unchanged.

### Immediate network incident notifications

Enabled targets now generate separate persistent packet-loss and timeout incidents on the first unanswered probe, even if optional threshold rules are unset. Continuous incidents are deduplicated until recovery. Existing threshold rules, per-target alert opt-out, dashboard acknowledgement, and historical probe data are unchanged. Local probe errors are not packet loss. Sign in as administrator to view the full alert history and unread notification feed.

## File integrity monitoring (Data Integrity)

In **Settings → Data Integrity & Tamper Detection**, enable the feature only when the protected files are known good. Add local absolute file or directory paths, optional exact excluded files/directories, and optional filename patterns (`*.log`, `*.tmp`, `report-?.csv`). Excluded directories include their descendants. Defaults have no exclusions; interval 300 seconds, recursive scan on, Windows Event Viewer off. Save with a reason and confirm the change. The first complete scan of at least one file creates the trusted baseline. Use the dedicated **Data Integrity** menu for current results, hashes, chain status, and Scan now.

The scanner runs on its own worker. SHA-256 hashes are compared against the initial baseline; each complete scan appends a sequence/timestamp/previous-HMAC/snapshot-digest/policy-digest record authenticated with a random 256-bit HMAC key protected by Windows DPAPI (LocalMachine). The snapshot digest is SHA-256 over a deterministic sorted list of path/hash pairs, not a Merkle tree. The baseline and chain live in `C:\ProgramData\LinkScope\data\integrity\chain.json`; a separate local head checkpoint is `data\integrity-checkpoint.json`. The data folder inherits the service's restricted ACLs. A separate checkpoint detects a truncated chain if the checkpoint itself remains intact. Do not delete either file or the protected master key. A crash between state and checkpoint writes can cause a fail-closed verification error; investigate and recover from trusted backups. Full local deletion or rollback of all state, key and checkpoint cannot be reliably detected without an independent remote anchor. The module is tamper-evident, not a replacement for ACLs, EDR, immutable backups or remote monitoring.

Modifications, missing files, additions, scan problems and authentication failures enter the existing alert history, unread counter and toast pipeline; incident details enter Application Logs and the configured Syslog/SIEM forwarding pipeline subject to log level and receiver settings. Enable the Event Viewer option to write incident events under `LinkScope` (event 4201). The `data_integrity` category is available for API tokens and telemetry export selection; existing tokens and selected exports need the category explicitly added. System reports and AI evidence use the existing category infrastructure. Policy changes and manual scans are audited. Acknowledging an alert does not update the baseline. New files added to coverage after enrollment are treated as new, not automatically trusted. This version deliberately has no web-based rebaseline/approval action, real-time watcher, remote checkpoint verifier, metadata/ACL/signature comparison or automatic remediation. Exclusions are global patterns or exact absolute paths. Only complete scans append checkpoints; unreadable files, reparse points and unavailable paths produce incomplete coverage, not proof of integrity. Limit: 100,000 hashed files per scan, up to 1,000 collected scan error details. The JSON chain grows with each scan; back up and monitor its storage. Periodic scans may miss transient changes between scans. Windows self-check includes isolated baseline, exclusion, modification, deletion, policy and chain tests; run the Windows build and verification before production deployment.

### Data Integrity dashboard
Open `/integrity` from the main navigation. The dashboard shares the System Health styles and polls every 15 seconds. Configure monitoring in Settings. Full PDF exports include the integrity snapshot (including embedded JSON) when enabled; historical alerts remain retained. The bearer-token API `/api/v1/system?categories=data_integrity` requires a token scoped to `data_integrity`; disabled monitoring reports disabled status.


## Endpoint Protection release candidate
See [ENDPOINT-PROTECTION.md](ENDPOINT-PROTECTION.md) for installation, third-party signature updates, real-time monitoring, canaries, entropy, audit correlation, restricted quarantine and containment, and Windows acceptance tests. See [ENDPOINT-VALIDATION.md](ENDPOINT-VALIDATION.md) for verification results and release gates. Monitor is the default.

### Responsive navigation and optional ClamAV installer

All authenticated pages share a compact desktop header. On tablets, phones, or when links cannot fit, the hamburger menu exposes all destinations including the Report link (complete PDF download). The bell, theme switch and account remain visible.

The Windows setup wizard checks ClamAV installation, configuration, service state, signature status and loopback engine readiness. If absent it offers the local `deploy\clamav-latest.msi` after mandatory detached OpenPGP verification of `deploy\clamav-latest.msi.sig` with a system-wide trusted GnuPG installation, then configures standard ClamD/FreshClam services and initial signatures with administrator consent. Installed but incomplete standard configurations can be repaired without reinstalling LinkScope. No MSI or executable is automatically downloaded, and no reboot is performed. See [CLAMAV-SETUP.md](CLAMAV-SETUP.md) and `deploy/README.md` for details.

The shared navigation uses Font Awesome Free 5.15.4 SVG icon outlines, including the menu, Report, notification bell, theme switch and account icon. No external scripts, fonts or Internet resources are required. See [FONT-AWESOME-NOTICE.md](FONT-AWESOME-NOTICE.md) for attribution. Desktop menu text is 12 px; the collapsed menu uses larger text and 44 px touch targets.

Run `python tests/validate_navigation_static.py` for portable source checks and `python tests/validate_navigation.py` with Playwright and Chromium for live navigation checks (mocked backend). See [NAVIGATION-SETUP-VALIDATION.md](NAVIGATION-SETUP-VALIDATION.md) for remaining Windows acceptance tests.

### Desktop web app and compile fixes

Setup now provisions LinkScope Desktop/Start menu shortcuts by default and offers default-checked managed Edge PWA registration, without replacing an existing foreign Edge web-app policy. See [DESKTOP-PWA-COMPILE-FIX.md](DESKTOP-PWA-COMPILE-FIX.md) for the browser policy implications, repair commands, compiler fixes and Windows acceptance checks. Actual PWA registration is performed by Edge when an eligible profile runs; the immediate shortcut uses browser app mode.

### Endpoint activity and build version

The Endpoint Protection dashboard includes a live activity indicator and scoped acknowledgement of previous alerts. Acknowledgement changes read state only; it does not resolve threats or delete evidence. Recovered orphaned central endpoint incidents are reconciled only after a successful complete online scan and delivery of pending transitions. The application footer displays the build's merged `v_` release branch version when available. See [ENDPOINT-ACTIVITY-VERSION.md](ENDPOINT-ACTIVITY-VERSION.md) for configuration, Git merge metadata and Windows acceptance checks.

### Endpoint canaries, live scan activity and signature updates

Canaries are enrolled only from the Endpoint Protection Maintenance tab in a saved, explicitly protected directory. No Documents canaries are created by setup in V50.

## Endpoint maintenance

See [ENDPOINT-MAINTENANCE.md](ENDPOINT-MAINTENANCE.md) for dashboard signature refresh, Canary Manager, release metadata and Windows acceptance tests.

### Third-party signature feeds

Use the local elevated **LinkScope Setup → Third-party signature sources...** editor
for approved HTTPS `DatabaseCustomURL` entries. Existing official signatures and
unmentioned feeds are preserved. Subscription URLs are not sent to the web UI or API.
See [THIRD-PARTY-SIGNATURES.md](THIRD-PARTY-SIGNATURES.md) for accepted formats,
credential handling and Windows acceptance tests.

## User management and MFA

Use the account icon → Users (Admin only) or My account & MFA (all signed-in users). Admin and Viewer roles are enforced at the server; anonymous localhost viewing is no longer available. See [USER-MANAGEMENT-MFA.md](USER-MANAGEMENT-MFA.md) for migration, credentials, MFA recovery, and acceptance tests.

See [SCAN-COVERAGE-AGGREGATION.md](SCAN-COVERAGE-AGGREGATION.md) for whole-volume scan warning consolidation and acceptance checks.

### V17 priority arrival scanning

See [PRIORITY-ARRIVALS.md](PRIORITY-ARRIVALS.md) for the new download/copy scheduling, retry policy and Windows acceptance tests.

### V18 file scan diagnostics
See [FILE-SCAN-DIAGNOSTICS.md](FILE-SCAN-DIAGNOSTICS.md) for exact-file service activity, direct ClamAV probing, and priority scheduling/retry changes.

## V19 exact-file service probe

See [SERVICE-FILE-PROBE.md](SERVICE-FILE-PROBE.md) for the actual service-account scan, in-memory EICAR engine check, and explicit scoped read-access troubleshooting.

### V20: user profile scanning permissions

See [Profile scan access](PROFILE-SCAN-ACCESS.md) for the administrator-only `Grant-LinkScopeScanAccess.ps1` utility and failed-watcher recovery. Upgrade alone does not change Windows user-profile ACLs.

### V21 — protected-directory access and priority arrival scanning

See [PRIVILEGED-ARRIVAL-SCANNING.md](PRIVILEGED-ARRIVAL-SCANNING.md) for the read-only SYSTEM-assisted scan fallback, downloaded/copied-file priority, reset behavior and Windows acceptance procedure. Upgrade both services together.

### V22 — independent Downloads reconciliation

In addition to USN and watcher events, the service enumerates the immediate files in standard Windows profile `Downloads` directories within the saved scan scope. Include the exact Downloads directory or a parent in Endpoint Protection settings; a Desktop-only scope does not include Downloads. See `DOWNLOAD-RECONCILIATION.md` for diagnostics, coverage limits and the Windows acceptance test.

### V23 — concise Endpoint Protection overview

The overview retains its real severity badge and independent metric cards, but replaces raw alert messages with counts and a link to **Active alert diagnostics** in the evidence area. Detailed paths, signatures, hashes, and exception text remain available there and in the existing evidence/history tables. Expanded diagnostics stay open during telemetry refresh. This is a presentation-only change; scan policy, notifications, incident history, ClamAV and USN processing remain unchanged.

Windows acceptance: upgrade, refresh `/endpoint`, and verify a retained EICAR finding still produces a critical badge and a malware count. Technical coverage warnings should be summarized rather than printed above the cards. Open the diagnostics link, confirm the full messages, and verify that the panel remains open after refresh. Portable renderer regression: `python tests/validate_endpoint_summary.py`.

V25: See [privileged watcher fallback](PRIVILEGED-WATCHER-FALLBACK.md) for coverage diagnostics and Windows acceptance checks.

### Default user profile protection (V26)

Historical V26 behavior, superseded by V50. New installations start with no monitored folders and Endpoint Protection disabled. Existing policies are retained; select application directories in Settings and enable protection explicitly. See [ENDPOINT-PROTECTION-V50.md](ENDPOINT-PROTECTION-V50.md).

### Watcher coverage and alert recovery (V27)

See [WATCHER-ALERT-RECOVERY.md](WATCHER-ALERT-RECOVERY.md). Keeps the privileged watcher warm alongside USN, refreshes the exact watcher warning without reopening it, and avoids duplicate alerts from the application’s own endpoint audit events. Genuine coverage failures remain visible.

### Independent watcher and ClamD deadline (V28)

See [WATCHER-CLAMD-RECOVERY.md](WATCHER-CLAMD-RECOVERY.md) for the watcher heartbeat, bounded ClamD transport and persistent retry behavior. Genuine coverage and security alerts remain visible.


### V65 isolated validation lab

See [ENDPOINT-PROTECTION-V65.md](ENDPOINT-PROTECTION-V65.md) for the opt-in disposable canary comparison and real EICAR quarantine exercise, evidence requirements, and limitations.

### Test Center directories
V66 requires explicitly saved disposable Test Center directories for live exercises. See [settings-driven test directory configuration](ENDPOINT-PROTECTION-V66.md).

V67 extends the full validation suite with temporary enrolled-canary watcher and normal-detector incident attribution evidence. See [production-path validation and limitations](ENDPOINT-PROTECTION-V67.md).

### V68 controlled termination validation

Full security validation includes a fixed owned-child process exit test and separately reports actual malicious-process containment as unverified. The production response now verifies exit on the retained process handle. See [V68 production acceptance record](ENDPOINT-PROTECTION-V68.md) for safeguards, regression results and Windows acceptance requirements.
