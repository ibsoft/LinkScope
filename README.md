# LinkScope

Read the [administrator guide](docs/README.md) for installation, uninstallation, network alert rules, searching and paging alert history, module logging, syslog and SIEM forwarding (Seq, Wazuh, Elasticsearch), dashboard service restart, AI Assist, security posture, SMTP email and test delivery, JSON file retention, System health graphs, the full PDF report, HTTPS and the API.

Extract the package, open **64-bit PowerShell as Administrator**, and run:

```powershell
.\LinkScopeSetup.exe --install
```

On a fresh installation open **http://127.0.0.1:9876/** on the monitoring computer. To upgrade, follow [Reinstall or upgrade](docs/README.md#reinstall-or-upgrade).

The [Postman collection](docs/LinkScope.postman_collection.json) and [environment](docs/LinkScope.postman_environment.json) are ready to import.

Recent probe failures include searchable, plain-language descriptions of ICMP statuses and local probe errors. Suggested causes are diagnostic hints, not confirmed root causes.

Fresh installations use `admin` / `admin` for local first-use enrollment only. A new password meeting the existing complexity rules is required before access. Upgrades preserve existing credentials.

### AI verdict network assessment
System verdicts include a deterministic per-target 1-hour and 24-hour network probe assessment, independent of AI summarization. Loss excludes local probe errors; timeouts are included in lost probes. Missing/stale data is explicitly identified. The same exact measurements are supplied to the AI for interpretation.

### Complete AI system verdict
The verdict evaluates all collected core and enabled optional Windows categories, SMART attributes, event metadata, network probe history, resource and adapter history, active connection snapshots, alerts, delivery, application logging and SIEM status. It includes direct measured facts and coverage alongside the AI interpretation; disabled, stale and unavailable categories are identified. Collection limits remain in effect (including up to 2,000 connection rows and configured event limits). Raw event messages, application log message bodies, credentials and selected identifying fields are not sent to providers. Review internal telemetry disclosure before enabling a cloud provider. Large evidence sets require multiple AI calls and may hit provider context, quota or time limits.

### AI verdict in PDF reports
When AI Assist is enabled, the latest successful system verdict (not an ordinary chat reply) appears on the report cover and continuation pages before network/system data, and in the attached JSON. The original AI interpretation, evidence timestamp, completion timestamp, provider and model are retained in the protected service data directory (`ai-verdict.json`). Export does not call the AI provider. Disabling AI hides the verdict; clearing chat does not erase the saved system verdict. The report labels the interpretation as historical; compare it with the current report readings. A failed analysis leaves the last successful verdict unchanged.

### Graphical installation wizard
Double-click `LinkScopeSetup.exe` without arguments to open the embedded Windows Forms wizard (Windows PowerShell 5.1, no separate installer runtime). Choose Install, Upgrade / repair, or Uninstall service. Windows requests UAC elevation for the selected operation; progress is indeterminate until the elevated command finishes. The console shows detailed installation output. The dashboard shortcut opens the fresh-install default URL only; use your configured URL for custom ports or HTTPS.

For automation, run from an elevated 64-bit terminal:

```powershell
.\LinkScopeSetup.exe --install
.\LinkScopeSetup.exe --upgrade
.\LinkScopeSetup.exe --uninstall
```

`--upgrade` extracts the already compiled service embedded in Setup, then deploys and starts it using the existing installer. `--install` retains its original behavior. Uninstall removes the service and hardware task while retaining settings, history, and installed files. Installation remains in the standard Program Files location; port, bind address and HTTPS are configured in the dashboard. Back up data before upgrading. An unsuccessful deployment after stopping the service may require manual recovery; this is not a transactional rollback installer. The setup binary is unsigned. Windows GUI, UAC and service installation require runtime validation on Windows.

### Scheduled telemetry JSON export
In Settings → Scheduled telemetry JSON export, enable export, set the interval (default 300 seconds), choose categories or Full telemetry, and specify an absolute local Windows directory. Leave the directory empty for `%ProgramData%\LinkScope\data\telemetry`. The service writes `telemetry.json`, atomically replacing its previous export; no historical files are kept. The first export runs on enable/start; optional inventory can initially be collecting. Export uses the latest sampled values, not a forced system scan every interval. Full includes all supported Windows inventory, day network reports, active connections and the saved AI verdict if available. API scopes are unchanged. Export is disabled by default. Custom folders must be restricted and writable by the service identity (LocalService); network shares and junctions are not supported. Moving or disabling export does not delete the last file in the old location. Export failures are logged and the previous successful file is retained. Refresh Settings to see the latest export status.

### Build application and setup together (Windows)

Run `Build.cmd` to generate both `LinkScope.exe` and `LinkScopeSetup.exe` in the project root. Alternatively, build or rebuild `LinkScope.sln` in Visual Studio with the .NET Framework 4.8 targeting pack; both executables appear in `bin\Debug` or `bin\Release`. The MSBuild post-build target runs on normal builds (not design-time builds), embedding the exact compiled application and existing wizard. Setup generation errors fail the build. The setup is unsigned and requires Windows .NET Framework 4.8 and Windows PowerShell 5.1 for its wizard; no Python, Linux, or C++ toolchain is required. The older native Linux setup builder is retained for reference only.

### Application branding
The root `linkscope.ico` is the single icon source for the application and setup executables, setup wizard, all web page headers and favicons, and PDF report branding. Replace it and rebuild both executables to change the icon. The web icon is embedded and requires no external file at runtime. Windows shell icon caching may delay visible changes. The service has no tray UI.

## Database cleanup (maintenance)

In Settings, choose a retention amount and Days, Months or Years. Automatic maintenance is opt-in (default: disabled, one year). Latest-month protection defaults to on and protects the rolling calendar month in UTC, even under the legacy retention rules. With maintenance enabled, the chosen retention overrides raw probe, aggregate and application-log retention and also prunes resolved alerts (by resolution time, or opening time if unavailable). Active alerts and alerts with queued email remain protected. Aggregate buckets that overlap the cutoff are preserved. Old queued SIEM records follow application log retention. Automatic cleanup runs at startup, after a changed policy is saved, and hourly; Run cleanup now uses the saved enabled policy. The UI displays the cutoff, status and counts from the most recent run (in memory). Cleanup is permanent and cannot restore previously removed history. Back up the SQLite databases before enabling it. Batches commit independently; failure may leave some batches already deleted. SQLite reuses freed pages; no automatic VACUUM is performed. Native Windows event logs, settings, tokens and telemetry.json are not deleted. When disabled, original network history retention (2/35/400 days) and independent application log retention apply, with the optional month floor; resolved alert cleanup stops.

### Application confirmation dialogs
Service restart, manual database cleanup and retention-policy activation use accessible in-page modals instead of native browser confirmations. Cancel and Escape dismiss without performing the operation. Destructive actions use a red confirmation button; existing toast notifications are retained.
