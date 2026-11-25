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
