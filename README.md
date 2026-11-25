# LinkScope

Read the [administrator guide](docs/README.md) for installation, uninstallation, network alert rules, searching and paging alert history, module logging, syslog and SIEM forwarding (Seq, Wazuh, Elasticsearch), dashboard service restart, AI Assist, security posture, SMTP email and test delivery, JSON file retention, System health graphs, the full PDF report, HTTPS and the API.

Extract the package, open **64-bit PowerShell as Administrator**, and run:

```powershell
.\LinkScopeSetup.exe --install
```

On a fresh installation open **http://127.0.0.1:9876/** on the monitoring computer. To upgrade, follow [Reinstall or upgrade](docs/README.md#reinstall-or-upgrade).

The [Postman collection](docs/LinkScope.postman_collection.json) and [environment](docs/LinkScope.postman_environment.json) are ready to import.

Recent probe failures include searchable, plain-language descriptions of ICMP statuses and local probe errors. Suggested causes are diagnostic hints, not confirmed root causes.
