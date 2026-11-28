# V27 — Watcher coverage and alert recovery

V26 can update a finding in endpoint.sqlite without updating its corresponding active notification. A notification using the old phrase “lack both watcher and live journal coverage” therefore does not establish that the current privileged watcher failed. V27 updates the exact active watcher finding in place, preserving its ID, timestamp and read state. A successful endpoint tick with a drained outbox can retire an orphaned watcher warning without waiting for a complete full disk scan. Malware, canary, quarantine and audit history are not reset.

The privileged recursive watcher is now maintained for failed LocalService directory roots even while USN is Live or Replaying. Its independent pipe remains restricted to the configured scope. Coverage still requires a verified watcher response (no gap and fresh within 30 seconds), or live/replaying USN, or successful native watcher registration. An initial or genuine coverage failure is still reported. Existing limitations (serial polling, leases, reparse points, inaccessible objects and Windows-native execution) remain.

The generic partial-coverage notification is not duplicated while the specific watcher warning is active. The endpoint collection status remains partial as appropriate. Other specific warnings remain active. The events alert evaluator excludes Application events from the exact provider Unixfor LinkScope with event ID 4201 because those are audit mirrors of already published endpoint/integrity alerts. The event viewer and Windows Event Log are not modified; other providers and event IDs remain eligible for alerts.

## Windows acceptance check

1. Rebuild and upgrade both LinkScope services. Check `Get-Service LinkScope,LinkScopeUsn` in an elevated PowerShell session.
2. Open Endpoint Protection and inspect NTFS journal state and Privileged watcher details. A failed LocalService Downloads watcher should be backed by the journal or a verified privileged watcher. If both are unavailable, the active notification now includes the latest helper failure or pending state instead of the old text.
3. Copy a harmless test file into Downloads and confirm a scan activity verdict. Use the existing `--endpoint-engine-self-test` and `--endpoint-scan-file` diagnostics if needed. Do not disable your primary antivirus.
4. Check that the coverage warning resolves on recovery; historical notifications remain. Verify that unrelated Application errors and actual malware findings still appear.

Portable validation: 13 selected scripts passed, including SQLite update SQL, watcher source wiring, USN, download reconciliation, profile settings, alert acknowledgement and dashboard tests. A C# native self-check was added; Windows build/runtime has not been executed in this environment.
