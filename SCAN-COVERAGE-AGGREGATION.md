# V15 — whole-volume scan coverage notifications

Whole-volume scans may encounter protected Windows files, private user profiles, locked files, size limits or engine errors. V14 creates a durable alert transition for each affected path. V15 stores the latest per-path state as an internal coverage record and publishes one stable `File scan coverage incomplete` warning while routine coverage issues remain. The Endpoint Protection page displays the outstanding count and up to 100 recent diagnostic records. Existing scan-activity records and incident history are retained. Individual warnings for configured roots and canary files, malware, heuristic findings, journal failures and other genuine security findings are not consolidated.

On the first enabled collection after upgrade, and after policy changes, the scanner migrates legacy per-file warnings using a transaction. It retains in-scope active gaps, retires out-of-scope gaps, and queues exact-key retirement of superseded old notifications. Central alert delivery marks only those superseded operational notifications read, closes them, and cancels their pending mail jobs; history remains intact. Already-sent or in-flight email cannot be recalled. Old notification cards already rendered in a browser may require a refresh. Other unread alerts remain unread. The existing generic scan-incomplete and provider-coverage alerts may still appear; they are not per-file alerts.

No new exclusions or elevated scanning permissions are introduced. A journal event is not evidence that the file's contents were successfully scanned. This update does not grant LocalService access to private or protected files or change the Windows ACLs. Successful reads, confirmed disappearance, scope changes and complete scans reconcile old coverage gaps; a full scan with errors does not pretend to have complete coverage.

## Windows acceptance checks

1. Rebuild Release and choose Upgrade / repair in Setup. Leave the existing ClamAV installation and canaries intact.
2. Select C:\ as a monitored root in Monitor mode, and start a scan. Confirm that routine inaccessible paths produce one coverage summary and appear in Scan coverage details rather than individual notifications.
3. Verify that old routine notifications are retired after the outbox drains and that prior incident history remains searchable. Refresh the browser. Confirm malware and canary notifications remain distinct and unread states are preserved for those categories of evidence.
4. Change the scope to C:\unx and retain the enrolled canaries. Verify that out-of-scope coverage details retire. Check that the summary resolves once no routine gaps remain.
5. Verify USN status separately. This revision does not modify native journal transport.

Portable checks: `python tests/validate_coverage_aggregation.py`, endpoint/scope/USN/canary regression checks and JavaScript syntax validation. These are not a Windows build or end-to-end scan. Existing CSS assertion in validate_endpoint_layout_updater.py remains failing.
