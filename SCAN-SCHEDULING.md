# V16 — Whole-drive scan scheduling and queue pressure

Upgrade from V15 with Rebuild-VisualStudio.cmd Release, then Upgrade / repair. Existing database, journal checkpoints, signatures and canary baselines are retained. The change does not modify Windows ACLs, grant administrative scanning rights or create exclusions.

## Behavior

* Watcher events are scope/exclusion filtered before enqueue, and duplicate pending paths are coalesced case-insensitively. Events can be accepted again after dequeue.
* Canary checks are performed in a dedicated lane before ordinary queue work. The ten-second interval is a scheduling target, not a hard deadline; a blocking file or engine operation can delay it.
* The scanner attempts one full-scan traversal entry before processing ordinary real-time work, to avoid indefinite starvation under backlog. The remaining work is still bounded by the existing per-tick budgets. Watcher work and journal work for the same path can share a scan attempt when the engine is online.
* Directory notifications and unresolved journal records request reconciliation on the configured scan schedule, rather than continuously forcing immediate whole-drive rescans. An actual journal gap detected during an in-progress scan cannot be cleared by that same scan. A complete later reconciliation is required. Historical records whose parent directories no longer exist may be impossible to reconstruct; the coverage warning is not suppressed or treated as a malware verdict.
* The real-time queue metric separates durable USN and watcher/deferred pending counts, and reports journal backpressure as a warning. A nonempty normal queue is labeled Queued, not No active alerts.

## Windows acceptance checks

1. Upgrade with ClamAV and existing canaries intact. Check Get-Service LinkScope,LinkScopeUsn.
2. In Monitor mode, create and modify a test file repeatedly inside a configured test directory. Inspect USN and watcher pending counts, and confirm the file is eventually scanned. Change it again after the queue drains and confirm it is scanned again.
3. While a scheduled scan is running, generate routine directory changes. Confirm scans progress and do not restart continuously due to ordinary directory notifications. An explicitly requested scan or actual watcher overflow may still schedule immediate work.
4. Check canary integrity independently while queue work exists. Do not delete production canaries solely to test; use a controlled test deployment.
5. Check journal coverage warnings after a fully completed reconciliation; they may remain when access restrictions, size limits or traversal limits prevent a complete scan. USN records are metadata, not antivirus scan results.
6. Compare process memory and CPU in Task Manager or Get-Process. The system-wide RAM alert does not identify the consuming process. ClamAV signature data, Windows and other processes may use substantial memory. No reduction in actual RAM or measured scan latency has been demonstrated here.

## Validation in the build environment

24 of 29 portable validation scripts passed, including new scheduling source/model checks, USN checkpoint/SQLite durability, transport, coverage migration and canary setup. Two browser checks could not complete (one timed out; one blocked localhost navigation). Three existing unrelated assertions failed (endpoint CSS, signature-provider CSS, missing FONT-AWESOME-NOTICE.md). Windows .NET Framework compilation and native runtime/throughput testing were not available. The 100,000-entry full scan cap and Windows access restrictions are unchanged.
