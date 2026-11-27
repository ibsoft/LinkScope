# LinkScope Endpoint Protection — implementation and validation report

**Revision:** 2026-11-27 release candidate  
**Source basis:** LinkScope_Endpoint_Protection_Preview.zip  
**Release decision:** NOT certified for production automatic response. Windows build and acceptance gates remain open. Monitor mode is the default; the feature is disabled until configured.

## Implementation inventory

| Capability | Source implementation | Validation status |
|---|---|---|
| Real-time filesystem detection | FileSystemWatcher, bounded queues, coalescing, incremental full scans, overflow alerts | Windows runtime pending |
| Canary monitoring | Separate persistent original SHA-256, recurring checks, modification/deletion alerts | Windows runtime pending |
| Entropy | First 64 KiB Shannon entropy, persisted prior measurements, correlated bulk-change heuristic | C# known-vector self-test added; not executed |
| Process correlation | Recent Windows Security event 4663, exact path, write/delete mask, PID and image | Requires audit policy/SACL and service read access; Windows runtime pending |
| Automatic containment | Explicit opt-in, exact executable eligibility, signed-engine trust via locally pinned hash and TCP peer identity, independent signature scan, process lifetime/criticality/session safeguards | High-risk response; isolated Windows tests mandatory; not executed |
| Quarantine | Stable file identity and re-scan, DPAPI sealed content, SHA-256 and metadata, original marked for deletion by verified handle | High-risk response; isolated Windows tests mandatory; not executed |
| Evidence review | Host-local elevated PowerShell export with hash verification, no web download or overwrite | Windows execution pending |
| Signature updates | Host-managed FreshClam official and approved third-party URLs; restricted local helper; DB version/date and stale warning | Actual ClamAV/FreshClam update and reload pending |
| Persistence and central alerts | SQLite file state, canaries, findings, history, durable outbox, transactionally committed central delivery cursor | SQLite SQL smoke checks passed; C# integration and crash replay tests pending |
| UI and reporting | Existing themed cards/search, mode settings, active findings/history/vault metadata, PDF summary, API category, AI/telemetry | JS parse and static field/resource checks passed; browser/API/PDF runtime pending |

## Portable checks actually executed

Run `python tests/validate_endpoint.py` on a development machine with Node.js and Python. The check extracts and executes the scanner's actual SQL literals with Python SQLite; it does not run the C# implementation or Windows SQLite DLL.

```text
PASS: all JavaScript files parse with Node.js
PASS: default endpoint policy is disabled, monitor-only, no response targets or engine pin
PASS: project XML, resource existence and Build.cmd parity
PASS: endpoint settings fields exist, HTML IDs unique
PASS: actual SQLite schema and SQL literals for file state, canary baseline, incident/open-close outbox and bounded deletion
PASS: C# lexer delimiter checks (not compilation)
PASS: portable validation completed; Windows compilation, runtime and security testing remain required.
```

The container lacks a .NET Framework 4.8 Windows compiler, a Windows service runtime and an installed ClamAV instance. C# delimiter validation is not compilation, type checking, native API validation or security testing. PowerShell execution, service identity, ACLs, browser appearance, API export and actual PDF generation were not tested. No malware or destructive response actions were executed.

## Windows acceptance checklist (all pending)

| ID | Scenario | Expected result |
|---|---|---|
| W01 | Build Debug and Release x64; execute `LinkScope.exe --self-test` | Clean build and self-tests, embedded UI/PWA resources available |
| W02 | Install/restart service in disposable VM with Defender enabled | Existing monitoring, audit, login, API, reporting and firewall intact |
| W03 | Monitor mode, benign files and exact/wildcard exclusions | Only in-scope paths observed; no source files removed |
| W04 | ClamD stopped, wrong port, scan cap exceeded, inaccessible file | Coverage warning; no false clean result or response |
| W05 | Official and approved third-party signature update, invalid/untrusted URL | Approved update succeeds/reloads; disallowed URL rejected by local helper; version verified |
| W06 | Create, change, rename, delete and rapidly rewrite benign monitored files | Real-time changes detected, queue remains bounded, full scan reconciles missed events |
| W07 | Force watcher overflow and restart service | Coverage warning and reconciliation; persisted baseline retained |
| W08 | Modify/delete/restore a trusted test canary, restart | Critical incident, original hash unchanged, recovery when restored |
| W09 | Harmless low/high-entropy test fixtures and legitimate batch writes | Correct entropy observation; correlated suspicion without claiming ransomware proof |
| W10 | Audit File System success + test path SACL; audit disabled/denied; reused PID | Matching 4663 evidence; absent/ambiguous evidence reported; response refused without all checks |
| W11 | ClamAV EICAR test under Monitor in isolated VM | Detection in central Alert History, seven-second toast, unread bell, no deletion |
| W12 | Protect test on EICAR in explicit disposable response scope | Pinned ClamD peer verified, sealed evidence and metadata written, source marked for deletion only after durable evidence; correct audit |
| W13 | Mismatched ClamD pin, untrusted TCP peer, locked file, changed hash, junction/hard link, excluded/system path | Response refused, original retained, explicit warning |
| W14 | Quarantine quota, write failure, service stopped mid-response | No removal without sealed evidence and metadata; preserve failed/uncertain evidence and report |
| W15 | Local evidence export in isolated review folder | Explicit confirmation, SHA-256 matches, no overwrite or original-path restoration |
| W16 | Contain mode with benign writer, missing/stale audit evidence, service or unlisted process | No process terminated; containment refused |
| W17 | Approved isolated test double for response identity/termination checks | Only specifically eligible disposable noncritical process with all evidence checks can be targeted; verify PID lifetime, file identity, access rights and failure paths. Do not run live ransomware. |
| W18 | Queue many short-lived incidents and simulate abrupt restart before/after central commit | Every durable open/close reaches Alert History; central delivery cursor prevents duplicate replay |
| W19 | Validate event 4201, Syslog/SEQ/Wazuh/Elastic, email and JSON alert exports | Matching enabled routes and levels; receiver outages observable |
| W20 | PDF, JSON attachment, scoped REST token, telemetry and AI | Endpoint section present only as configured, explicit incomplete coverage, no sealed payload or key exposure |
| W21 | Settings authorization/CSRF, exclusion changes, engine pin mismatch, theme and search | Existing admin gates, audit records, no untrusted markup, consistent UI |
| W22 | Sustained workload, 100,000-entry traversal, many findings, slow engine, shutdown | Measure service responsiveness, storage growth, memory, false positives and shutdown behavior; tune before rollout |

## Decisions and remaining risks

The module is a user-mode detector and restricted responder, not a kernel minifilter or certified antivirus/EDR. It cannot guarantee interception before file modification; locked files, missed notifications and fileless/unknown malware can evade detection. A local admin/SYSTEM compromise can bypass monitoring and tamper with local evidence. First canary enrollment must occur on a trusted host. File-state scopes reset when paths/exclusions change, and the sliding behavior window resets at restart. Per-file content limit is 1–100 MiB, traversal is capped at 100,000 entries, and watcher queues can overflow. Entropy is sampled, not proof of encryption. Process evidence uses Security auditing rather than ETW, and a signature on the executable file does not prove the code currently loaded in a process. Automatic actions are narrow and disabled by default. Third-party feed authenticity and licensing remain the operator's responsibility; per-feed freshness is not independently verified. Engine binary pinning is not hardware-backed attestation. ClamD is separately installed and maintained. Quarantine stores file bytes, not all NTFS metadata; DPAPI is machine-bound and not a replacement for ACLs and independent backups. The offline recovery helper has a separate local audit log. No automated restore to original paths or network isolation is provided. The endpoint SQLite store and quarantine vault are separate from standard database cleanup; set operational storage/retention procedures. API/dashboard snapshots are bounded while durable alert transitions are queued independently. External notification delivery is subject to existing receiver settings, log thresholds and availability. A crash after central database commit but before external log forwarding can still interrupt forwarding. No performance or false-positive benchmarks have been established. Complete W01–W22 and an independent security review before production use of automatic response.
