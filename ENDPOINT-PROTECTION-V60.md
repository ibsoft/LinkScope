# Endpoint Protection V60 — evidence-first validation

This version is based on the V59 source archive. It does not claim that Windows event delivery, DNS resolution or production containment has been verified on the target machine.

## Live audit probe

The probe uses the same File/System 4663 query shape as the general audit check, with a 15-minute native query window. It stops reading pre-probe records, polls for fresh events within an 8-second read budget, deduplicates record IDs and limits inspected unique records to 512. Native query setup and transport are not guaranteed to complete within the read budget. The browser request timeout is 20 seconds. An event must be a fresh 4663 record with a positive record ID, the exact generated marker path, a write/append access mask, the service PID and its executable image. The probe returns structured marker and event evidence only when the corresponding observations are made. The dashboard checks this evidence before displaying the exact writer test as Pass. A timeout, missing event, invalid/missing proof, or inconsistency is inconclusive, not a successful test. No production correlation/termination gates are relaxed.

## Official ClamAV signatures

The bounded background DNS lookup uses the configured resolver with FQDN, no multicast, no hosts-file lookup and local cache bypass. Failed/invalid cached comparisons retry after two minutes (successful comparisons after ten minutes). The status is Unknown if the official daily version cannot be established; the separate 72-hour publication age remains visible. DNS errors, task states, invalid TXT fields and out-of-window advertisement ages are reported. This lookup is advisory, not signature authentication. A matching current DNS advertisement and valid loaded database metadata are necessary for the Current status; a newer archive on disk still produces a reload warning. No changes to provider cooldowns or production scan response policy.

## Report integrity

Readiness snapshots must have a server collection timestamp and be at most 20 seconds old when captured. Engine and response readiness additionally require check timestamps within 90 seconds of that snapshot. Missing expected rows, duplicate check names, invalid states, empty evidence, missing timestamps and inconsistent audit verdicts are not counted as passes. The report displays evidence source UTC, distinguishes configuration-only and in-memory checks from live checks, and gives a partial report if a suite is interrupted after it begins. Manual external writer, real canary, quarantine and containment exercises remain Not tested in the automated suite. The test uses only an already-authorized disposable directory; no ACL changes, real malware, or process termination. The marker is uniquely named and created using CREATE_NEW and DELETE_ON_CLOSE.

## Installation and verification

Rebuild using Rebuild-VisualStudio.cmd Release, run the usual Setup upgrade, then select the disposable LinkScope-Ransomware-Test directory instead of the entire application root. Run the automated suite and export the report. Investigate any Review/Unknown/Not tested result rather than assuming it passed.

## Validation performed

See ENDPOINT-TEST-RESULTS-V60.txt. Native Windows compilation, installer execution, actual event delivery, live DNS integration, quarantine and containment were not performed in the development environment. The full historical regression suite was not run. Browser tests explicitly used mocked service responses; these are not runtime evidence. Neither the V59 audit timeout nor the DNS lookup failure is confirmed resolved on the target host.
