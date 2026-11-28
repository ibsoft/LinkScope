# V63 — Post-probe validation and evidence reconciliation

## Evidence from V62

The supplied Windows report confirms loaded daily version 28194 equals the official DNS-advertised version. Actual service writer Event 4663 record 1714016 matched the new marker, PID 19280, image and write mask 0x6 after watermark 1714014; cleanup was verified. The general historical audit check was executed before the probe and found no recent events at that time. The external writer, live canary, quarantine and containment were not tested. No production certification follows from those observations.

## Changes

The suite now executes five stages: initial readiness, initial diagnostics, one existing self-writer audit probe, final diagnostics, then a fresh readiness fetch. Initial observations remain visible in an expandable section and in the exported text report, with original evidence and timestamps. Only final observations and the actual live test results count toward the final totals; initial issues are not deleted or retroactively relabeled. Final diagnostics require a server timestamp no earlier than the preceding server observations; inconsistent or missing timestamps cannot produce a final Pass. Final readiness requires a non-stale sample collected at or after the final diagnostics timestamp; the browser retries for an eight-second polling window (individual HTTP requests retain their existing twelve-second timeout). If a usable sample is not returned, the final readiness is Review/Not tested, never a recycled initial Pass.

General audit diagnostics now read the recent Security log in reverse using the unfiltered query method verified in V62. Local filtering requires a real Event 4663, positive record ID, timestamp in the last fifteen minutes, File object type, protected/nonexcluded path and a matching write/delete mask. The bounded scan remains three seconds and now inspects at most 512 Security records. No-match, timeout and truncated reads remain inconclusive. The successful two-handle live probe, official DNS worker, production writer correlation, privileges, response policy, and containment safeguards are unchanged.

The external writer, live canary and EICAR quarantine remain guided manual isolated exercises, and production termination is not executed. These exercises cannot be inferred from self-writer evidence and the automatic suite does not modify canary enrollment, create malware-test artifacts, or launch/terminate other processes. Select only a dedicated disposable test folder.

## Development verification

Five targeted scripts passed: validate_audit_diagnostics_v55.py, validate_automated_suite_v59.py, validate_signature_versions_v57.py, validate_live_audit_v56.py, validate_guided_test_center_v58.py. Chromium tests use mock API responses, including initial missing evidence followed by final evidence, report export, stale final telemetry, replayed final diagnostic timestamps, scope invalidation, timeouts, missing/contradictory audit proof and role restrictions. Static tests inspect C# source and installer configuration; no C# compiler or Windows host execution was available. Node syntax check passed. Native execution of V63 and the full historical regression suite are not verified.
