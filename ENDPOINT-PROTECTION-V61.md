# V61 — Live audit retrieval and DNS refresh correctness

V60 host report: Security channel access passed, marker write and cleanup passed; exact filtered audit query yielded zero records and timed out. Official DNS status was WaitingToRun, which is an internal task state rather than a resolver error. Neither establishes that the expected event exists or that the official database is outdated.

## Audit probe

Before writing the unique marker, read the newest Security record using the unfiltered channel reader. If no valid watermark can be read, do not create the marker. After writing, inspect newly observed records in reverse order, stopping at the watermark. Filter Event 4663 in managed code; still require the exact marker path, File object type, write/append mask, PID, image, timestamp, positive record ID greater than the watermark, and successful cleanup. The browser independently checks that the proof record ID exceeds the returned watermark without converting to a floating-point number. Limits remain 8 seconds of reads and 512 unique records; these limits are not a guarantee of total request duration. Report counts for all new records, 4663 records, exact-path candidates, retries and whether the watermark was reached. No changes to production correlation, response policies, permissions, marker creation or cleanup. If Windows emits no matching marker event, result remains Review.

## DNS

Keep the last completed native resolver answer separately from the active lookup, with actual completion UTC. Use a single long-running worker task, retain a usable previous sample during refresh (maximum 15 minutes; advertisement age still validated), and invalidate it on completed failure. A pending initial lookup is explicitly pending, not a DNS error or a successful version comparison. Include completed sample UTC in evidence. No changes to download cooldowns or production response. A blocked native lookup does not spawn additional concurrent workers; the result becomes unavailable as the cache expires.

## Validation

Ran five targeted scripts: validate_signature_versions_v57.py, validate_audit_diagnostics_v55.py, validate_live_audit_v56.py, validate_automated_suite_v59.py, validate_guided_test_center_v58.py. Static checks and Chromium mock API tests only. Added browser rejection of missing watermark and record at/before watermark. Node syntax check passed. Native Windows compilation, audit-event generation for service probe, and live DNS resolver behavior were not tested. No production certification.
