# V18 — Copied-file and download diagnostics

V17 can still miss a timely scan: one synchronous scan can occupy the endpoint worker, the durable journal is served after a background scan, and transient ClamAV errors can remove a path without a retry. V18 processes journal work before the guaranteed background step, chooses the oldest eligible arrival within the download/non-download priority class, and retries transient engine I/O and non-verdict replies up to three times. Ordinary write events remain in the normal/recent lane to preserve reserved capacity. All existing scope and exclusion checks, fixed canary monitoring, service identity, and response restrictions remain intact.

## Exact-file verification

Run from an elevated PowerShell after rebuilding/upgrading, replacing the path with the exact existing test file:

```powershell
& "$env:ProgramFiles\LinkScope\LinkScope.exe" --endpoint-file-status "$env:USERPROFILE\Downloads\eicar.com.txt"
```

This reads the actual service's retained activity and findings in SQLite (read-only), reports whether the file is in scope and in the durable USN queue, and performs a separate read-only ClamAV INSTREAM probe using the invoking administrator's file access. It does not create a service detection or modify the test file. If the executable is installed elsewhere, use its actual location. An absent activity row is inconclusive because the activity ring retains only the latest 1,000 entries. The direct probe is not proof of LocalService access. Service diagnostics now distinguish path metadata, opening, hashing, engine communication and verdict recording.

If the service reports access denied but the direct probe returns FOUND, inspect narrowly scoped read permissions for `NT SERVICE\LinkScope`, not all of C: or the user profile. If the file is missing, check the primary antivirus quarantine history, including ESET. Do not disable existing antivirus or add global exclusions to force this test. If ClamAV returns OK, verify the actual contents against the official EICAR test file and current signatures; a filename alone is not a detection criterion. If the direct probe returns FOUND but no recent service row exists, capture queue depth and USN status, and repeat with a monitored readable test directory. No ACL changes are applied automatically.

Native Windows compilation, EICAR detection, ACL behavior and throughput are not validated in the Linux packaging environment. The scheduler remains single-threaded, so an active scan can still delay a new arrival. No real-time pre-execution blocking is claimed.
