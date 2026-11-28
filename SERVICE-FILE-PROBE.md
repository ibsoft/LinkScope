# V19: exact-file detection and service-access diagnosis

V18 prioritized arrivals, but this cannot overcome the LocalService account's ACLs or an existing antivirus removing a file. The actual reason for a missed EICAR detection on the target PC is not yet known. V19 adds a durable administrator-only exact-file request processed by the normal endpoint scanner, before queued arrival/background work. The probe records a fresh scan verdict (not a previous activity row), preserves the standard scope and exclusion checks, and explicitly disables automatic response for this diagnostic. Normal automatic monitoring continues under the existing policy. A 90-second client wait is not a guaranteed scan deadline; a request can complete later and expires after 24 hours. The pending request queue is limited to 64. Canary checks still precede the probe. No automatic ACL changes or third-party AV changes are made.

## Windows acceptance procedure

After rebuilding and upgrading, from elevated PowerShell, run:

```powershell
$exe = Join-Path $env:ProgramFiles 'LinkScope\LinkScope.exe'
& $exe --endpoint-engine-self-test
```

The first command streams the standard harmless 68-byte EICAR test string to the configured ClamAV engine from memory and expects a FOUND verdict identifying EICAR. No file is written and no endpoint alert is created by the engine-only test.

Then select the exact existing downloaded file (adjust its filename):

```powershell
$file = Join-Path $env:USERPROFILE 'Downloads\eicar.com.txt'
Test-Path -LiteralPath $file
& $exe --endpoint-scan-file $file
& $exe --endpoint-file-status $file
```

The service probe runs the actual scanner in the running service's identity. `Infected` means the real service scanner recorded the signature detection; the dashboard should receive its normal alert. `Failed` with UnauthorizedAccessException identifies the service file access problem. `Missing` means the scanner cannot find the file; check ESET and the browser's download history. `Clean` means ClamAV did not report a signature for the file bytes. `Excluded` means policy excludes the file. `Unavailable` means no verdict was produced. If no result arrives, check the installed build, service state and logs. A direct admin probe is not proof of service access.

If the service probe confirms an ACL failure, explicitly decide whether to grant the service read access to a specific monitored folder. For example, for the current user's local Downloads folder (adjust for a redirected folder):

```powershell
$folder = Join-Path $env:USERPROFILE 'Downloads'
icacls $folder /grant 'NT SERVICE\LinkScope:(OI)(CI)(R)'
```

Only run after confirming that the chosen folder is the intended monitoring location and is not a reparse point. This adds an inheritable read ACE to that folder, not the entire user profile or drive. It may not fix protected ACLs or parent metadata restrictions. It grants the service access to files in the chosen directory; do not grant it broad access to C:\ or disable ESET. Existing ACLs and canary originals are otherwise untouched. Re-run the exact-file test, then repeat the normal download/copy acceptance test and inspect activity. If ESET intercepts the file, do not disable it merely to force a test; use an isolated test environment if needed.

Other fixes: retry transient unauthorized-access errors with the existing bounded real-time retry policy; preserve a USN pending item when a newer watcher event arrived during scanning; report offline background scans as incomplete rather than treating missing engine verdicts as completed coverage. These are source-level fixes, not proof of the cause on the target PC. Native Windows compilation and EICAR end-to-end testing were not available in the Linux environment.
