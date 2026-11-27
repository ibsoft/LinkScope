# V13 — USN transport and scope diagnostics

V12 disposed `IAsyncResult.AsyncWaitHandle` before calling `EndRead` or `EndWrite` on an asynchronous named pipe. This is a credible cause of the Windows error `Safe handle has been closed`. V13 uses task-based pipe I/O with bounded waits, closes a timed-out connection, observes late faults, and identifies the failing stage. The existing journal retry, durable queue, checkpoints, and fallback are preserved. No service privilege or ACL expansion is introduced.

The Endpoint Protection page now displays the actual protected paths reported by the scanner at the top. Settings explicitly offers to retain exact canary file paths if a narrower scope no longer covers them. It does not silently retain a parent folder or a whole drive. If you want only C:\unx plus the enrolled canaries, replace the previous paths with C:\unx and accept the exact canary path confirmation. Check the active scope after saving and after the next fresh collection. A USN volume label C:\ identifies the volume, not necessarily the scan scope; the journal paths are filtered by the saved monitoring policy.

Access denied for in-scope directories remains an honest coverage warning, not a malware verdict. No automatic changes are made to protected Windows folders or personal-folder ACLs. Out-of-scope operational findings are retired using the existing V12 reconciliation; security history and canary baselines remain intact.

## Windows acceptance test

1. Extract to a clean directory, run `Rebuild-VisualStudio.cmd Release`, then upgrade/repair using LinkScopeSetup.exe. Both LinkScope and LinkScopeUsn must be updated, not just the dashboard.
2. In elevated PowerShell run `Get-Service LinkScope,LinkScopeUsn` and `fsutil usn queryjournal C:`. Both services should run and the journal must exist. No journal creation or resizing is automatic.
3. Run `LinkScope.exe --usn-self-test` using the rebuilt executable. The native regression fixture verifies 32 named-pipe round trips, complete reads, and a bounded read timeout, alongside parser fixtures. This is a test of local pipe mechanics, not the service ACL or native journal.
4. Check the dashboard for the actual scan scope and journal status. After the retry and a fresh sample, a successful journal transaction should clear the USN-unavailable finding. Create or edit a benign file inside the configured scope and check scan activity. Repeat outside the scope; it must not be scanned unless explicitly included.
5. Confirm canaries remain enrolled and genuine inaccessible paths remain visible if still in scope. If USN fails again, capture the complete stage-qualified error, both service states, and journal query output.

## Validation limits

Portable source checks, SQLite checkpoint/scope tests, Node syntax and path-selection tests passed. Windows build and native runtime tests were not performed. The existing layout CSS assertion failed and the full navigation browser test could not access a running Windows dashboard in this environment. No claim is made that NTFS volume access or named-pipe service integration has been verified on Windows.
