# V46 — ClamD resource telemetry repair

V45 could show valid physical-memory samples but no ClamD counters. Its .NET Process property calls could request access not held by the LocalService worker. The exact Windows failure was hidden by a catch-all. This is a plausible cause of the reported symptom, not a confirmed live diagnosis.

V46 queries the SCM-registered clamd PID using the standard installation image and a PROCESS_QUERY_LIMITED_INFORMATION handle. GetProcessMemoryInfo (PROCESS_MEMORY_COUNTERS_EX) supplies working set/private commit, and GetProcessTimes supplies CPU deltas normalized by logical CPU count. CPU is unknown until two readings of the same process lifetime; process restart or lost identity clears the delta. A failed memory query does not discard an otherwise verified CPU measurement. Failures are shown with a stage and Win32 code when available. Nonstandard image/port registrations remain unsupported by this collector. History remains bounded to 120 samples and memory only.

The existing fixed, administrator/SYSTEM-only periodic query-access task now permits the same narrowly scoped query ACE when Endpoint Protection is enabled in Monitor mode on standard port 3310. The task retains its standard service, image, loopback and live-PID checks; it does not grant VM read, terminate, or full process access to LinkScope. Protect/Contain retain their trusted path requirement and existing per-response hash verification. No scanning policies, response scopes, signature settings, resource thresholds or service identities are changed.

Upgrade using the generated setup. Allow the installed query-access task to run and two resource samples to arrive. If necessary, inspect the task from elevated PowerShell:

```powershell
Get-ScheduledTaskInfo -TaskName 'LinkScope ClamD Query Access'
Get-CimInstance Win32_Service -Filter "Name='clamd'" | Select-Object Name,State,ProcessId,StartName
```

The task is not exposed as a web action. Do not run LinkScope as SYSTEM or change ClamD's service identity to work around missing counters. A standard installation can request the existing fixed maintenance task from an elevated administrator session with `Start-ScheduledTask -TaskName 'LinkScope ClamD Query Access'`. If it fails, capture the task result and dashboard diagnostic.

Microsoft API documentation: https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getprocessmemoryinfo ; https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes

Validation: see ENDPOINT-TEST-RESULTS-V46.txt. Native Windows compilation, runtime P/Invoke and installed task behavior have not been tested here. A native self-check for query-only counters on the current process was added, but does not substitute for testing the actual LocalService-to-ClamD ACL on Windows.
