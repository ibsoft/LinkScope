# V48 — Containment Test Center

Endpoint Protection → Test center (administrator). Live readiness is explicitly separate from read-only diagnostic results, historical incidents and local lab exercises. Stale or disabled telemetry never shows a current pass. The diagnostic POST uses the existing authenticated administrator/CSRF/origin enforcement. It does not expose a command runner or accept arbitrary process IDs. The optional marker must be an existing safe, non-excluded protected path of the form `LinkScope-Containment-Lab-<32 hex>/audit-marker.txt`. The service uses the same bounded 4663 matching logic as production and queries the expected lab process using a limited-information handle. This does not test the service's terminate access.

Checks use production entropy and corroboration functions, canary template hashes, negative malware-verdict gate tests, current configuration, Security log readability and optionally fresh lab writer identity. No positive malware verdict is injected. No changes to the production containment/quarantine algorithms or permission policy. In-memory detector checks do not prove a live ransomware incident or successful quarantine. Results are returned to the browser and not written as production incidents.

## Isolated local exercise

On a disposable Windows VM, use an existing dedicated test directory inside the configured protected scope. Configure successful file-write auditing on the disposable parent and inheritance for new subdirectories. Keep existing primary AV enabled. In Windows PowerShell 5.1:

```powershell
.\Test-LinkScopeContainmentLab.ps1 -LabRoot 'C:\Apache24\LinkScope-Ransomware-Test' -TerminateChild
```

The path is an example, not built into the application. A new GUID-named folder is created; a harmless writer compiled locally writes exactly one marker and waits. Paste the printed marker path into the Test Center within 30 seconds; click Run diagnostics. If selected, the local script terminates only its own child after 40 seconds. That is a local process lifecycle test, not service-driven containment. Without the switch the child exits normally after about 50 seconds. Local audit evidence and exit observations are written to `lab-report.json`. Run with `-WhatIf` to preview. No recursive deletion, production canary editing, audit-policy changes or response permission grants are performed.

Optional `-Eicar` creates only the standard harmless EICAR test file in the new lab folder. Use this only in an isolated VM, with an approved disposable response directory and Protect or Contain selected. Check the exact file path, fresh malware finding and quarantine receipt. A different AV may intercept the write; that is not proof of LinkScope response. The lab leaves its files for evidence review; remove the disposable lab manually when done and permitted. For live canary tests, enroll and baseline a separate disposable canary, edit only that file, then restore and verify. No actual malware is supplied or required for these exercises.

## Validation boundary

Browser and static regression tests only. No Windows native compiler, PowerShell runtime, ClamAV installation or real Windows event log in the build environment. The true service termination path remains untested. Existing directory permission issues are not modified. See ENDPOINT-TEST-RESULTS-V48.txt.
