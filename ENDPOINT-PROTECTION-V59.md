# V59 — Automated validation suite and installed lab script

The Test Center now offers **Run all automated tests** above the guided stages. Choose an existing disposable response directory and confirm the benign file probe. The sequence captures current readiness, calls the existing read-only diagnostics API, then calls the existing live audit probe API. It displays progress and opens Step 6 with individual results, evidence, and a downloadable UTF-8 text report. Cancel does not invoke either endpoint. A directory that becomes unavailable before the audit stage is not used. Errors remain visible as Review; manual external writer, canary, EICAR quarantine and production containment exercises remain Not tested. No new service API, permission grants, or production containment actions are introduced. The report is session-local until exported.

## Installed lab

The normal installation and upgrade deploy the embedded `Test-LinkScopeContainmentLab.ps1` into `%ProgramFiles%\LinkScope\lab`. The installer creates a restricted directory, stages a new file, replaces the existing script on upgrade, applies the restricted file ACL and checks byte equality with the embedded payload. Both MSBuild and Build.cmd embed the script. It is not executed during installation. The existing uninstall retains installation files; the lab script is retained with them. Use elevated Windows PowerShell 5.1 on the monitored host:

```powershell
& "$env:ProgramFiles\LinkScope\lab\Test-LinkScopeContainmentLab.ps1" -LabRoot 'C:\YourDisposableTestFolder'
```

Use a disposable existing application directory already included in the applicable protection scope. Step 4 uses the installed path. The script's optional EICAR and local child termination switches remain manual and are not used by the suite.

## Validation and limitations

Seven selected regression scripts passed, including mocked Chromium tests for sequential requests, confirmation cancellation, timeout/error handling, scope invalidation, report download, viewer restrictions, both themes and responsive widths. Static checks cover resource wiring, installation copy and verification. JavaScript syntax checked. Native C# compilation, Windows file ACL/deployment, and live Security event delivery not tested here. V58's exact live audit query timeout was not changed; the new report surfaces it as Review if it recurs. No claim of production containment certification.
