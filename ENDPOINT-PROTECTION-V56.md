# V56 — Controlled live audit verification

The reported Windows test showed that File System success auditing is enabled, the response directory has successful write/delete SACL entries, and three recent 4663 events were generated after manual activity. V55's earlier zero-record result preceded this activity. This is evidence that Windows generates audit events, not yet that the service correlates a particular external writer.

## Run the test

1. Rebuild and install V56 using the existing Setup workflow.
2. Sign in as administrator and open Endpoint Protection > Test center.
3. In Live audit verification choose a saved, verified response directory dedicated to testing. Confirm Run live audit test.
4. Review the selected scope, marker write, marker cleanup, exact Event 4663/service writer, and production containment rows. The last row is intentionally Not tested. A pass requires successful marker write, verified cleanup and matching audit evidence.
5. Run the existing read-only diagnostics again for the general recent protected-path evidence. For an external writer, continue to use the isolated lab script and exact marker correlation. The live audit probe does not test the external production correlation algorithm or process termination.

## Security and operational boundaries

The new POST route is administrator-only, requires the existing session CSRF validation, and is limited to one request per 30 seconds. The directory must exactly match a saved response path, be inside a protected scope, not excluded or a system location, exist and pass reparse checks. The service uses its current identity; the UI selects a verified directory and requires explicit confirmation. No arbitrary marker names or data, executable paths, commands or PIDs are accepted. The marker is a GUID-named benign TXT file created with CREATE_NEW and DELETE_ON_CLOSE, using a pinned directory and verified final path/file identity before writing. No existing files are overwritten or explicitly deleted. No additional ACL grants are made. If file creation is not permitted, the result reports the failure and skips audit correlation. The existing permission repair grants read/delete, not write; do not broaden production ACLs merely to make this test pass.

A bounded recent Security query targets the generated marker and requires matching ObjectName, ObjectType, write access mask, service PID, image and event time. Missing or timed-out evidence stays Review. The nominal query budget is five seconds and up to 64 records, with bounded read timeouts; Windows query construction, XML conversion or filesystem operations can exceed that budget. The browser request has a 12-second timeout; a timed-out client request may still complete on the service. No new privileges, simulated malware verdicts, quarantine or production termination are introduced. A normal file watcher may see the harmless marker. The probe result is displayed in the current browser session; the request is recorded in the existing user audit log. The result is not persisted as a production incident.

Setup continues existing scoped ACL provisioning and now directs administrators to the live test. It does not automatically write into every production directory during installation; the test is explicitly chosen after sign-in. Global audit policy, production writer correlation, detection/response policies and ClamAV signatures are unchanged.

## Validation

Seven selected portable regression scripts passed (static source checks and Chromium UI tests using mocked API responses). JavaScript syntax checked. Native C# 5 compilation, Windows CreateFile/delete-on-close, event-log XPath and service identity integration are unverified in this environment. Validate on a disposable directory before production use. Full historical regression suite not rerun.
