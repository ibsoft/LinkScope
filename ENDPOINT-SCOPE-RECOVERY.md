# Endpoint scope changes (V12)

Changing Endpoint Protection monitored paths already reconfigured watchers and the USN monitor in V11. The persistent `findings` table, however, did not retire obsolete coverage warnings. An access-denied warning for a former root could therefore remain active indefinitely, even after a successful scan of the new root.

V12 reconciles operational findings before the first enabled scan tick on startup and after a policy change. Removed or excluded file paths retire their scan-error, size-limit and incomplete-engine-scan warnings. Former exact configured-root availability warnings are retired when that root is no longer configured. Removed-volume journal warnings are retired; a warning on a still-monitored volume remains active. Warnings are closed transactionally with the corresponding durable alert outbox transition. Existing incident history, canary baselines, malware, heuristic and canary violations and quarantine evidence are retained. Historical scan activity and unread historical alerts may still mention the old path. A scope change is not evidence that a former threat has been remediated.

The scanner filters late filesystem watcher events against the current policy before deferral, and a successful full directory enumeration clears the directory's previous access-error warning. Existing V11 journal checkpoint scope isolation remains unchanged. This update does not elevate the scanner or change Windows filesystem permissions.

## Windows acceptance check

1. Upgrade/repair the existing installation; do not reinstall ClamAV or reset the endpoint database.
2. Save `C:\unx` as the monitored root. If existing canaries or response paths are outside that directory, retain their specific paths as needed or explicitly reconfigure those settings; validation does not silently remove them.
3. Confirm `Protected paths` shows the saved policy. Wait for the next endpoint collection and alert delivery. The obsolete Desktop scan-error alert should no longer be active; historical records should remain.
4. Check for any new scan errors within `C:\unx`, which should still be reported. Check that canary and malware findings remain intact.
5. Restart LinkScope and repeat. Reconciliation is idempotent and runs on startup as well as policy changes.

Portable checks: `python tests/validate_endpoint_scope.py`, `python tests/validate_endpoint.py`, `python tests/validate_usn_journal.py`, `python tests/validate_endpoint_activity_version.py`, `python tests/validate_canary_setup.py` passed in the development container. A native C# self-check fixture was added to `SelfCheck.cs`; Windows compilation, native execution and the user's actual database remain untested.
