# V50 — Explicit server application protection scope

New installations have Endpoint Protection disabled, Monitor mode selected, and empty protected, excluded, response, and canary paths. The installer does not discover or enroll the interactive user's profile, seed browser-cache exclusions, create Documents canaries, or enable endpoint monitoring. ClamAV installation and the network monitoring service remain separate. Existing policies (including previously automatically added profile paths and canaries) are preserved on upgrade. The legacy ProfileDefaultsApplied field is retained for compatibility and marked true by setup without modifying other endpoint settings. Old installer canary-token and prepare/repair-canaries command routes have been removed; previous saved canary baselines remain intact.

## Configure a new server

1. Install LinkScope and open Settings > Endpoint Protection. Add the absolute paths of the application directories that require coverage, one per line. Enable Endpoint Protection and save; start with Monitor mode.
2. If required, use Endpoint Protection > Maintenance > Canary manager to explicitly enroll canaries inside a saved protected directory. No canaries are needed merely to enable monitoring. This operation uses existing service permissions and refuses replacement of previously enrolled files.
3. For automatic response, separately specify deliberately approved response paths, verify antivirus trust and freshness, then use the local V49 permission repair wizard where necessary. Containment has additional prerequisites; no policy or termination rules have been weakened in V50.

## Existing installations

Inspect saved Protected application paths and Canary paths. To discontinue old home-directory coverage, remove the old profile paths and their enrolled canary entries together, plus any obsolete response paths or termination executables referencing that scope. Save a valid policy. Files and recorded evidence are not automatically deleted. Removing a path from Settings does not undo Windows ACL/SACL repairs: use the V49 local rollback workflow when appropriate. Do not remove any intentionally protected directories.

The reported stale signatures, Security log access denial, quarantine ACL failures, Protect mode and empty termination allowlist are separate live host issues. V50 does not change Windows permissions or signature content, and does not establish that containment works. Existing V49 permission repair is retained.

## Validation

See ENDPOINT-TEST-RESULTS-V50.txt. Browser tests use mock telemetry. Native C# 5 compilation, PowerShell wizard execution, fresh install and upgrade on Windows remain to be tested.
