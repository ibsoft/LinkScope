> Historical documentation — superseded by V50. Setup no longer adds user profiles or creates home-directory canaries. See [ENDPOINT-PROTECTION-V50.md](ENDPOINT-PROTECTION-V50.md). Existing settings remain unchanged.

# Default user profile protection (V26)

## Installation and upgrade

Run LinkScopeSetup.exe normally under the Windows account you want to protect. The wizard sends the pre-elevation user SID in a versioned setup token, independently of canary selection. The elevated installer resolves the SID using the machine's ProfileList registry, and accepts an existing local fixed-drive, non-reparse profile path. It does not derive the profile from the LocalService or LocalSystem accounts. A direct interactive CLI installation without a wizard token uses the invoking account instead. No profile is guessed in session 0.

Fresh installations enable Endpoint Protection in Monitor mode, real-time monitoring, a 24-hour scheduled scan interval and a 100 MiB file limit. An empty disabled policy from an earlier installation is treated as unconfigured. ClamAV must be operational for signature detection. An enabled existing policy receives the profile root once, if it is not already covered, while preserving all previous protected paths, ordinary exclusions, response mode, canaries and scan settings. Existing disabled policies with saved paths remain disabled at this migration step (explicit setup canary enrollment retains its existing behavior). A saved marker prevents subsequent upgrades from re-adding a deliberately removed profile. If discovery or policy validation fails, setup logs the reason and keeps the existing policy; configure paths manually.

## Add other paths

Settings > Endpoint Protection > Protected paths (user profile and additional local paths). Add one absolute local path per line, then save. For example:

```
C:\Users\Example
C:\unx
D:\Projects
```

A drive root is also accepted. Existing nested paths are preserved, even if redundant. Additional users and redirected known folders outside the profile must be added explicitly. Network files copied to a monitored local destination are covered by the existing arrival detection; a remote UNC share is not a supported monitoring root.

## Exclusions

The new Background-only excluded paths editor skips exact paths and descendants during scheduled or manual full traversal. It does not apply to USN, real-time watchers, Downloads reconciliation or exact-file probes. A background exclusion never skips traversal needed to reach an enrolled canary. Full-scan cleanup does not interpret intentionally skipped files as missing or retire their malware/coverage findings solely because they were skipped.

Defaults are narrow paths within the chosen profile: Windows INetCache, Chrome and Edge Default Cache/Code Cache/GPUCache, Firefox cache2/startupCache in up to 20 discovered local Firefox profiles, and specific NTUSER/UsrClass registry-hive files and transaction logs. Firefox discovery is best effort; other browser profiles can be added manually. No entire AppData, Temp, Downloads, Desktop or Documents exclusion is installed. No filename wildcard or all-scanning exclusion is added by default. Existing all-scanning exclusions are retained and take precedence. Review them if a path appears unprotected.

## Acceptance checks (Windows 11)

1. Rebuild in Visual Studio Release, run the wizard normally, upgrade both services, and verify Settings lists the intended user's profile and previous paths.
2. Add an extra local folder; save, reload, and confirm the profile and extra folder persist. Upgrade again and check that intentionally removed paths are not reintroduced.
3. Check that the background exclusion editor contains only intended paths. Create a benign test file in a background-excluded cache and check that real-time events still reach the scanner. Confirm canary checks remain active.
4. Check ClamAV with `LinkScope.exe --endpoint-engine-self-test`. Test a downloaded/copied EICAR test file in a monitored location, where another antivirus has not intercepted it. Inspect the actual recorded verdict.
5. Test a new configuration without canary enrollment and an existing disabled configuration with saved paths.

No Windows build or runtime was performed in the packaging environment. Portable tests exercise source integration, JavaScript settings round-trip, and existing SQLite regressions. Native assertions were added to the existing C# self-test. A changed scope starts its own journal reconciliation; stored historical records are retained. The existing native file-access, reparse-point, scan-size, queue and full-traversal limits remain. This is post-event monitoring, not a pre-execution antivirus driver. Keep primary antivirus protection active.
