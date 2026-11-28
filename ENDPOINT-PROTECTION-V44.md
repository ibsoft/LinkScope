# LinkScope V44 — adaptive endpoint resource management

## Settings → Endpoint Protection

- Pause background scans when memory is low: enabled by default. Scheduled and manual baseline work only. Existing real-time, canary, watcher and USN processing remain governed by their existing policy and engine availability.
- Minimum available memory: 512 MiB, configurable 128–8192; percentage floor: 10%, configurable 5–40. Effective floor is the larger of those two values, capped at half of physical RAM. Two consecutive samples below the floor pause background work; two samples at or above the floor plus the larger of 128 MiB or 3% of RAM (capped at total RAM) resume it. Samples are taken on worker cycles at least five seconds apart. Not an instantaneous memory guarantee. Unavailable memory measurement is reported and does not apply the RAM pause; disk/battery policies remain.
- Maximum background files per work cycle: 4, configurable 1–4. This is a sequential batch limit, not a change to ClamAV thread concurrency. LinkScope already uses one scan worker.
- Scheduled update memory deferral: 60 minutes, configurable 0–120. Applies to LinkScope's optional scheduled refresh only, not FreshClam's own automatic refresh, manual refreshes, or an update already running. A due request retains its existing persisted schedule while delayed. At the deadline the memory-specific hold ends; existing authorization, busy and cooldown checks still apply. No signature updates are disabled.

## Dashboard

Resource management displays available/total physical RAM, registered ClamD service working set/private memory and normalized CPU usage. CPU is unavailable until two successful samples of the same process identity exist. Process telemetry uses the registered service PID and process name; custom ports or access failures display unknown. This is diagnostic only and does not change response authorization. The 120-sample history is bounded in RAM, not persisted; actual time span depends on scan durations. Missing or stale readings are shown as unavailable. Baseline pause reason is displayed explicitly.

## ClamAV

No hard process memory cap, forced GC, service termination, antivirus exclusion, or automatic engine config rewrite. Existing ClamAV remains required for independent signature scanning. A behavioral-only mode with ESET is not implemented. ClamAV's normal resident signature memory is not reduced by this change. Administrators may separately evaluate `ConcurrentDatabaseReload no` in the installed clamd.conf, with backups and a maintenance window: reduces simultaneous database reload memory at the cost of scanning interruption. V44 permits this yes/no setting in both existing standard-config validators; it does not change it automatically. FreshClam remains enabled. Do not treat this setting as a guarantee against reload pressure.

## Upgrade and verification

Extract a clean source tree and run `Rebuild-VisualStudio.cmd Release`, then upgrade with the generated installer. Existing protected paths and security findings are retained by the existing upgrade workflow. New policy fields may invalidate older cache/baseline checkpoints; expect a reconciliation scan. Version metadata is V44. Test first on an isolated Windows VM. Verify actual service build, memory sampling with the service identity, pause/resume, queued real-time events, canaries, scheduled refresh deferral and signature readiness under load. Portable static checks and Chromium fixtures ran; no Windows compiler/runtime or native memory stress test was available. Two inherited regression fixtures were updated for the server-owned ProfileDefaultsApplied flag and configurable entropy settings, retaining their assertions on defaults and warning-only behavior. See ENDPOINT-TEST-RESULTS-V44.txt. Native SelfCheck resource hysteresis assertions are included but not executed here.
