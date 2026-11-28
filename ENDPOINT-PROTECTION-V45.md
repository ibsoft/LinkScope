# LinkScope V45 — Endpoint workspace

## User interface

Endpoint Protection opens on a compact overview, with four high-priority indicators, a consolidated current protection state, and a short attention summary. Seven views organize the existing features: Overview, Scanning, Ransomware, Maintenance, Resources, Evidence and Quarantine. The dashboard preserves the existing settings, actions, confirmation dialogs and evidence. Scan counters are separate from advanced queue/journal details. Status-card navigation reveals the appropriate view and opens any containing disclosure. No new external UI dependencies are introduced.

## Scan status and observability

Baseline pause/running status is independent of signature freshness and folder coverage warnings. An unavailable engine is shown as a dependency for a running baseline. The scanner publishes a small immutable worker-phase frame independently of the completed tick; the API exposes it alongside the last completed snapshot. The dashboard shows the phase and elapsed time, not an asserted completion percentage. A stale snapshot is explicitly indicated. Endpoint GET requests have a bounded 12-second browser timeout; acknowledgement status is fetched independently, so it cannot block the rendering of a successful endpoint response. Unchanged snapshot DOM is reused. The scan engine, background pacing, resource thresholds, threat decisions, response permissions and storage schema are unchanged.

This resolves contradictory UI status and improves diagnostics; it does not establish or fix a specific Windows scanner deadlock. A long synchronous file/engine operation or OS resource contention can still delay a completed snapshot. Worker-phase telemetry is advisory, not a watchdog or proof of a stuck worker. No automatic kill/restart of the antivirus engine is introduced.

## Upgrade

Extract into a clean directory, rebuild using `Rebuild-VisualStudio.cmd Release`, install the generated setup, then sign in and hard refresh. V45 archive version metadata is supplied. Existing persisted configuration and evidence should be preserved by the normal upgrade process; back up the data before upgrading.

## Validation

The new full-page Chromium fixture exercises the actual renderer using synthetic endpoint data, including all view controls, pause/engine separation, stale telemetry, evidence routing, and overview at five widths in both themes. V44 resource renderer, V40 detector contracts, setup and Visual Studio source checks also pass. No Windows native build or real ClamAV/service execution was available. Older renderer-specific test fixtures that assume a single ungrouped dashboard are not revalidated by these checks.
