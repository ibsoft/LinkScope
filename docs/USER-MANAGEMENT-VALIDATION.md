# Portable validation results

12 suites passed. These are not Windows compilation or live browser tests. Browser navigation test not run in this update; prior attempt was blocked by environment policy.

## validate_canary_setup.py

```text
PASS: three fixed harmless templates, valid ZIP/XML Office packages, SHA-256 changes on mutation
PASS: Word and Excel templates opened by portable document readers
PASS: setup opt-in default, original user creation, explicit baseline seed, no overwrite/recreation and fixed-original recovery wiring (source assertions)
PASS: immutable baseline INSERT, 1,000-row activity retention, detection outbox, dashboard/API/report data, local signature update controls
Windows compilation, ACLs, Office compatibility in Microsoft Office, ClamAV runtime, notifications and PDF/API end-to-end tests remain pending.
```

## validate_clam_signature.py

```text
PASS: official key import/fingerprint, genuine synthetic detached signature, tampered payload, wrong signer, malformed signature, expiry/revocation status rejection, setup ordering and embedded resources. Windows runtime not tested.
```

## validate_clamav_setup.py

```text
PASS: ClamAV setup source/build inclusion, readiness-state branches, loopback configuration, service/update safeguards, wizard command length, and C# delimiter checks. Not Windows compilation or runtime tests.
```

## validate_desktop_app.py

```text
PASS: response type shares correct namespace in a separately compiled source; all timeout constructions qualified; installer shortcut and optional managed PWA wiring; policy ownership guards; non-caching PWA. Windows compilation, COM shortcuts and policy application not executed.
```

## validate_endpoint.py

```text
PASS: all JavaScript files parse with Node.js
PASS: default endpoint policy is disabled, monitor-only, no response targets or engine pin
PASS: project XML, resource existence and Build.cmd parity
PASS: all C# compile items explicitly included once; EndpointResponse declaration, references and missing-file diagnostics checked
PASS: endpoint settings fields exist, HTML IDs unique
PASS: actual SQLite schema and SQL literals for file state, canary baseline, incident/open-close outbox and bounded deletion
PASS: C# lexer delimiter checks (not compilation)
PASS: portable validation completed; Windows compilation, runtime and security testing remain required.
```

## validate_endpoint_activity_version.py

```text
PASS: scoped SQLite acknowledgement preserves all history, active incidents, unrelated categories and later unread events
PASS: live UI state logic in Node.js (not visual rendering)
PASS: authenticated/CSRF-protected route, category-only toast dismissal, reconciliation gating and telemetry wiring (source assertions)
PASS: every page version placeholder, embedded-resource build wiring and real Git merge-history selection (portable equivalent)
```

## validate_endpoint_layout_updater.py

```text
PASS: actual renderHealth places 8 summary and 6 scan statistic cards above stable activity controls; evidence below; repeat/disabled refresh
PASS: bounded updater waits, service PID exclusion, safe restart/rollback order and no-wrap menu font settings (source checks)
```

## validate_endpoint_maintenance.py

```text
PASS: maintenance fixed action, state semantics, canary reservation, log patterns, version wiring, project XML and JavaScript
```

## validate_navigation_static.py

```text
PASS: nine navigation headers, ten consistent Font Awesome icons, active routes, Report link, hamburger, utility icon artwork, no font files
PASS: responsive navigation and existing Report/notification wiring (static source assertions)
PASS: GUI setup build, hidden child-process flags, optional MSI workflow and deploy instructions (static source assertions)
PASS: strict single-row grid, initial compact state, versioned theme resources and overflow fallback
```

## validate_provider_sources.py

```text
PASS: provider formats, local elevated editor, validation/merge safeguards, private configuration and logging, header icon sizing, login label, and summary-card-first dashboard (static checks only).
```

## validate_setup_build.py

```text
PASS: MSBuild setup project, x64 GUI settings, exact payload resource, build order, conditional MSI copy, cleanup and standalone build compatibility (static checks only).
```

## validate_users.py

```text
PASS: real locally generated authenticator QR decoded to exact otpauth URI
PASS: role/CSRF gates, password derivation and MFA replay source checks, audit attribution, resource parity and JavaScript syntax
Pending: Windows compilation, C# self-tests, browser login/enrollment, authorization and DPAPI runtime validation.
```
