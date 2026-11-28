# V54 — setup-integrated permission provisioning

Base: V53. A successful normal Setup install/upgrade/upgrade-PWA now invokes the existing administrator-only permission provisioning primitives before the elevated installer exits. No separate executable lookup, terminal command, or repair-wizard launch is required.

## Workflow

- Fresh installs with protection disabled, and Monitor mode, are skipped without ACL mutations. No directory is automatically enrolled. Configure protected and explicit response paths, then run Setup > Upgrade / repair.
- Protect/Contain uses saved explicit response paths only. If process correlation is enabled, plan Security log read access for the dedicated LocalService service SID and successful write/delete audit rules for eligible directories. Plan scoped read/delete rights for eligible response directories. No global audit policy is changed; review its reported state.
- Preflight steps independently. The local elevated installer shows a scrollable summary of eligible and blocked operations, with Skip as the default. Approval authorizes the listed changes, including inherited DELETE_CHILD and a service restart. Do not approve a production directory if only a disposable lab should have response rights. Exact saved response paths can include files; this directory repair intentionally refuses files, missing paths, reparse points, whole profiles, system infrastructure and excluded-path overlaps.
- Each eligible change is checked again against the approved policy snapshot, directory identity and original/planned permission descriptors. Backups are persisted before writes in `C:\Program Files\LinkScope Permission Backups`. Nested scopes are processed child-first; rollback is conflict-aware and should proceed in reverse order. Child ACL inheritance, explicit denies and Windows policy may affect actual access. Existing ACL safeguards remain in place.
- Setup independently logs apply failures, attempts a bounded restart of LinkScope after approved apply attempts, and reports a separate review result (21) when provisioning is declined, blocked, fails or the restart fails. The software install itself is not reported as failed solely because permission provisioning needs review. No service is elevated or termination rights granted. No automatic changes are made from the web UI.
- The ordinary elevated install/upgrade log in `C:\Program Files\LinkScope Setup Logs` contains the exact preflight/apply/restart results, with the path shown in the completion dialog. Existing manual repair and rollback wizard remains available. Run Test Center to verify effective service access, auditing evidence and response readiness; descriptor readback does not establish access under the running service token.

ClamAV signature updates and provider cooldowns are unchanged. Existing saved endpoint mode/scope and security history are preserved. For a test-only grant, remove broader parent paths from Explicit response paths before upgrading (do not remove them from Protected paths).

## Validation

Six targeted scripts passed (see report); five are static source/build checks, one also exercises the dashboard with a mocked API in Chromium. Native Windows compilation, UAC, actual ACL changes, effective access, and service restart are not verified in this environment. No claim of production certification. The V53 version assertion was relaxed to accept subsequent version numbers; all other historical V53 assertions remain unchanged. The full historical regression suite was not rerun.
