# V52 — Automatic endpoint permission repair

Open the local LinkScope Setup, choose Endpoint permission repair, select the exact saved response directory and click Automatic repair. If a single saved directory is available it is preselected, but changes still require explicit confirmation. With multiple directories, choose one; no bulk grants occur.

The wizard reads the File System audit policy and preflights the existing Security log channel descriptor, directory audit descriptor and directory access descriptor. All three are previewed before the confirmation prompt. It uses the existing V49 backed-up, scope-validated, readback-verified permission writer. If a step fails, the wizard stops, reports the error and retains backups for individually rolling back earlier changes. It does not change global audit policy, restart services, authorize additional paths, change production mode or grant termination permissions. Windows inheritance can extend permissions to descendants, including name-pattern exclusions; only use dedicated response directories. Existing deny rules and protected child ACLs may still prevent effective access.

After repair, restart LinkScope at an appropriate maintenance time and run Test Center diagnostics. Fresh audited file activity is required for writer attribution. The existing signature freshness warning is independent and is not changed by this repair.

Verification: five targeted regression scripts passed in the portable environment; native C# compilation, UAC, actual ACL changes and live service identity checks were not executed. The earlier V51 test was updated only to accept successor version numbers. Full historical regression suite not rerun.
