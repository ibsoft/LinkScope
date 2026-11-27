# V20 — user profile scan access

The reported access denial at `C:\Users\ioannisb` prevents the LocalService scanner from opening the root and prevents watcher creation. The USN reader has a different identity and cannot grant file access to the scanner. V20 retains the restricted service account and introduces explicit local permission management; it does not automatically grant profile access during setup or through the web dashboard.

## Windows acceptance

1. Upgrade with the rebuilt setup. Enable Endpoint Protection and save the exact intended directory in Protected paths.
2. In elevated Windows PowerShell 5.1, from the extracted source directory, preview the operation for the user's explicitly selected profile:

```powershell
.\Grant-LinkScopeScanAccess.ps1 -Path 'C:\Users\ioannisb' -AllowProfileRoot -WhatIf
```

3. If you accept service read access to that profile (including potentially sensitive personal/application data), run the same command without `-WhatIf`, and confirm. Prefer selecting Downloads or a dedicated directory instead where possible. If the parent profile denies metadata access, a narrower grant alone may not suffice. No automatic ancestor changes are performed.
4. Allow the failed watcher retry to run, or restart the LinkScope service after the ACL operation completes. Verify real-time watching and scan coverage in the dashboard. The watcher retry does not discard queued events or recreate successful watchers. On recovery it requests a reconciliation scan.
5. Run the existing service and engine probes, adjusting the filename to the actual existing test file:

```powershell
$exe = Join-Path $env:ProgramFiles 'LinkScope\LinkScope.exe'
& $exe --endpoint-engine-self-test
& $exe --endpoint-scan-file 'C:\Users\ioannisb\Downloads\eicar.com.txt'
```

Do not disable another antivirus to force a test. Use an isolated test environment if necessary. A successful engine memory test alone does not establish real-time file coverage. Protected child ACLs, explicit deny rules, reparse points, EFS, locked files and third-party antivirus interception can still prevent detection. No system-wide permission or privilege changes are made. The utility adds a read-only inheritable ACE without replacing existing ACEs; Windows may propagate inheritance to existing descendants. For rollback, review the ACL and remove only the ACE added by this operation; do not indiscriminately remove existing LinkScope permissions. The operation has no automatic rollback and Windows runtime validation is required.
