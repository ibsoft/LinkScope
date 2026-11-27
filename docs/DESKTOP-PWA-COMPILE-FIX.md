# LinkScope build fixes and desktop web app setup

This update starts from `LinkScope_ClamAV_Verified_Setup.zip`. ClamAV detached-signature verification, automatic engine configuration, hidden installer consoles and the Visual Studio setup build are retained.

## Compiler fixes

- `setup/ClamSetup.cs` imports `System.ServiceProcess` and `System`; its explicit process timeout now throws `System.TimeoutException` (not the ServiceProcess timeout type). Other explicit timeout constructions are also qualified.
- `EndpointWriter` and `EndpointResponse` are now declared in the same `LinkScope` namespace and compilation unit as their callers in `src/EndpointProtection.cs`. `src/EndpointResponse.cs` is an intentionally empty compatibility marker, not another copy of the response class. This prevents the response type from being lost when a separate source-file entry is stale or omitted. The original release already had an explicit project entry; the cause of the compiler errors on another machine is not established by these static checks.
- Both normal build paths include the desktop integration: the explicit Visual Studio Compile items and the `Build.cmd` source wildcard. The existing setup MSBuild target still embeds the newly built application.

Extract the full archive to a **clean directory**, copy your optional `deploy\clamav-latest.msi` and matching `.sig` into that directory, open `LinkScope.sln`, select Release | x64 and rebuild. Run `bin\Release\LinkScopeSetup.exe`.

## Desktop application and PWA

A successful LinkScope installation/upgrade provisions a common Desktop and Start menu shortcut called LinkScope, with the real embedded LinkScope icon. The browser target is a standard system-wide Edge installation if available, then Chrome; otherwise the shortcut opens the configured URL in the default browser. The browser shortcut uses `--app=` to provide a standalone app window. No browser is launched from the service or the elevated shortcut-creation worker. The URL is generated from the validated LinkScope configuration, rather than hardcoding the default port. With nondefault HTTPS configurations the certificate still needs to be trusted normally. The existing PWA service worker continues to avoid caching authenticated data.

The setup wizard also has a **default-checked, optional managed Edge PWA registration** setting. The documented `WebAppInstallForceList` policy requests actual web-app installation when a compatible Edge profile runs. This is separate from the immediate desktop shortcut; Edge is not asked to generate a duplicate shortcut. A managed PWA is installed by policy, so the user cannot remove it through Edge while that policy applies. Uncheck the setting before setup if you do not want a new local browser policy. Unchecking does not remove a previously configured policy. Installation or upgrade always attempts to create the immediate shortcut, regardless of this setting.

Setup does not overwrite an existing Edge web-app policy that it does not own. It checks the current registry user and both machine registry views. Domain Group Policy, other user profiles, browser versions and browser/profile restrictions can affect whether the new policy applies; IT should use its existing policy management in that case. The local policy may make Edge show a managed-browser indicator. Setup records only its own policy value in the restricted LinkScope data area and removes that value on uninstall only if it still matches. Other policies are not changed. If there is no existing policy, the new local machine policy is `HKLM\SOFTWARE\Policies\Microsoft\Edge`, value `WebAppInstallForceList`. See Microsoft's documentation: https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/webappinstallforcelist .

There is no promise of immediate browser-native registration: after installation, open Edge in the intended user profile and verify `edge://policy` and `edge://apps`. If automatic registration is not available, the immediate app-mode shortcut remains usable, and Edge's ordinary install-app command is an alternative. The ordinary shortcut is not itself a registered PWA. A trusted HTTPS certificate is still necessary for a non-loopback PWA; the installer does not change TLS validation or browser security settings.

The public icon asset is stored separately at `C:\Program Files\LinkScope Desktop\linkscope.ico`, readable by normal users. This does not loosen the existing private service/configuration/data ACLs. Existing shortcuts not created by LinkScope are not overwritten or removed. Setup keeps the small icon asset on uninstall for independent app shortcuts that may still reference it. Uninstall removes its owned common shortcuts and owned matching local Edge policy, but does not delete browser user profiles.

For a repair without reinstalling the service, from an Administrator PowerShell or command prompt:

```
LinkScopeSetup.exe --desktop-app
```

To explicitly request managed registration as well:

```
LinkScopeSetup.exe --register-pwa
```

The shortcut is generated for the origin configured at setup time. If the host, port, or HTTPS configuration subsequently changes, repair the shortcut; a changed native PWA origin may require removing the old registered app through your browser/policy management. Setup logs desktop/PWA warnings and continues the underlying service installation if optional desktop integration is unavailable.

## Validation

Portable tests run on this source archive:

- Endpoint regression tests: JavaScript parsing, settings defaults, resources, SQLite SQL, C# source/project parity and delimiter checks.
- New desktop/compile-source check: qualified timeouts, response class namespace depth, project inclusion, installer operation wiring, shortcut ownership, registry guards and network-only PWA.
- Setup build graph, ClamAV setup and signature tests (synthetic valid and altered payloads; embedded key fingerprint).
- Navigation static source checks.

These do not compile C# or execute Windows APIs. No .NET Framework 4.8/Windows compiler is available in the test environment. Real Windows build, COM shortcut generation, MSI installation, and browser-native PWA registration remain to be validated.

### Windows acceptance checks

1. On a disposable x64 Windows VM, rebuild in Visual Studio; verify no CS0104 or CS0103 errors. Also build with `Build.cmd`.
2. Verify `LinkScopeSetup.exe` embeds the same application binary: `powershell -NoProfile -File tests\Verify-VisualStudioSetup.ps1 -OutputDirectory bin\Release`.
3. Install using the setup wizard with the default PWA option. Confirm the service runs. Review the setup log in `C:\Program Files\LinkScope Setup Logs` for any desktop or policy warnings.
4. As an ordinary user, run `powershell -NoProfile -File tests\Verify-DesktopApp.ps1 -ExpectManagedPwa` if no existing policy blocked the new registration. Omit that switch for shortcut-only installation. For nondefault listeners pass `-ExpectedOrigin` with the actual origin.
5. Launch the Desktop shortcut, confirm it has the LinkScope icon and opens an app-mode window, and sign in. Open Edge and verify the registered app under `edge://apps`. Review `edge://policy` for the effective managed policy, if requested.
6. Repeat with the checkbox unchecked on a fresh VM, then with an unrelated existing WebAppInstallForceList. Confirm no new policy is written in shortcut-only mode and the unrelated policy is preserved byte-for-byte.
7. Change the listening port on the test VM, restart LinkScope and run `--desktop-app`. Verify the shortcut launches the updated configured origin.
8. Uninstall LinkScope on the disposable VM. Verify owned common shortcuts are removed and a matching LinkScope policy is removed, with other policies untouched. ClamAV, application data and browser profiles are retained.
9. Confirm ClamAV MSI verification still blocks missing/invalid signatures before Windows Installer runs.
