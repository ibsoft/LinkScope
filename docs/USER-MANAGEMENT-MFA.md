# LinkScope — User management and authenticator MFA

This update is based on `LinkScope_Endpoint_Layout_FreshClam_Fix.zip`, retaining its endpoint card ordering, 15 px desktop navigation font, 16 px collapsed navigation, and bounded FreshClam process shutdown handling. Existing monitoring, setup generation and bearer-token endpoints are retained.

## Upgrade and sign-in

Build the solution in a clean source directory using Visual Studio (Release | x64) or `Build.cmd`. Run the generated setup to upgrade the Windows service. Back up the protected LinkScope settings and data before upgrading. Existing built-in `admin` credentials are preserved. Fresh installations retain the local-only starter password enrollment procedure. Newly created or changed passwords must contain 12–128 characters, upper- and lowercase ASCII letters and a digit; existing permanent passwords are not silently replaced.

Authenticated access is now mandatory, including localhost. The old RequireLogin setting is forced true. If no permanent admin password has been established, complete local first-use enrollment or set the password from an elevated local command prompt with `LinkScope.exe --set-admin`.

## Accounts and roles

Open the top-right account icon → **Users**. The page is restricted to Admin accounts. The list shows username, display name, email, role, MFA enrollment state, password-change state, update timestamp and actions. Search matches all loaded account profiles. Up to 128 accounts are supported. Usernames are case-insensitive ASCII (1–64 characters, letters, digits, dot, underscore, hyphen), normalized to lowercase and cannot be renamed. Use the display name to edit a person's name.

- Add user: enter profile information, Admin or Viewer role and a temporary password. The new user must replace that password before a session is issued.
- Edit user: change display name, email and role.
- Reset password: set a new temporary password; no existing password can be retrieved.
- Reset MFA: revoke the registered authenticator for another managed account. The user must enroll again.
- Delete: remove a managed account; historical audit records remain.
- My account & MFA: all authenticated accounts may edit their own profile, change their own password and enroll/disable MFA.

Admin operations require the acting administrator's current password and, when MFA is enabled, an unused authenticator code. The built-in `admin` cannot be deleted, demoted or managed by another administrator through this UI. Other admins cannot delete or change their own role through Users. Password changes, admin edits, role changes, MFA resets and deletions invalidate affected sessions. No permanent session is issued for incomplete first-use or MFA authentication.

| Capability | Admin | Viewer |
|---|---|---|
| Network, System Health, Integrity, Endpoint Protection | Yes | Read only |
| Alert history, Application Logs, PDF reports | Yes | Read only |
| Shared acknowledgement, scan/update requests, maintenance | Yes | No |
| Settings, token management, AI Assist, User Audit, Users | Yes | No |
| Own profile, password, MFA, logout | Yes | Yes |

Viewer restrictions are enforced at the HTTP dispatcher with an explicit read allowlist and a narrow POST allowlist (own account and logout), not just hidden UI controls. Existing API bearer tokens remain separately scoped service credentials; users do not automatically receive API tokens. Monitoring alerts remain shared, rather than introducing per-user alert-read state. Viewers may dismiss local toast popups, but not mark shared alerts as read.

## Google Authenticator enrollment

1. Sign in and open the user menu → My account & MFA.
2. Choose Set up MFA, re-enter your current password and generate the QR code.
3. In Google Authenticator (or another standards-compatible TOTP app), add an account by scanning the QR code. The manual key is available if scanning is not possible. Never share or screenshot the enrollment secret.
4. Enter the six-digit code and choose Enable MFA. Enrollment expires after ten minutes and is bound to the authenticated session and credential revision. The browser generates the QR locally, without contacting a QR service.
5. Sign in again with your password and a **fresh** six-digit code. Wait for the next code if the last one was used for enrollment or sign-in. Each accepted time step is persisted and cannot be accepted a second time. The server allows one adjacent 30-second step for ordinary clock skew. Keep the Windows host and authenticator clocks synchronized.

MFA is optional per account; enable it for administrators after upgrading. It is TOTP, not a Google account or cloud identity integration. Disabling MFA requires password and current unused OTP. Admins can reset other managed users' MFA after reauthentication. There are no recovery codes in this release; retain local Windows administrative access. A freshly generated code may also be necessary before sensitive management actions. The existing sign-in attempt limit (8 requests per source IP and 30 global in five minutes) also covers reauthentication and enrollment confirmation. A successful login does not exempt subsequent attempts from that rate limit.

### Built-in administrator recovery

If the built-in administrator loses the authenticator, run these steps **locally as a Windows administrator**, after ensuring any console-mode monitor is stopped. Do not delete `users.json` or modify stored hashes.

```powershell
Stop-Service LinkScope
# Change to the installed LinkScope executable directory first.
.\LinkScope.exe --reset-admin-mfa
# Enter RESET at the confirmation prompt.
# If the password is lost too:
.\LinkScope.exe --set-admin
Start-Service LinkScope
```

The local recovery action is recorded in User Audit Logs. The normal password-reset command does not silently disable MFA. An offline Windows administrator has authority over this local service and its credentials; the scheme is not designed to resist a fully compromised operating system administrator.

## Credential protection

- PBKDF2-HMAC-SHA256, 600,000 iterations, independent 24-byte random salts and 32-byte derived hashes. Constant-time comparison of equal-length verifiers. Plaintext passwords are not stored or returned by the account API.
- TOTP uses 160-bit random secrets, six digits and 30-second periods. The long-term secret is protected using Windows DPAPI LocalMachine. The credential database inherits the application's restricted settings-directory ACL. LocalMachine DPAPI alone does not protect against other identities who can read the ciphertext; preserve the ACL.
- Account records are saved atomically in `%ProgramData%\LinkScope\settings\users.json`. The existing built-in admin verifier remains authoritative until the built-in administrator changes the password through My account. That managed override is bound to the original credential revision; a local `--set-admin` reset invalidates it. Maintain secure backups of **both** the existing `admin.json`/enrollment credential files and `users.json`. DPAPI secrets are machine-bound; plan MFA reset/re-enrollment if restoring to another host. Do not delete credential files as a recovery method.
- Existing opaque session cookies remain HttpOnly and SameSite=Strict, Secure over HTTPS. Non-loopback cleartext access is prohibited by the existing configuration rules. Account mutations require same-origin checks and a CSRF token. Authentication and account responses use `Cache-Control: no-store`. The PWA does not cache account content. Reauthentication and MFA enrollment are rate-limited. MFA does not eliminate phishing or host compromise risks.
- Audit records contain actual usernames, approved action labels, source IP and outcomes, never passwords, hashes, QR URIs, secrets or one-time codes. Users cannot access another user's profile via an ID on the self-service endpoint; the server binds it to the authenticated session.

## Acceptance and validation

Portable `tests/validate_users.py` decodes a real QR matrix to its exact test enrollment URI, checks the independent RFC reference vector, and inspects role/CSRF gates, password derivation, audit attribution, resource parity and JavaScript syntax. Existing portable regression scripts are retained. Run `LinkScope.exe --self-test` on Windows to execute the new C# account tests (migration, temporary password, Viewer route policy, protected admin, TOTP RFC vector, DPAPI, enrollment, replay rejection, credential changes and session revocation).

Before production deployment, also complete these Windows/browser integration tests:

1. Build both Debug and Release and confirm `LinkScopeSetup.exe` is generated.
2. Upgrade an existing installation and verify the existing admin password still works. Test clean local first-use enrollment separately.
3. Create a Viewer with a temporary password; verify there is no session before successful password change.
4. Confirm Viewer can read dashboards, reports and alert history, but receives HTTP 403 for `/users`, `/ui/users`, `/settings`, `/ui/settings`, token generation, AI, audit, acknowledgement and scan/update POST requests. Attempt direct HTTP calls as well as UI actions.
5. Confirm every mutation rejects missing or incorrect CSRF and cross-origin POSTs.
6. Enroll MFA with Google Authenticator, verify wrong/expired/replayed codes fail, confirm a fresh code succeeds and session is revoked after MFA changes. Try confirming an enrollment from another session. Test per-IP and global limits.
7. Change password, change role, reset MFA and delete a user while that user is signed in elsewhere. Verify subsequent requests reject old session cookies. Test that built-in admin cannot be removed or demoted.
8. Inspect credential storage, inherited ACLs, API responses, audit logs and browser network/cache entries for secrets. Verify secure remote HTTPS configuration.
9. Test local admin recovery with the service stopped, verify previous sessions are invalidated, and re-enroll MFA.
10. Verify themed account menus, QR dialogs, search, mobile navigation, report export, previous endpoint panel ordering and FreshClam source configuration.

**Validation limitation:** This archive contains updated source code. The build environment has no Windows/.NET Framework compiler or Windows service runtime. The C# tests, DPAPI behavior, actual sign-in, full HTTP authorization and browser rendering have not been executed there. Do not interpret portable tests as production security certification.
