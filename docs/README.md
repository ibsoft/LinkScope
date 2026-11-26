> **Graphical setup:** Double-click `LinkScopeSetup.exe` to open the installation wizard. For elevated command-line installation, upgrade/repair or service removal use `--install`, `--upgrade` or `--uninstall`, respectively. The wizard retains the standard installation directory and existing configuration. See the root README for limitations.

# Unixfor LinkScope administrator guide

LinkScope is a Windows service that pings configured IP addresses, records packet loss and round-trip latency in SQLite, and serves a web dashboard. It also collects Windows health on the monitoring computer. A fresh installation listens on `http://127.0.0.1:9876` and pings the local host every **5 seconds**. Add the IPs you want to monitor in **Settings → Network probes**.

| Task | Go to |
| --- | --- |
| Install, sign in or reset the admin password | [Installation and first sign-in](#installation-and-first-sign-in) |
| Delete the service, reinstall or apply an update | [Uninstall](#uninstall) · [Reinstall or upgrade](#reinstall-or-upgrade) |
| Change ping frequency, targets, port, thresholds or Windows collection | [Settings reference](#settings-reference) |
| Enable HTTPS with a self-signed or company certificate | [HTTPS setup](#https-setup) · [Recover local access](#recover-local-access) |
| Generate an API token and run curl requests | [System health API](#system-health-api) · [Windows curl examples](#windows-powershell-with-curlexe) · [Bash example](#bash-with-curl) |
| Search colored application logs, set retention or forward to syslogd | [Application logs and syslog](#application-logs-and-syslog) |
| Configure a model and ask a diagnostic question | [AI Assist for technicians](#ai-assist-for-technicians) |
| Inspect UAC, Secure Boot, TPM and BitLocker | [Security posture](#security-posture) |
| Send alert emails, test the relay or export active alerts to disk | [Alert delivery settings](#alert-delivery-settings) |
| Import the Postman collection and environment | [Test with Postman](#test-with-postman) |
| Understand the graphs or export a report | [Interpreting the graphs](#interpreting-the-graphs) · [Export a complete PDF report](#export-a-complete-pdf-report) |
| Diagnose a service startup error | [Repair a service registered from a Debug folder](#repair-a-service-registered-from-a-debug-folder) · [Verify on Windows](#verify-on-windows) |

[SIEM forwarding and test events](#forward-application-logs-to-seq-wazuh-or-elasticsearch) · [Restart after changing targets](#apply-new-network-targets-from-the-dashboard)

## Installation and first sign-in

1. Use 64-bit Windows 10/11 or Windows Server 2019 or later with **.NET Framework 4.8**, Windows PowerShell 5.1, Task Scheduler and Windows' built-in SQLite component (`winsqlite3.dll`). The offline setup extracts the compiled service embedded during the Windows build. The source ZIP includes the build scripts, full source, a PowerShell API client and a verification script.
2. Extract the ZIP. Open **64-bit PowerShell as Administrator** in the extracted folder and run the following commands. For an existing installation, use [Reinstall or upgrade](#reinstall-or-upgrade).

   ```powershell
   .\LinkScopeSetup.exe --install
   if ($LASTEXITCODE -ne 0) { throw 'Installation failed. Check the installer output.' }
   Get-Service -Name LinkScope
   ```

3. When the status is **Running**, open **http://127.0.0.1:9876/** in a browser **on the monitoring computer**. On a new installation the username is **admin** and the starter password is **`admin`**. Enter and confirm a different password when prompted. Use **7–128 characters** including at least one A–Z, one a–z and one digit 0–9. Symbols are optional. Control characters are rejected.
4. Open **Settings → Network probes**. Enter one IP and optional display name per line, set **Probe interval (seconds)**, and click **Save settings**. Click **Restart LinkScope** under the target list and confirm. Sign in again and select a target under **Network** to confirm the first observations.

Setup installs one service executable, registers **LinkScope Network Monitor** with automatic startup, and starts it as `NT AUTHORITY\LocalService`. Its service SID is `NT SERVICE\LinkScope`. Setup also registers **Unixfor LinkScope SMART**, a scheduled task that uses the same executable with `--smart-once` as SYSTEM every five minutes to read physical disk health.

### Administrator password and sessions

The sign-in page shows the brand and login form. Submitting valid form fields immediately shows a spinner inside the button. A successful sign-in keeps the spinner visible through navigation. A rejected sign-in or first-use password prompt makes the form available again.

On a fresh install the starter credential can be used only from the monitoring computer while the service is listening on loopback. An upgrade retains an existing password. If an older installation has no password, setup initializes the starter credential. If you have already bound the listener to a LAN address or forgotten the password, run this command **on the monitoring computer in elevated PowerShell** and enter the new password twice.

```powershell
& "$env:ProgramFiles\LinkScope\LinkScope.exe" --set-admin
```

A reset expires existing browser sessions. API tokens have their own expiry and revocation controls. Browser sessions expire after 15 minutes idle or eight hours total. Automatic dashboard refreshes count as activity.

### Files and service locations

| Item | Location or name |
| --- | --- |
| Installed executable | `%ProgramFiles%\LinkScope\LinkScope.exe` |
| Windows service / scheduled tasks | `LinkScope` / `Unixfor LinkScope SMART` and `Unixfor LinkScope Restart` |
| Active configuration | `%ProgramData%\LinkScope\settings\config.json` |
| Network and resource history | `%ProgramData%\LinkScope\data\history.sqlite`, created automatically |
| Diagnostic log | `%ProgramData%\LinkScope\data\service.log` |
| Most recent hardware scan | `%ProgramData%\LinkScope\hardware.json` |
| Generated public certificate | `%ProgramData%\LinkScope\LinkScope-public.cer` |

On a first upgrade from a legacy installation, setup reads the old `%ProgramData%\LinkScope\config.json` if the active settings file is missing. It preserves targets, interval, port and adapter and sets a local HTTP listener with login enabled. Subsequent starts and reinstalls use the active file in `settings`.

## Uninstall

In **64-bit PowerShell as Administrator** on the monitoring computer, run the installed application's uninstall switch. The installer and installed service executable have different names.

```powershell
& "$env:ProgramFiles\LinkScope\LinkScope.exe" --uninstall
if ($LASTEXITCODE -ne 0) { throw 'Uninstall failed. Check the output above.' }
sc.exe query LinkScope
Get-ScheduledTask -TaskPath '\' -TaskName 'Unixfor LinkScope SMART','Unixfor LinkScope Restart' -ErrorAction SilentlyContinue
```

Uninstall stops monitoring, unregisters the SMART and restart tasks and removes the Windows service. The expected checks are **1060** from `sc.exe query` and no task object from `Get-ScheduledTask`. The executable, settings, admin credential, token hashes, certificate and SQLite history remain on disk for reinstallation. The Windows certificate store, client trust and any manually created firewall rule are separate. If retiring the host and you created the example rule in this guide, remove it with `Remove-NetFirewallRule -Name 'Unixfor-LinkScope-Management'`.

### If the installed executable is missing

Use `sc.exe qc LinkScope` to inspect the registration. Even if the service points to a missing file or an old `bin\Debug` build, the package can compile a copy of the **same uninstaller**. In elevated PowerShell in the extracted ZIP folder, run the following commands. Then repeat the two verification commands above.

```powershell
.\Build.cmd
if ($LASTEXITCODE -ne 0) { throw 'Build failed. Check the compiler output.' }
.\LinkScope.exe --uninstall
if ($LASTEXITCODE -ne 0) { throw 'Uninstall failed. Check the output above.' }
```

If someone has already deleted the service manually, check the scheduled task separately. In Task Scheduler Library, inspect **Unixfor LinkScope SMART**. A LinkScope task has one action, `%ProgramFiles%\LinkScope\LinkScope.exe --smart-once`. If this matching task remains on a host being decommissioned, end it if running and delete it.

## Reinstall or upgrade

Extract the ZIP for the desired version. In elevated PowerShell in the extracted folder, run the following block. It works after an uninstall and for an in-place upgrade. The stop is important during an upgrade because the installer leaves a healthy copy already running at its installed path in place.

```powershell
$svc = Get-Service -Name LinkScope -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne 'Stopped') { Stop-Service -Name LinkScope -ErrorAction Stop }
.\LinkScopeSetup.exe --install
if ($LASTEXITCODE -ne 0) { throw 'Installation failed. Check the installer output.' }
Get-Service -Name LinkScope
```

After **Running** appears, open the existing dashboard URL and sign in with your current admin password. Reinstalling reuses the active settings, history and existing credentials. If Windows returns **1072** (service marked for deletion), close Services (`services.msc`) and other tools holding a service handle. Retry once `sc.exe query LinkScope` returns **1060**.

## Settings reference

Sign in as **admin**, open **Settings**, edit the fields, and click **Save settings**. The page shows the current listener and, when a restart is required, the URL to open afterward. The active file is `%ProgramData%\LinkScope\settings\config.json`.

**When changes take effect.** Saving through the browser updates login policy, alert thresholds, collection settings, log channels and optional API categories in the running service. New samples can take a collection cycle. Listener, certificate, target, ping timing and adapter changes take effect after restarting LinkScope. Use **Restart LinkScope** under **Network probes** or run `Restart-Service LinkScope` in elevated PowerShell on the host. For direct JSON edits, validate the file and restart the service. A service restart signs browser users out.

### Dashboard appearance

Set **Brand label** (`BrandLabel`) to the text you want before **LinkScope** in the top bar and browser tab. The default is empty, which shows **LinkScope**. For example, entering `Unixfor` shows **Unixfor LinkScope**. Save the setting to apply it without a service restart. The limit is 80 characters.

### Access and HTTPS

| Settings field | JSON property | Default | Accepted value and effect |
| --- | --- | --- | --- |
| Listen on IP address | `BindAddress` | `127.0.0.1` | One specific IP assigned to the monitoring host. Use loopback for host-only access. Wildcard listeners such as `0.0.0.0` and `::` are rejected. A LAN IP requires HTTPS and a DNS name other than `localhost`. |
| TCP port | `Port` | `9876` | 1–65535. Both the web pages and the API use this listener. |
| Enable HTTPS | `UseHttps` | `false` | Enables the TLS 1.2 listener on the selected port. |
| HTTPS DNS name | `HostName` | `localhost` | A DNS name of up to 253 characters using letters, digits, hyphens and dots, with no trailing dot. For HTTPS, use this name in the browser and in curl. It must resolve to the listener and match the certificate. |
| HTTPS certificate / Certificate thumbprint | `CertificateThumbprint` | Empty | **LinkScope self-signed certificate** uses the thumbprint saved by setup. **My Windows certificate** uses the 40-hex-character Windows store thumbprint you enter. Spaces are stripped. |
| Require dashboard login on localhost | `RequireLogin` | `true` | When cleared, local visitors can read the network and core system-health views. Settings, token management and administrative actions require an admin session. Remote dashboard users sign in. The machine API always requires a bearer token. |

### Network probes

| Settings field | JSON property | Default | Accepted value and effect |
| --- | --- | --- | --- |
| Probe interval (seconds) | `IntervalSeconds` | 5 | 1–86400. One ICMP probe per configured IP per round, scheduled in parallel. |
| Timeout (milliseconds) | `TimeoutMs` | 1500 | 100–30000. The effective deadline is the smaller of this setting and the probe interval in milliseconds. |
| Network adapter | `InterfaceName` | Empty | Adapter name or interface GUID on the monitoring computer (up to 256 characters). Empty selects an active adapter automatically. The traffic chart shows this adapter's receive/transmit rates. Use `Get-NetAdapter` to list adapters. |
| Targets | `Targets` | `127.0.0.1`, Local host | 1–128 distinct unicast IPv4/IPv6 addresses. In the UI, enter one IP per line, optionally followed by a space and a display name (up to 120 characters). In JSON each target has `Address` and `Name`. |

For example, paste these two lines into **Targets**, set **Probe interval** to `10`, save, click **Restart LinkScope**, and confirm. Substitute addresses reachable from your monitoring computer.

```text
192.168.1.1 LAN gateway
192.168.2.1 Branch router
```

### Apply new network targets from the dashboard

1. Open **Settings → Network probes**, enter one IP and display name per line, and click **Save settings**.
2. Click **Restart LinkScope** below the target list and confirm. The button also appears when you reopen Settings with a saved change pending. Monitoring briefly pauses and existing dashboard sessions end.
3. For an unchanged listener, the page waits for a new service instance and opens sign-in. After signing in, check the **Network → Target** dropdown. For a changed host, port or HTTPS setting, follow **Open dashboard** to the new origin.

The signed-in administrator can request this action when a saved change requires it. Setup registers an on-demand Windows task named **Unixfor LinkScope Restart**. Its fixed action restarts the installed LinkScope service. The service SID receives permission to read and run this task. When running in console mode, stop and start the console process yourself. If a restart times out, check `Get-Service LinkScope` and the task's Last Run Result on the monitoring host. The elevated PowerShell fallback is `Restart-Service LinkScope`.

### Network probe alert rules

Open **Settings → Network probes → Per-target network alerts**. Each target has its own **Alerts on** switch and thresholds. Save a rule change to apply it on the next probe round for a running target. Adding or renaming a target also requires the service restart described above.

| Per-target field | JSON property inside `Targets` | Default and behavior |
| --- | --- | --- |
| Alerts on | `AlertsEnabled` | On. Turning it off closes active alert conditions for this target on the next round. Probing and history collection continue. |
| Consecutive failures | `FailureCount` | Blank (`null`) inherits the global `ProbeAlertCount`, initially 3. Set 1–100 to override, or 0 to disable this rule. The next successful reply resets the count. |
| RTT threshold (ms) | `HighRttMs` | Blank disables this rule. Enter 1–30000. Choose a threshold below the effective ping timeout so a slow reply can still be measured. A successful reply at or above the threshold raises an alert. The next successful reply below the threshold resolves it. A timeout has no RTT. |
| Loss threshold (%) | `LossPercent` | Blank disables this rule. Enter 1–100. The alert opens when the rolling loss percentage reaches or exceeds the threshold and resolves when it drops below. Local probe errors are excluded from the loss calculation. |
| Loss window (probes) | `LossWindowProbes` | 20, configurable from 2–1000. The service waits for a full window of eligible probes. On restart it seeds the window from retained recent probes. |

For example, for a branch router set **Consecutive failures** to **3**, **RTT threshold** to **150 ms**, **Loss threshold** to **20%**, and **Loss window** to **10**. Three consecutive failures raise a failure alert. A 150 ms reply raises a latency alert. Two unanswered probes among the last ten eligible probes raise a loss alert. Find each occurrence under **Alert history** and in **Export PDF**.

### Alert delivery settings

Sign in as **admin** and open **Settings**. Email and JSON output are independent and both start **off**. Changes apply when you click **Save settings**. Existing installations keep their ping targets, credentials, history and alert rules.

#### Send email through SMTP

1. In **Alert email (SMTP)** enter your server, port, encryption and authentication settings. For example, an Exchange relay authorized for the monitor's IP might use port **25**, **None (relay)** and the encryption required by your administrator. An authenticated submission service commonly uses **587 + Require STARTTLS** or **465 + Implicit TLS (SMTPS)**.
2. Enter the **From address** and at least one **To address**. Use commas or semicolons for multiple To, Cc or Bcc addresses. Add a display name, Reply-To and subject prefix if wanted.
3. Click **Send test email**. It uses all the current form values, including unsaved changes, and sends to all listed recipients. To test with only yourself, temporarily put your own address in To and empty Cc/Bcc. Test delivery works with alert email switched off. The page shows the result of this send without saving your edits. On success it reports relay acceptance, recipient count, transport, authentication method and elapsed time. Check the recipient mailbox to verify end-to-end delivery.
4. Set your production recipients, select **Email newly opened monitoring alerts**, choose whether to send recovery emails, and click **Save settings**.

| Setting in `Delivery` | Default | Options and behavior |
| --- | --- | --- |
| `EmailEnabled` / `EmailRecovery` | Off / On | Queue one message when a monitoring incident opens, and optionally one when it resolves. Updating the measurement or marking it read does not send another email. |
| `SmtpHost` / `SmtpPort` | Empty / 587 | DNS name or IP and TCP port 1–65535. TLS clients validate the server name and certificate. Use a name covered by the relay certificate and ensure Windows on the service host trusts its issuer. |
| `Encryption` | `starttls` | `starttls` requires the server to upgrade the connection. `tls` negotiates TLS before the SMTP greeting. `plain` supports an unencrypted relay with no authentication. |
| `Authentication` / `Username` | `none` / empty | `none` for an authorized relay. `auto` selects a supported password method, preferring PLAIN over TLS. You can also choose `login` or `plain` explicitly. SMTP AUTH must be enabled on the server. |
| SMTP password | Empty | Enter it in Settings. A blank field reuses the stored password. Use **Clear stored SMTP password on save** to remove it. Re-enter or clear the password when changing server or username. Windows DPAPI protects the saved value in the ACL-protected configuration. Migrating to another computer requires re-entering the password. |
| `From` / `SenderName` / `ReplyTo` | Empty / LinkScope / empty | One sender address, optional display name and optional single reply address. The SMTP server must authorize the sender. |
| `To` / `Cc` / `Bcc` | Empty | Supply bare email addresses. Up to 100 entries total. The relay receives Bcc addresses as envelope recipients. Recipient headers omit Bcc. |
| `SubjectPrefix` / `TimeoutSeconds` | `[LinkScope]` / 20 | Set the subject prefix and an overall send timeout of 3–120 seconds. Subjects and bodies support UTF-8 text. |

Email delivery runs in the background. LinkScope queues new transitions in the same SQLite transaction as the alert record. Enabling email does not resend old history. The queue survives restarts. A failed send is retried after 30 seconds, with increasing delays up to one hour. The Settings page shows queued messages and the latest result. Saving revised relay settings retries pending mail using the new settings. Disabling email clears pending mail. An in-progress submission may already have reached the relay. If a connection breaks after the relay accepts the message, a retry can produce a duplicate with the same Message-ID.

For the submission port conventions, see [RFC 8314](https://www.rfc-editor.org/rfc/rfc8314.html).

If a test fails, the status identifies the SMTP step. Check DNS and outbound firewall access for connection errors, certificate name and trust for TLS errors, credentials and SMTP AUTH policy for **535**, and sender or relay permissions for **550**. Settings supports anonymous relays and password-based SMTP AUTH. If your provider requires OAuth-only submission, use an authorized SMTP relay.

#### Write active alerts as JSON files

1. In **Active alert JSON files**, enable **Write active monitoring alerts to JSON files**.
2. Leave **Output directory** empty to use `%ProgramData%\LinkScope\data\active-alerts`, or enter a full Windows path such as `D:\Monitoring\LinkScopeAlerts`. For a custom local directory, grant **Modify** to `NT SERVICE\LinkScope`. On a UNC share, both share and filesystem permissions must allow the service's network identity to create, replace and delete files. Local Service typically accesses network resources anonymously. Use a local folder if your share requires an authenticated identity. Choose a dedicated folder without junctions or symbolic links.
3. Set **Maximum files to keep** and **Save settings**. The default is **100**, with a range of **1–10,000**. Check the output status on the same page.

Each file contains one active incident and is named `LinkScope-alert-<installation-id>-<sequence>.json`. It includes the monitoring host, occurrence ID, category, severity, message, UTC start and read status. Readers see complete UTF-8 JSON files through atomic publication. Use the nested `alert.id` to correlate a file with the bell history.

Files are ordered by the alert's opening sequence. Only the newest **N active alerts** are exported. An alert resolving removes its file during the next background synchronization. If there is spare capacity, the next older still-active alert can reappear. Marking an alert read updates its JSON file. Changing directories or disabling export cleans up LinkScope-managed files in the previous location. Other applications' files are preserved. File retention has no effect on SQLite alert history. The service reconciles on startup, on changes, and periodically to recover from temporary filesystem errors.

Microsoft documents the [Local Service account](https://learn.microsoft.com/en-us/windows/win32/services/localservice-account).

The JSON properties are `JsonEnabled`, `JsonDirectory` and `MaxJsonFiles` inside `Delivery`. If deletion fails, restore the service's delete permission and check the output status for the next synchronization.

### Windows health and notifications

| Settings field | JSON property | Default | Accepted value and effect |
| --- | --- | --- | --- |
| High CPU threshold | `CpuAlertPercent` | 90% | 1–100. CPU utilization at or above the threshold raises an alert. |
| High RAM threshold | `RamAlertPercent` | 90% | 1–100. RAM utilization at or above the threshold raises an alert. |
| Volume usage threshold | `DiskAlertPercent` | 90% | 1–100. Applies to individual fixed volumes. |
| Consecutive failed probes for an alert | `ProbeAlertCount` | 3 | 1–100, per target. A successful probe resets the failure count. |
| CPU, RAM and disk sample (seconds) | `ResourceSeconds` | 15 | 5–3600 seconds between resource sampling cycles. The first CPU sample establishes a baseline. |
| Windows inventory interval (minutes) | `InventoryMinutes` | 5 | 1–1440 minutes between completed inventory cycles. The separate privileged SMART task captures hardware every five minutes. |
| Disk replacement threshold | `LowLifePercent` | 10% remaining | 1–50. A reported life estimate at or below this threshold can trigger replacement advice. Firmware warnings and failing SMART attributes may also trigger it. |
| Write replacement notifications | `WriteDiskEvents` | `true` | Writes Application log warnings from **Unixfor LinkScope**, Event ID **4101**, when a drive enters a replacement state. Dashboard alerts have their own read/acknowledgement state. |
| Recent events per channel | `EventsPerChannel` | 25 | 1–100 per selected channel over a rolling 24 hours. Captures Critical, Error and Warning levels. |
| Event log channels | `EventChannels` | First five below | Select at least one supported channel. Availability depends on Windows edition, enabled logging and read permissions. |
| API response categories | `ExtraCategories` | `[]` | Enables optional inventory for collection, signed-in views, reports and token scope selection. The eight core categories are always available for selection. |

| Event channel | Default |
| --- | --- |
| `System` | On |
| `Application` | On |
| `Microsoft-Windows-Windows Defender/Operational` | On |
| `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` | On |
| `Microsoft-Windows-WindowsUpdateClient/Operational` | On |
| `Microsoft-Windows-TaskScheduler/Operational` | Off |
| `Microsoft-Windows-NTFS/Operational` | Off |
| `Microsoft-Windows-Storage-Storport/Operational` | Off |

The next section describes certificates. The [API reference](#system-health-api) lists every category ID and the controls for generating and revoking tokens.

## HTTPS setup

The default **HTTP** address is `http://127.0.0.1:9876` on the monitoring computer. For **HTTPS**, choose a certificate, configure the listener in Settings, and restart LinkScope. The same port then speaks TLS 1.2. Update your browser bookmark and API base URL to `https://`.

### Choose the listener and DNS name

| Intended access | Listen on IP address | HTTPS DNS name | Client URL |
| --- | --- | --- | --- |
| Only on the monitoring computer | `127.0.0.1` | `localhost` | `https://localhost:9876` |
| On a management LAN (example) | `192.168.10.20` | `monitor01.example.internal` | `https://monitor01.example.internal:9876` |

Use your server's actual LAN IP and DNS name. The HTTPS handler checks the HTTP Host header against the configured origin, including a nondefault port. A certificate that covers multiple names still requires clients to use the name selected in Settings.

### Option A — LinkScope self-signed certificate

1. Complete the initial admin password change locally. On the monitoring host, inspect the DNS names and expiry of the certificate created by setup.

   ```powershell
   $root = "$env:ProgramData\LinkScope"
   $thumb = (Get-Content "$root\self-signed.thumbprint" -Raw).Trim()
   Get-Item "Cert:\LocalMachine\My\$thumb" |
       Format-List Subject, DnsNameList, Thumbprint, NotAfter, HasPrivateKey
   ```

2. If the certificate or thumbprint file is missing, run the following command in elevated 64-bit PowerShell and repeat step 1.

   ```powershell
   & "$env:ProgramFiles\LinkScope\LinkScope.exe" --prepare-certificate
   ```

3. In **Settings → Access and HTTPS**, check **Enable HTTPS** and choose **LinkScope self-signed certificate**. Set the IP, TCP port and DNS name from the table above. The generated certificate contains `localhost`, the computer name and, when available at creation, its machine FQDN. Use a name listed in the certificate. A custom DNS alias needs a certificate covering that alias.
4. Establish client trust. The public certificate is `%ProgramData%\LinkScope\LinkScope-public.cer`. On the monitoring host, get the SHA-256 file hash. Copy the **public .cer** to the intended Windows client. Compare the client's file hash with the value obtained directly from the host.

   ```powershell
   # Monitoring computer
   Get-FileHash "$env:ProgramData\LinkScope\LinkScope-public.cer" -Algorithm SHA256
   ```

   ```powershell
   # Windows client, in the folder containing the copy
   Get-FileHash .\LinkScope-public.cer -Algorithm SHA256
   # After the hashes match, trust the certificate for the current Windows user.
   Import-Certificate -FilePath .\LinkScope-public.cer -CertStoreLocation Cert:\CurrentUser\Root
   ```

   Windows curl builds using Schannel normally use the Windows trust store. For a client that uses a file-based CA bundle, convert the verified DER public certificate to PEM and point curl at the PEM file. Browser trust may depend on browser or enterprise policy.

   ```powershell
   certutil.exe -encode .\LinkScope-public.cer .\LinkScope-public.pem
   # Run after activating HTTPS, using the DNS name selected in Settings.
   curl.exe --cacert .\LinkScope-public.pem --silent --show-error --output NUL --write-out '%{http_code}' 'https://monitor01.example.internal:9876/login'
   ```

5. Click **Save settings**, complete the activation steps below, and open the new URL. For a planned renewal, `--prepare-certificate` creates a replacement when the generated certificate is missing, lacks its private key, or is within 30 days of expiry. Redistribute the verified public certificate if it changed and restart LinkScope.

### Option B — Your own CA-issued certificate

1. Obtain a current server-authentication certificate with an RSA or ECDSA private key and a DNS Subject Alternative Name matching the intended URL. The example name is `monitor01.example.internal`.
2. On the monitoring computer, run `certlm.msc` as an administrator. Under **Personal → Certificates**, use **All Tasks → Import** to import your PFX with its private key. To import from PowerShell, run the following commands.

   ```powershell
   $pfxPassword = Read-Host 'PFX password' -AsSecureString
   $cert = Import-PfxCertificate -FilePath '.\monitor01.pfx' -Password $pfxPassword -CertStoreLocation Cert:\LocalMachine\My
   $cert | Format-List Subject, DnsNameList, Thumbprint, NotAfter, HasPrivateKey
   ```

3. In `certlm.msc`, right-click the server certificate → **All Tasks → Manage Private Keys**. Add `NT SERVICE\LinkScope` on the local computer with **Read** access. Confirm the certificate has a private key. The service tests that it can open and use that key.
4. In **Settings → Access and HTTPS**, enable HTTPS, choose **My Windows certificate**, paste the **server certificate's 40-character thumbprint**, and enter its DNS name and your chosen listening IP/port. For a renewal, import the renewed certificate and grant key access before switching thumbprints.
5. Install required intermediates on the server and ensure clients trust the issuing CA under your organization's certificate policy. The server's private key stays on the server. Click **Save settings** and activate the listener below.

### Activate and test HTTPS

Run on the monitoring host in elevated PowerShell after saving.

```powershell
Restart-Service -Name LinkScope -ErrorAction Stop
Get-Service -Name LinkScope
```

For a LAN listener, allow inbound TCP on the configured port from the intended management client(s). If a domain firewall policy already supplies the rule, use it. The following is an example **host-side** rule for server `192.168.10.20` and one management PC at `192.168.10.50`. Replace both addresses and select the active Windows firewall profile.

```powershell
New-NetFirewallRule -Name 'Unixfor-LinkScope-Management' -DisplayName 'Unixfor LinkScope management' -Direction Inbound -Action Allow -Protocol TCP -LocalAddress 192.168.10.20 -LocalPort 9876 -RemoteAddress 192.168.10.50 -Profile Domain,Private -Program "$env:ProgramFiles\LinkScope\LinkScope.exe"
```

From the **client**, test DNS, TCP, then the HTTPS login page. For loopback-only setup, run the checks on the host with `localhost`.

```powershell
Resolve-DnsName monitor01.example.internal
Test-NetConnection monitor01.example.internal -Port 9876
curl.exe --silent --show-error --output NUL --write-out '%{http_code}' 'https://monitor01.example.internal:9876/login'
```

Expect `TcpTestSucceeded : True` and HTTP **200** for `/login`. Then test an authenticated API call. If DNS is pending, `curl.exe --resolve 'monitor01.example.internal:9876:192.168.10.20' 'https://monitor01.example.internal:9876/login'` tests the same hostname and certificate against that IP. Certificate or hostname errors must be fixed before sending a token.

### Recover local access

If a listener change prevents access, use an elevated PowerShell window on the monitoring computer.

```powershell
Stop-Service LinkScope -ErrorAction Stop
notepad.exe "$env:ProgramData\LinkScope\settings\config.json"
```

In the existing JSON, change `BindAddress` to `"127.0.0.1"`, `Port` to `9876` (or a free port), `HostName` to `"localhost"`, `UseHttps` to `false`, and `RequireLogin` to `true`. Save and close the editor, then run:

```powershell
& "$env:ProgramFiles\LinkScope\LinkScope.exe" --check-config
if ($LASTEXITCODE -eq 0) { Start-Service LinkScope -ErrorAction Stop }
```

Open the local HTTP URL. Configuration validation checks values and syntax. Listener startup checks the selected bind address, port and, when enabled, certificate key.

For more detail, see [Microsoft certificate stores](https://learn.microsoft.com/en-us/windows/win32/seccrypto/system-store-locations), [Import-Certificate](https://learn.microsoft.com/en-us/powershell/module/pki/import-certificate), [curl certificate verification](https://curl.se/docs/sslcerts.html).

## System health API

Use `GET /api/v1/system` to read the latest Windows health snapshot from the computer running LinkScope. The configured IP targets are ICMP probes. To see their loss, latency and history, open **Network**. To download a complete PDF for all targets, use **Export PDF** in the top bar. The bearer API has one read-only endpoint.

### Create and manage a token

1. Sign in as **admin** and open **Settings**. If the client needs optional data such as event message text, select it under **API response categories** and click **Save settings**.
2. Under **API tokens**, enter a **Client name** (1–80 characters), choose **Expires in days** (1–365, initially 90), and select the categories the client may read. At least one category is required. For example, give a capacity-monitoring client `cpu`, `ram` and `disk_usage`. Up to 128 unexpired tokens can be active.
3. Click **Generate token**, copy the entire `ls_` value into the client's secret store, then click **Hide token**. LinkScope displays the secret once and stores a hash.
4. To rotate, generate a replacement, update the client, test a request, then click **Revoke** beside the old token. Revocation applies to the next request. If the secret is lost, generate a new token. An admin password reset expires browser sessions. Use **Revoke** to withdraw a client's API access.

### Request and categories

| Item | Value |
| --- | --- |
| Local base URL on a default installation | `http://127.0.0.1:9876` |
| Remote base URL | The configured HTTPS origin, for example `https://monitor01.example.internal:9876` |
| Protocol, method and path | HTTP/1.1, `GET /api/v1/system` |
| Required header | `Authorization: Bearer <token>` with the complete, case-sensitive token |
| Optional query | `categories=cpu,ram`. Use distinct lowercase IDs, separated by commas without spaces. |
| With no query string | Returns every category currently enabled on the server and granted to this token. |
| Successful response | HTTP 200 with a JSON snapshot and active alerts for the selected categories. |

| Category group | IDs to use in curl |
| --- | --- |
| Core health (always enabled) | `cpu`, `ram`, `disk_usage`, `smart`, `events`, `firewall`, `antivirus`, `security` |
| Optional operating system and hardware | `os`, `computer`, `bios`, `baseboard`, `processors`, `memory_modules`, `graphics`, `pnp_devices`, `usb`, `battery` |
| Optional networking and storage | `network_adapters`, `ip_addresses`, `dns`, `routes`, `volumes`, `partitions`, `shares`, `pagefile` |
| Optional software and operations | `services`, `processes`, `hotfixes`, `installed_software`, `drivers`, `printers`, `time_zone`, `event_details` |

Turning off an optional category removes it from the effective access of existing tokens. To poll for capacity, request just the needed IDs. Optional inventory can include up to 256 records per applicable category. The event categories use the configured per-channel count and a rolling 24-hour window. `events` supplies record metadata. `event_details` adds message text of up to 512 characters and needs its own permission.

### Windows PowerShell with curl.exe

Run the setup block **once in the same PowerShell window**. Use the local URL on the monitoring host or replace it with the server's configured HTTPS URL on a remote client. The examples use `curl.exe` explicitly so they work even when PowerShell maps `curl` to another command. The `--header '@-'` option reads the header from standard input. It requires curl 7.55.0 or newer.

```powershell
$Base = 'http://127.0.0.1:9876'
# For a remote client, use the name on the configured certificate.
# $Base = 'https://monitor01.example.internal:9876'

$secureToken = Read-Host 'Paste the LinkScope API token' -AsSecureString
$authHeader = 'Authorization: Bearer ' + ([System.Net.NetworkCredential]::new('', $secureToken)).Password
```

**Get all categories this token can read** and print the JSON.

```powershell
$authHeader | curl.exe --silent --show-error --fail --connect-timeout 5 --max-time 20 --header '@-' "$Base/api/v1/system"
```

**Get CPU, RAM and volume usage**, then print CPU and RAM percentages. Use a token with all three categories.

```powershell
$raw = $authHeader | curl.exe --silent --show-error --fail --max-time 20 --header '@-' --get --data-urlencode 'categories=cpu,ram,disk_usage' "$Base/api/v1/system"
if ($LASTEXITCODE -ne 0) { throw 'LinkScope request failed.' }
$health = $raw | ConvertFrom-Json
$health.categories.cpu.result | Select-Object status, usedPercent
$health.categories.ram.result | Select-Object status, usedPercent
$health.categories.disk_usage.result.items | Select-Object volume, usedPercent, freeBytes
```

**Save a disk-health snapshot** to a JSON file and read its replacement recommendations. A drive may have a verdict even when it cannot report a life percentage.

```powershell
$authHeader | curl.exe --silent --show-error --fail --max-time 20 --header '@-' --get --data-urlencode 'categories=smart' --output '.\linkscope-smart.json' "$Base/api/v1/system"
if ($LASTEXITCODE -ne 0) { throw 'Disk-health download failed.' }
$diskHealth = Get-Content '.\linkscope-smart.json' -Raw | ConvertFrom-Json
$diskHealth.categories.smart.result.items | Select-Object model, diskId, estimatedLifeRemainingPercent, recommendation
$diskHealth.alerts | Select-Object severity, title, message
```

**Read recent event metadata, firewall and antivirus status** using a token granted those categories.

```powershell
$authHeader | curl.exe --silent --show-error --fail --max-time 20 --header '@-' --get --data-urlencode 'categories=events,firewall,antivirus' "$Base/api/v1/system"
```

**Inspect an HTTP error.** The first command deliberately omits the token and should return HTTP 401. The second shows the headers and body of a real request. When finished, remove the header and token variables from your session.

```powershell
curl.exe --silent --show-error --include --max-time 20 "$Base/api/v1/system"
$authHeader | curl.exe --silent --show-error --include --max-time 20 --header '@-' --get --data-urlencode 'categories=cpu' "$Base/api/v1/system"
Remove-Variable authHeader, secureToken
```

### Bash with curl

Use this from a Linux or macOS management client that trusts the server certificate. For a verified private CA bundle, add `--cacert /path/to/ca.pem` to the curl command.

```bash
base='https://monitor01.example.internal:9876'
read -rsp 'Paste the LinkScope API token: ' token
printf '\n'
printf 'Authorization: Bearer %s\n' "$token" |
  curl --silent --show-error --fail --connect-timeout 5 --max-time 20 \
    --header '@-' --get --data-urlencode 'categories=cpu,ram' "$base/api/v1/system"
unset token
```

The ZIP also contains a PowerShell client. It prompts for a token, validates the HTTPS certificate and writes the JSON to standard output.

```powershell
.\Get-LinkScopeHealth.ps1 -Server 'https://monitor01.example.internal:9876' -Categories cpu,ram,smart
```

### Read a response

Illustrative response to `?categories=cpu` after sampling has started.

```json
{
  "schemaVersion": 1,
  "monitorHost": "MONITOR01",
  "generatedUtc": "2026-11-25T08:00:03.0000000Z",
  "categories": {
    "cpu": {
      "collectedUtc": "2026-11-25T08:00:00.0000000Z",
      "ageSeconds": 3,
      "stale": false,
      "result": { "status": "ok", "usedPercent": 17.4 }
    }
  },
  "alerts": []
}
```

Use `monitorHost` to identify the source. `generatedUtc` is the time of the response, and `collectedUtc` is the time of the measurement. `stale` becomes true after more than twice the category's configured sample interval plus 60 seconds. Immediately after startup a category can be just `{"status":"collecting"}`. The first CPU result can report `warming_up` with a null percentage. Treat missing, stale, partial and unavailable data separately from measured zero. An empty `alerts` array means there are no active alerts for the categories in this response.

### Troubleshoot API requests

| Result | Meaning and action |
| --- | --- |
| 200 with `collecting` or `warming_up` | Let the relevant sampler run and request the snapshot again. Some Windows providers can report partial or unavailable coverage. |
| 400 | Check the URL, host, port and parameter name. The only query parameter is `categories`. |
| 401 | Supply the full bearer header. Check for a missing, expired, revoked or incorrectly copied token. The admin sign-in password is a browser credential. |
| 403 | One or more requested categories are unknown, disabled, repeated, empty or outside this token's scope. Omit the query to see what the token can currently read. |
| 404 | Use the exact path `/api/v1/system` and the GET method. |
| 405 | The HTTP listener rejected the method. Send a GET request. |
| 503 | The service could not complete the request. Retry later and inspect the service log if the error persists. |
| Connection or TLS error before any HTTP status | Test DNS, then TCP connectivity, then certificate trust and name. See [Activate and test HTTPS](#activate-and-test-https). |

See the [curl command reference](https://curl.se/docs/manpage.html) for header input, URL encoding, timeouts and export options.

## Test with Postman

The `docs` folder contains [LinkScope.postman_collection.json](LinkScope.postman_collection.json) and [LinkScope.postman_environment.json](LinkScope.postman_environment.json).

1. In the Postman desktop application, choose **Import** and select **both JSON files**. Select **LinkScope — local or HTTPS** as the active environment.
2. Set **baseUrl** to `http://127.0.0.1:9876` on the monitoring computer or to the configured HTTPS origin, such as `https://monitor01.example.internal:9876`, from another machine. Omit the trailing slash. For private or self-signed certificates configure the trusted CA in Postman. Leave certificate validation enabled.
3. In LinkScope **Settings → API tokens**, create a token with the eight core categories for the full standard test run. In Postman paste it into the local value of **apiToken**. For optional inventory, enable the desired IDs in LinkScope, grant them to the token, and enter their comma-separated IDs in **optionalCategories**. Leaving it empty skips that request.
4. Run **1. System health API** and **2. API error responses**, or run the entire collection. The tests cover all eight core categories, combined category selection, response structure, and expected 400, 401, 403 and 404 responses. A deliberately rejected request passes when it returns the expected status.
5. For the optional admin tests, first finish the starter password change in the browser. Set **runAdminTests** to `true` and enter the permanent LinkScope password in the **local value** of **adminPassword**. Run **3. Optional admin diagnostics and temporary token lifecycle** *in order using the Collection Runner*. Keep Postman's cookie jar enabled. The folder signs in, reads the settings, alert history and graph/report inputs, issues a one-day CPU-only token, verifies scope enforcement, revokes it and signs out. The final revoked-token request must return **401**. It reads alert history without marking live alerts as read.
6. After testing, clear the local secret values if this is a shared workstation. If a run is interrupted after issuing a token, open **Settings → API tokens** and revoke the token labelled `Postman-LinkScope-…` for that run.

| Environment variable | Value supplied |
| --- | --- |
| `baseUrl` | Defaults to the local HTTP origin. Use the configured DNS name over HTTPS for remote calls. |
| `apiToken` | Empty secret. Supply the full bearer token including its `ls_` prefix. |
| `optionalCategories` | Empty. Optional comma-separated IDs, for example `os,bios`, if enabled and granted. |
| `runAdminTests` | Defaults to `false`. Set to the text `true` to enable folder 3. |
| `adminPassword` | Empty secret. Required only for the optional folder. |

The optional admin folder also checks delivery status. To send a **real SMTP test** from Postman, explicitly set **runSmtpTest** to `true` in addition to enabling the admin folder. The request uses the saved SMTP settings from that run's settings read. Use **smtpTestOverrides** for unsaved options, for example `{"To":"operator@example.org","Cc":"","Bcc":"","TimeoutSeconds":30}`. Supply **smtpTestPassword** only when you want to test a replacement password. The next request polls for relay acceptance. The default `runSmtpTest=false` skips both send and wait requests.

The PDF is rendered in the browser. Postman tests its data sources. To verify the downloaded document, sign in to the dashboard and click **Export PDF**. For the Postman import workflow, see [Import data into Postman](https://learning.postman.com/docs/getting-started/importing-and-exporting/importing-data/).

## Loading indicators

AI Assist shows a spinner above the question box as soon as you send a question or request a verdict. The label follows the service through evidence collection and model analysis. The spinner clears when the answer appears, the service confirms cancellation, or an error is shown. If you return to AI Assist in the same session during a request, the page checks its status and resumes showing progress.

A small indicator in the lower-left corner appears when a page load or foreground action takes longer than 200 milliseconds. Actions include changing a graph period, searching or paging through alerts and logs, saving settings, and exporting the complete PDF. You can keep using the page while it is visible. Routine monitoring refreshes run quietly. Both indicators use a static ring and a text label when reduced motion is enabled.

## Interpreting the graphs

- **Round-trip latency** shows the weighted average of successful replies and their minimum and maximum in each time bucket. Failed probes have no latency value. Hover over a chart, or focus it and use the arrow keys, to inspect an interval.
- **Packet loss** is unanswered probes divided by successful plus unanswered probes. An unreachable response counts as an unanswered echo. Timeouts also have their own count. Local probe errors are reported separately. ICMP filtering or rate limiting can affect results.
- **Monitor adapter traffic** shows receive and transmit Mbps calculated from byte-counter deltas and elapsed time on one local interface. Compare a latency spike with this chart to see whether it coincides with heavy traffic on the monitor. Measuring a router or switch link’s own utilization requires counters from that device.
- **Missing observations** appear as gaps. Service downtime does not generate synthetic timeouts. The footer shows how many time buckets have at least one observation. A stale last probe is labelled on the page.
- **Recent probe failures** lists up to 2,000 recent failures within the selected period and retained raw history. Filter by free text, failure category, exact result and local date/time range, sort newest/oldest, and use colored category badges and pagination. Filters persist during the five-second dashboard refresh. The existing report/API events field retains the latest 20 entries; searchEvents supplies the extended snapshot.

**Example from a new installation.** The horizontal axis shows the entire selected period. If the service has run for only 15 minutes, the Day chart will show those readings at the far right of a 24-hour window. The vertical latency axis starts at zero and rounds up to a readable maximum. A highest reply of 30 ms gives a 0–50 ms scale with grid lines every 12.5 ms. The darker line shows average latency in each bucket. The pale bar shows the fastest and slowest successful replies. A blank interval means there are no measured replies to plot. Check packet loss and the observation count to distinguish failed probes from time before monitoring began.

## Windows health

Open **System health → Resource history**. Choose **Day**, **Week**, **Month**, or **Year** to graph CPU usage, RAM usage and utilization of each fixed volume with stored samples. Charts appear two per row on desktop and one per row on narrow screens. Click the plot or choose **Expand** to open a larger chart of the same metric and time range. Hover or use the arrow keys on the enlarged chart to inspect intervals. Use **Close**, Escape, or the backdrop to return. Each chart uses a 0–100% scale, with a dark line for the weighted average and a pale bar for the minimum and maximum. Hover, or focus the graph and use the arrow keys, for the exact interval. Blank intervals indicate missing samples. The historical graphs use existing SQLite data. SMART attributes, antivirus, firewall and optional inventory show the latest available readings.


| Default category | Data returned |
| --- | --- |
| `ram` | Total, available and used bytes, used percentage |
| `cpu` | CPU busy percentage between samples. The first sample establishes a baseline. |
| `disk_usage` | Fixed drive letters, capacity, free and used bytes and percentage |
| `smart` | Per-drive verdict, model, firmware, serial, capacity, scan time, vendor, bus, ATA attributes, NVMe log, findings, advice and reliability counters when available |
| `events` | Critical, Error and Warning records in the last 24 h. Default logs cover System, Application, Microsoft Defender, Windows Firewall and Windows Update. Each channel has a status and truncation indicator |
| `firewall` | Domain, Private and Public firewall profile states and effective default actions |
| `security` | UAC policy, UEFI Secure Boot, TPM readiness and OS-volume BitLocker protection |
| `antivirus` | Defender engine, real-time protection and definitions, plus Windows Security Center summary and registered products where Windows exposes them |

Open **System health → Disk health and SSD life**. Each drive has **S.M.A.R.T. Report**, **Findings / Advice** and **Diagnostics / NVMe** tabs. ATA rows show State, Num, Attribute Name, Value, Worst, Raw (hex) and Threshold. The report uses Samsung-specific names on matching drives and retains unknown vendor IDs. Missing thresholds display a dash. NVMe drives show native critical warning, endurance, temperature, spare, power-on hours, media errors and other available counters. Windows, RAID controllers, USB bridges and virtual disks differ in the data they expose. A missing or stale hardware scan and unavailable attributes are identified explicitly. Unmatched Windows Storage records remain separate when a drive cannot be identified reliably.

The default low-life threshold is **10% estimated remaining**. Replacement warnings can also arise from firmware failure prediction, a critical SMART threshold or NVMe reliability warnings. The findings explain the reason. Windows wear and NVMe percentage used are endurance estimates. For a matching Samsung 870 EVO, LinkScope also evaluates its normalized wear attribute 177. Other vendor-specific normalized attributes retain their reported meaning. An unknown assessment appears as **UNABLE TO DETERMINE**. Dashboard warnings appear under System health. By default the service writes Windows **Application** event **4101**, source **Unixfor LinkScope**, when a disk enters a replacement state. It suppresses repeats across service restarts and rearms after a normal result.

## Toast notifications and read status

Notifications disappear after **five seconds**. Automatic dismissal leaves an alert unread. Click the **bell** or **Alert history** in the top navigation to open the signed-in history. The bell badge counts unread alerts, including resolved alerts. New tabs preview up to three recent unread alerts. Opening the history does not acknowledge anything.

- Choose **Mark as read** on an individual alert or its toast. **View details** on a toast also acknowledges the alert.
- Choose **Mark all alerts as read** to acknowledge the entire history through its last refresh, including rows outside the current search. Newer arrivals stay unread. **Refresh** retrieves new entries and **Previous**, **Next** and the page number let you navigate the results. Use **Rows** to change the page size.
- Each monitoring alert keeps its category, severity, message, start time, active or resolved state, read status and resolution time when available. Read and resolved occurrences remain in `history.sqlite`. Alert history has no automatic age cutoff. A recurring incident after recovery gets a new entry.
- On upgrade the service imports the alerts retained in the old `alert-state.json` once, with their read and resolved flags. Previous versions discarded some resolved alerts. Only records still present at the upgrade can be imported.
- With anonymous localhost viewing enabled, visitors can dismiss their own notices in that browser. Sign in to view full history or change the shared read state. Open the **user icon → Log off** to end a signed-in session on any dashboard page.

### Search and page through alerts

On **Alert history**, search by target name, IP address, alert ID, category, severity, title or text in the message. Multiple words must all match somewhere in the record. The search ignores case and accents. For example, search for a branch IP and `latency`, or use a Greek target name without entering its accents.

Open **Advanced filters** to combine a category, severity, active/resolved state, read/unread status, and an opening-date range in your browser's local timezone. The end date includes the whole day. Click **Search** to apply the filters across the complete SQLite history. **Clear search** restores the full list. The bell count and **Mark all alerts as read** always apply globally.

Use **Rows** (10, 25, 50 or 100), **Previous**, **Next**, or enter a page number. Alerts start at 25 rows per page. Newly arriving alerts appear when you refresh or start a new search, so they do not shift rows while you page through results. Marking an alert read updates the current results. Network failures, probe-rule settings, API tokens, SMART attributes, per-channel events, and inventory tables use the same paging controls with 10 rows initially. Their current page is preserved during dashboard refreshes. Paging shows the records collected for that table. The PDF export includes the full report regardless of the page or filters on screen.

The defaults are **90%** for CPU, RAM and volume usage, **10% remaining SSD life**, and **three consecutive failed probes** for a network warning. Settings lets you change these thresholds. Other notices include SMART review or unavailable coverage, recent critical/error/warning events grouped by channel and level, disabled firewall profiles, antivirus health, disabled Defender protection, outdated Defender definitions, and collection errors or inventory limits in enabled categories. The PDF includes all active alerts. The remote JSON API includes active alerts only for its authorized response categories. Browser notifications use a local toast component bundled in the executable.

## Export a complete PDF report

Sign in and click **Export PDF** in the top navigation on Network, System health, Alert history or Settings. The single download is named `LinkScope_Complete_<UTC timestamp>.pdf`. The selection currently open in the dashboard does not limit the export.

The report includes the following sections.

- Every configured ping target across **Day, Week, Month and Year**, with latency, packet loss, timeouts, monitor adapter traffic and retained recent probe failures.
- CPU, RAM and per-volume summaries and graphs for the same four periods. Existing observations appear immediately after upgrade. Gaps identify periods without measurements.
- The monitoring computer's latest readings for every enabled Windows category, including SMART attributes, NVMe diagnostics, replacement advice, recent Windows events, firewall, antivirus and enabled optional inventory. The Windows event window is the 24 hours before collection.
- Active alerts plus the full stored **alert history**, including read and resolved occurrences. Longer sections continue across pages.
- A **LinkScope-report.json** attachment containing the network, resource, Windows and alert data used in the PDF. Save it from a PDF reader's attachments panel.

Export uses the browser and can take longer for many targets or a long alert history. Keep the page open until the download begins. If any section fails to load, the page reports the error and lets you retry. Reports may contain hostnames, IP addresses, drive serials, event messages and enabled inventory.

## SQLite history

CPU, RAM and per-volume utilization use sampled percentage aggregates at 5-minute and hourly resolution with the same 35-day and 400-day retention. Snapshots of optional inventory and event records are held in service memory. The latest direct disk scan is stored in the protected `hardware.json` file.

The service creates `%ProgramData%\LinkScope\data\history.sqlite` on first start. It writes each probe and its rollups in the same transaction. SQLite WAL mode lets the dashboard read while collection continues. To copy the database with ordinary file copy, stop the service first and copy the data directory as a unit, including any SQLite sidecar files. Restart the service afterward.

| Stored history | Retention | Dashboard use |
| --- | --- | --- |
| Individual probes | 48 hours (or latest month with protection enabled) | Latest probe status and exact failure timestamps |
| 5-minute aggregates | 35 days | Day at 5 minutes, Week at 30 minutes, Month at 2 hours |
| Hourly aggregates | 400 days | Year at 1 day |

The dashboard shows 24 hours, 7 days, 30 days or 365 days of UTC-aligned buckets ending in the current, partially filled bucket. Times display in the browser’s local timezone. Counts, sums and extrema preserve short spikes when graphs are aggregated. The service prunes expired history hourly. SQLite can reuse freed space in the existing file.

## Repair a service registered from a Debug folder

If `--install` printed `CreateService SUCCESS` followed by `Access is denied`, inspect the registered executable with `sc.exe qc LinkScope`. The previous installer registered the executable from its launch directory. A build under `C:\Users` can be inaccessible to the Local Service account.

Run these commands from an elevated PowerShell in the updated package folder.

```powershell
.\LinkScopeSetup.exe --install
Get-CimInstance Win32_Service -Filter "Name='LinkScope'" |
    Select-Object State, StartName, PathName
```

Look for `Running`, `NT AUTHORITY\LocalService` and `"%ProgramFiles%\LinkScope\LinkScope.exe" --service` with the actual Program Files path. The installer updates the existing LinkScope registration in place and retains the configured targets and existing SQLite history. A Visual Studio build of the updated source also supports `.\LinkScope.exe --install` directly from `bin\Debug`.

If startup still fails, the installer prints the service exit codes. Run these commands immediately afterward for details.

```powershell
sc.exe qc LinkScope
sc.exe queryex LinkScope
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'; StartTime=(Get-Date).AddMinutes(-15)} |
    Where-Object { $_.Message -match 'LinkScope' } |
    Select-Object -First 3 TimeCreated, Id, Message | Format-List
$log = "$env:ProgramData\LinkScope\data\service.log"
if (Test-Path $log) { Get-Content $log -Tail 30 }
```

## Service commands

To check the installed service and validate its configuration, run these commands in elevated PowerShell.

```powershell
$exe = "$env:ProgramFiles\LinkScope\LinkScope.exe"
Get-Service LinkScope
& $exe --check-config     # Check settings before restarting
```

If the configuration file is missing, run `LinkScope.exe --init-config` from the installation directory in elevated PowerShell to create it and prepare data-directory permissions.

For an interactive diagnostic run, stop the service, run `LinkScope.exe --console`, press Ctrl+C, then use `Start-Service LinkScope`. A file lock prevents two collectors from writing duplicate samples. Runtime errors are logged in `%ProgramData%\LinkScope\data\service.log`. If startup fails, check this file, the configuration, the bind address, and whether the port is already occupied.

| Installed executable switch | Purpose |
| --- | --- |
| `--install` / `--uninstall` | Deploy or remove the service and its two scheduled tasks. Run as Windows administrator. |
| `--init-config` / `--check-config` | Initialize missing configuration and protected directories, or validate the active configuration. |
| `--set-admin` | Set a permanent LinkScope admin password in an elevated interactive console. |
| `--prepare-certificate` | Prepare the self-signed certificate and its service key permissions on the installed host. |
| `--smart-once` | Capture physical disk health immediately. Requires elevation. |
| `--console` / `--self-test` | Run monitoring interactively, or run the built-in checks. |
| `--service` | Entry point used by the Windows Service Control Manager. |

## Build from C# source

Run `Build.cmd` on Windows to generate `LinkScope.exe` and `LinkScopeSetup.exe` in the extracted folder. Visual Studio builds both in the configuration output folder. This path uses the Framework compiler without downloading packages. Alternatively, open `LinkScope.csproj` in Visual Studio with the .NET Framework 4.8 targeting pack. Run the new build with `--install` from an elevated terminal. It deploys to Program Files. An existing healthy service already running at the installed path keeps running. To deploy a new build over that running copy, stop the service before invoking `--install`. The managed Windows setup builder is in the `setup` directory. The legacy native Linux builder is retained for reference only.

## Verify on Windows

Setup first runs a self-check of the local-only default, remote HTTP rejection, ATA decoding, scoped-token revocation and persistent alert acknowledgements. The extended `--self-test` also checks JSON retention and recovery cleanup, advanced search on existing history, stable paging, SMTP secret handling, and a loopback-only test relay. Run `LinkScope.exe --self-test` to repeat these checks and test the starter-password change, password rules and preservation of existing credentials in a temporary directory.

Run `.\Verify.ps1` from the extracted package in elevated Windows PowerShell and enter the **LinkScope admin** credential when prompted. It checks registration, the database, default health categories, API authentication, a temporary CPU-only token, denial of an out-of-scope category, token revocation, the four network history ranges and a new probe. The script revokes its test token. After switching to HTTPS, the verification computer must trust the certificate.

For a disk-by-disk hardware check, open **System health → Disk health and SSD life**. Compare model, firmware and serial with the intended drive. Check the hardware reader task, its most recent run, and the captured data if rows are unavailable.

```powershell
Get-ScheduledTaskInfo -TaskName 'Unixfor LinkScope SMART'
Get-Item "$env:ProgramData\LinkScope\hardware.json" | Select-Object LastWriteTime, Length
Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='Unixfor LinkScope';Id=4101} -MaxEvents 10
```

The event query may return no matches until a drive first triggers a replacement warning. An elevated administrator can run `LinkScope.exe --smart-once` on the monitoring computer for an immediate hardware capture. The dashboard reads it on the next Windows inventory cycle.

## Application logs and syslog

Open **Logs** in the top navigation. Each row shows its local time, a labeled severity badge, module, operation, message and any client or target IP, HTTP status and duration. Purple means Debug, blue Info, amber Warning and red Error. Use **Advanced filters** to combine literal search terms with level, module, operation, IP, status code and a local date/time interval. The start is inclusive and the end exclusive. Search ignores case and accents. Choose 10, 25, 50 or 100 rows, use Previous/Next or jump to a page. **Refresh** takes a new snapshot. New arrivals do not move the current page while you browse. Retention may remove expired entries.

**Settings → Application logging** takes effect when saved. Defaults are **Info**, **30 days**, and syslog forwarding **off**. Choose **Debug** to trace routine successful module calls, including each ICMP reply, Windows health and inventory category, history write, alert-rule evaluation and read-only dashboard poll. Info includes service lifecycle, successful authenticated API calls, settings and token operations, report requests, and mail delivery. Warnings include probe failures and rejected requests. Errors include failed operations and HTTP 5xx. Application log detail is intentionally structured. HTTP metadata includes the known route, HTTP code, peer and duration. Request bodies, raw query strings, headers, API keys, credentials, AI questions and AI answers are excluded.

| Setting | Default | Meaning |
| --- | --- | --- |
| Minimum level | Info | Store this level and higher. Choose Debug while tracing routine activity. |
| Retention (days) | 30 | 1–3650 days. The service removes expired rows on startup, after a change and hourly. Reducing the period can delete older rows immediately. It applies to the application journal and its pending forwarding queue. |
| Forward to syslogd | Off | Starts forwarding newly captured records. Local logging continues if the receiver is unavailable. |
| Server / port | Empty / 514 | Enter a DNS name or IP and the receiver's listening port. |
| Transport | UDP | UDP datagrams, TCP, or TCP with TLS and Windows certificate validation. TCP uses octet-counted framing. The UI suggests 6514 for TLS. |
| Facility | 16 (local0) | Select the facility used by your receiver's routing rules. |
| Minimum forwarding level | Info | Forwards records meeting both the local and forwarding thresholds. |

For example, to forward warnings to an existing rsyslog receiver, enable forwarding, enter its DNS name, select its configured transport and port, choose **local0**, select **Warning**, and save. Look in the receiver for the application name **LinkScope**. UDP can confirm a local send only. TCP/TLS retries may duplicate a partially sent batch. Records waiting for delivery survive service restarts until local retention expires. Disabling forwarding or changing the destination clears that destination's pending work. A send already in progress can finish. Forwarding failures are recorded locally and retried with backoff. The delivery status is visible in Settings.

The local database is **%ProgramData%\LinkScope\data\application-logs.sqlite**. The PDF includes retained counts by module and level. The existing **service.log** remains a small rotating fallback for startup and local-journal failures. Alerts, monitoring history and the Windows Application event log have their own retention. Maintenance commands use fixed event IDs in the Windows Application log and are imported by the service on its next check. The in-memory write buffer holds 8,192 entries. Queue overflow is reported locally when writing resumes.

## Forward application logs to Seq, Wazuh or Elasticsearch

After signing in, open **Settings**. **SIEM forwarding** is the first section on the page. You can also open it directly at `/settings#siem`. If this section is missing on your host, follow [Reinstall or upgrade](#reinstall-or-upgrade) from the newly extracted ZIP. Expand a receiver, enable it, enter its settings, and choose the minimum forwarding level. Click **Save settings**. The changes take effect immediately. Each receiver can run independently alongside the local application log and existing syslogd destination. Fresh installations and upgrades start with all three SIEM receivers disabled.

| Receiver | Settings | Delivery and verification |
| --- | --- | --- |
| Seq | Enter the ingestion server's base URL, for example `https://seq.example.org`, and the ingestion key if required. A reverse-proxy path prefix is supported. | LinkScope appends `/ingest/clef` and posts newline-delimited CLEF. Keys use the `X-Seq-ApiKey` header. Search Seq for `Application = 'LinkScope'` or `EventId = '<test ID>'`. |
| Wazuh | Enter the manager or syslog relay hostname, protocol and port. Defaults are TCP and 514. On the manager, configure a syslog `<remote>` listener with the matching port and protocol and include the LinkScope host's IP in `<allowed-ips>`. Restart the manager after changing that receiver configuration. | LinkScope sends a UTF-8 RFC 3164-style envelope with program name `LinkScope`, facility `local0`, and a single JSON object. TCP uses newline framing. Use the JSON decoder and a matching rule for alert indexing. Verify receiver input or enabled archives when a test event has no alert rule. |
| Elasticsearch | Enter the Elasticsearch base URL, an existing index or writable data stream (default `linkscope-logs`), and the **encoded** Elasticsearch API key if authentication is enabled. For a data stream, configure the appropriate index template. Grant the key create-document access to that target. | LinkScope posts NDJSON create actions to `/<target>/_bulk`. Each document includes `@timestamp`, `event.id`, `log.level`, `host.name`, `service.name`, and `message`. In Kibana Discover, open a data view matching the target and search `service.name : "LinkScope"` or `event.id : "<test ID>"`. |

**Send test event** queues one **Info** event to that saved receiver, even when its forwarding threshold is higher. The page displays its event ID and refreshes the receiver's delivery status. An HTTP receiver status of **Last accepted** means the sender received an ingestion response. Wazuh's **Last sent** reports a successful local socket write. Check the receiver for end-to-end confirmation.

**Scope and delivery.** The feed contains LinkScope application log entries, including recorded alert and recovery operations. Windows Event Log inventory and arbitrary files have separate collection paths. Ordinary events must pass both the local log minimum and the destination minimum. Queue records and local log inserts commit together in SQLite. Each receiver retries independently. Pending events survive a service restart until the corresponding log records expire under local retention. Enabling a receiver forwards new events. Disabling a receiver or changing its destination drops its pending deliveries. An in-flight send can complete. Rotating a key on the same destination keeps the backlog. Retries can duplicate Seq and Wazuh events. All three receivers carry a stable per-installation event ID. Elasticsearch checks individual bulk results and uses stable document IDs for retries against the same index.

HTTPS uses the Windows certificate trust store. Configure HTTPS for a receiver that uses an API key. Saved keys are protected with Windows DPAPI and redacted from the settings response. To change a receiver URL with a stored key, enter a replacement or select **Clear saved API key** before saving.

**Admin API and Postman.** `GET /ui/settings` returns receiver configuration and restart availability. `GET /ui/alert-delivery` returns `logStatus.siem` for all three receivers. With an administrator session, same-origin header and CSRF token, `POST /ui/siem-test` accepts `{"Receiver":"Seq"}`, `{"Receiver":"Wazuh"}` or `{"Receiver":"Elastic"}`. The response contains `queued` and `eventId`. Set the Postman environment variable **siemTestReceiver** to one of those names to enable this optional test in the admin folder. Leave it empty to skip sending. For a saved service change, `POST /ui/restart` with `{}` returns HTTP 202 when the restart task accepts the request. The standard Postman run does not restart the service.

For receiver configuration and wire formats, see [Seq HTTP ingestion](https://datalust.co/docs/posting-raw-events), [Wazuh syslog reception](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/syslog.html), and the [Elasticsearch bulk API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-bulk).

## AI Assist for technicians

1. Open **Settings → AI Assist** and select a provider. Enter the **exact model ID** authorized on your account, or your deployment name for Azure. For Amazon Bedrock use a model or inference profile ID compatible with Converse.
2. Enter the provider's API key. Keys are stored per provider using Windows machine DPAPI and the protected settings directory. A blank field keeps the existing key. Save before switching providers to retain a newly entered key. Changing a configurable endpoint requires re-entering or clearing its saved key.
3. Check **Enable technician AI Assist** and **Save settings**. Open **AI Assist**. The side panel shows which provider, model and host will receive a request.
4. Select **Generate system verdict** or ask a question, for example *“Packet loss increased this morning. Do the probes, adapter traffic and CPU readings suggest a host issue? Which check should I run first?”* Ask follow-ups in any language, including Greek. **Ctrl+Enter** sends. **Cancel request** stops the current analysis. **New chat** clears the session conversation.

| Provider | Connection settings |
| --- | --- |
| OpenAI, xAI, Mistral, DeepSeek, Groq, OpenRouter | Built-in chat-completions endpoint. Set a chat model ID and its provider key. |
| Anthropic Claude | Native Messages API, model ID and Anthropic key. |
| Google Gemini | Native generateContent API. Enter the bare model ID and a Gemini Developer API key. |
| Azure OpenAI | Resource API base such as `https://RESOURCE.openai.azure.com/openai/v1`, deployment name and resource key. |
| Amazon Bedrock | Regional base such as `https://bedrock-runtime.eu-central-1.amazonaws.com`, Converse model ID and Bedrock bearer API key. |
| Cohere | Native v2 Chat endpoint, model ID and Cohere API key. |
| Custom OpenAI-compatible gateway | HTTPS API base, for example `https://gateway.example.org/v1`, and model ID. Include an API key if the gateway requires one. |

**What the provider receives.** Each request includes the technician's question and a fresh snapshot of the available signals. These include all configured Windows categories, UAC, BitLocker, Secure Boot and TPM, SMART findings, event channel and event-ID counts, recent event metadata, firewall and antivirus state, active alerts, up to 60 recent recoveries, and each configured target's latest result and day/week/month/year network summaries. Resource and adapter aggregates cover the same four periods. Application logs contribute 24-hour counts and up to 30 recent warning/error metadata entries (without message bodies or peer addresses). The verdict also includes all collected SMART attributes, collected event metadata, up to 2,000 native connection rows, delivery status and SIEM status. Exact core health readings, alert counts, active alerts, recent history and coverage are appended independently of model summarization. Disabled optional categories are explicitly listed. Core and enabled inventory categories carry their collection time or availability. Empty history represents missing evidence. Network rates describe traffic observed on the monitoring host.

The provider can receive internal hostnames, IP addresses, inventory, alert titles, and operator-entered chat text. The evidence builder excludes credential settings, raw event message bodies, disk serial fields, and MAC address fields. Large snapshots are reviewed in groups and summarized in additional provider calls. The provider's token pricing, context size, regional availability and usage quotas apply. API usage starts only when a technician asks for analysis. No AI output is executed on the computer. Use a model with enough input capacity for a monitoring snapshot and its conversation context.

Each signed-in session has its own in-memory conversation. The most recent six exchanges are retained, with earlier responses shortened when sent back as context. Refreshing the page restores completed exchanges. New chat, sign-out, a provider configuration change, or a service restart clears the conversation. Inactive conversations expire after 30 minutes. AI Assist is disabled on fresh installs and upgrades until configured. Provider errors display the HTTP status. For 401/403, verify the key and model permission. For 404, check the model/deployment ID and API base. For 429, check the provider quota. Logs record the provider and operation outcome.

## Security posture

Open **System health → Security posture**. The **security** category shows UAC's EnableLUA policy, UEFI Secure Boot, TPM presence/readiness, and BitLocker protection on the OS volume. Each control reports enabled, disabled, or unavailable with a short explanation. For example, a suspended BitLocker protector can report disabled even if the volume is encrypted. Systems without a usable UEFI, TPM or BitLocker provider can return unavailable. A confirmed disabled control raises a warning for review against the organization's baseline. A missing reading retains an existing warning until LinkScope observes recovery.

Existing API tokens retain their original scopes. Generate a token with `security` selected to grant this category. The existing SYSTEM hardware task captures these four read-only checks every five minutes in the protected `%ProgramData%\LinkScope\security.json` cache. The service reads it during the configured Windows inventory cycle. A cache older than 15 minutes is treated as unavailable. No recovery passwords, key protectors or TPM owner secrets are collected. Firewall profiles and antivirus retain their own categories. Security appears in the combined PDF, alert search, technical AI evidence and API token scope selection. On upgrade, existing API tokens keep their original scopes. Issue a token with **Security posture** selected to read it remotely.

## API examples for Logs, Security and AI

Use an admin browser session for application logs and AI. The commands below are for Bash. First complete the normal login flow described in the API section. Set `BASE` to your LinkScope origin, `JAR` to the login cookie jar and `CSRF` to the value returned by `GET /ui/session`. The regular system API uses a scoped bearer token.

```bash
curl -fsS -H "Authorization: Bearer $LINKSCOPE_TOKEN" --get \
  --data-urlencode 'categories=security,firewall,antivirus' "$BASE/api/v1/system"

curl -fsS -b "$JAR" --get "$BASE/ui/logs/search" \
  --data-urlencode 'level=Warning' --data-urlencode 'module=Network' \
  --data-urlencode 'operation=ping' --data-urlencode 'size=25' --data-urlencode 'page=1'

curl -fsS -b "$JAR" "$BASE/ui/ai"
curl -fsS -b "$JAR" -H "Origin: $BASE" -H "X-CSRF-Token: $CSRF" \
  -H 'Content-Type: application/json' -d '{"verdict":true}' "$BASE/ui/ai/ask"
curl -fsS -b "$JAR" "$BASE/ui/ai/result"
curl -fsS -b "$JAR" -H "Origin: $BASE" -H "X-CSRF-Token: $CSRF" \
  -H 'Content-Type: application/json' -d '{"question":"Which finding should I verify first?"}' "$BASE/ui/ai/ask"
```

Poll `/ui/ai/result` until `busy` is false before sending a follow-up. The result contains the answer, timestamp, evidence coverage and any provider error. POST `{}` with the same session/CSRF headers to `/ui/ai/cancel` or `/ui/ai/clear`. Log search accepts `q`, `level`, `module`, `operation`, `peer`, `status`, `from`, `until`, `page`, `size` and `through`. Dates are UTC Unix seconds. Reuse the returned `through` on subsequent pages. `GET /ui/logs/summary` returns retained counts by module and level.

The Postman admin folder includes these diagnostic reads and an optional real AI verdict. Set **runAdminTests=true** for admin tests. Set **runAiTest=true** only when you want to send the host's evidence to your configured provider and incur its normal usage. Default runs skip the external analysis.

## Network chart expansion and connection snapshot

Click a chart, its title, or Expand to open a larger chart for the currently selected history period. Escape or Close dismisses it. The chart refreshes with the dashboard. SIEM forwarding is directly after Application logging in Settings.

The Network page includes a manual Active network connections snapshot. Sign in as administrator and click Refresh connections. The native .NET Framework IPGlobalProperties API enumerates active TCP connections, TCP listeners and UDP bindings across all local adapters (up to 2,000 rows per request). The authenticated GET /ui/connections endpoint is session-only, not a bearer-token API. This snapshot does not establish connection initiation direction, process ownership, UDP peers or per-connection throughput. No packet capture, persistent connection history or external forwarding is enabled.

### Advanced connection search and live polling
Use the Network page's Active network connections panel to search all fields, or combine protocol, state, local/remote endpoint, exact local/remote port and IPv4/IPv6 filters. Colored badges identify protocol and TCP state; counters describe the loaded snapshot. Auto refresh is off by default, with selectable 1, 2, 5, 10 or 30 second polling. Polling pauses in hidden tabs, avoids overlapping requests, and stops on authorization failure. Search is limited to the first 2,000 endpoints returned by the existing administrator-only API; the UI explicitly reports truncation. This is snapshot polling, not packet capture or a complete event stream.

Database cleanup settings override the legacy retention table when enabled. See the root README for retention, protection and scheduling details.
