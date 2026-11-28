[CmdletBinding()]
param([string]$Target, [PSCredential]$Credential)
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::Expect100Continue = $false
$root = Join-Path $env:ProgramData 'LinkScope'
$config = Get-Content (Join-Path $root 'settings\config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$registered = Get-CimInstance Win32_Service -Filter "Name='LinkScope'"
$expected = '"{0}" --service' -f (Join-Path $env:ProgramFiles 'LinkScope\LinkScope.exe')
if ($registered.PathName -ne $expected -or $registered.StartName -ne 'NT AUTHORITY\LocalService') {
    throw "Unexpected service registration. Path $($registered.PathName), account $($registered.StartName)."
}
$restartTask = Get-ScheduledTask -TaskPath '\' -TaskName 'LinkScope Restart' -ErrorAction Stop
if (@($restartTask.Actions).Count -ne 1 -or $restartTask.Actions[0].Execute -ne (Join-Path $env:ProgramFiles 'LinkScope\LinkScope.exe') -or $restartTask.Actions[0].Arguments -ne '--restart-installed') {
    throw 'Unexpected dashboard restart task action.'
}
if ((Get-Service LinkScope).Status -ne 'Running') { throw 'LinkScope is not running.' }
if (!(Test-Path (Join-Path $root 'data\history.sqlite'))) { throw 'SQLite history file is missing.' }
if (!$Target) { $Target = $config.Targets[0].Address }
$scheme = if ($config.UseHttps) { 'https' } else { 'http' }
$name = if ($config.UseHttps) { $config.HostName } else { $config.BindAddress }
$base = [UriBuilder]::new($scheme, $name, [int]$config.Port).Uri.AbsoluteUri
$origin = ([uri]$base).GetLeftPart([UriPartial]::Authority)
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
if (!$Credential) { $Credential = Get-Credential -UserName admin -Message 'LinkScope administrator' }
$login = @{user=$Credential.UserName; password=$Credential.GetNetworkCredential().Password} | ConvertTo-Json -Compress
$signIn = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "${base}auth/login" -ContentType 'application/json' -Headers @{Origin=$origin} -Body ([Text.Encoding]::UTF8.GetBytes($login)) -SessionVariable session
Remove-Variable login
if ($signIn.changeRequired) { throw "Complete the first sign-in at $base on the host, then verify using your new password." }
$state = Invoke-RestMethod -UseBasicParsing -Uri "${base}ui/session" -WebSession $session
if (!$state.admin) { throw 'Administrator session unavailable.' }
$headers = @{Origin=$origin;'X-CSRF-Token'=$state.csrf}
function Admin-Post($route,$body) {
    Invoke-RestMethod -UseBasicParsing -Uri ($base+$route) -Method Post -WebSession $session -Headers $headers -ContentType 'application/json' -Body ($body | ConvertTo-Json -Compress)
}
$health = Invoke-RestMethod -UseBasicParsing -Uri "${base}ui/system" -WebSession $session
foreach ($key in 'cpu','ram','disk_usage','smart','events','firewall','antivirus','security') {
    if (!$health.categories.PSObject.Properties[$key]) { throw "Missing category $key" }
}
function Expect-Status($url,$authHeaders,[int]$expectedCode) {
    try { Invoke-WebRequest -UseBasicParsing -Uri $url -Headers $authHeaders -MaximumRedirection 0 -ErrorAction Stop | Out-Null }
    catch { if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq $expectedCode) { return }; throw }
    throw "Expected HTTP $expectedCode from $url"
}
Expect-Status "${base}api/v1/system" @{} 401
$label = 'Verify-' + [guid]::NewGuid().ToString('N')
$key = Admin-Post 'ui/tokens' @{name=$label;categories=@('cpu');days=1}
$auth = @{Authorization=('Bearer '+$key.token)}
try {
    $sample = Invoke-RestMethod -UseBasicParsing -Uri "${base}api/v1/system" -Headers $auth
    if (($sample.categories.PSObject.Properties.Name -join ',') -ne 'cpu') { throw 'Token scope mismatch.' }
    Expect-Status "${base}api/v1/system?categories=ram" $auth 403
    Expect-Status "${base}ui/settings" $auth 403
} finally {
    $settings = Invoke-RestMethod -UseBasicParsing -Uri "${base}ui/settings" -WebSession $session
    $entry = @($settings.tokens | Where-Object name -eq $label)
    if ($entry.Count -ne 1) { throw "Cannot identify test token $label. Revoke it from Settings." }
    Admin-Post 'ui/tokens/revoke' @{id=$entry[0].id} | Out-Null
}
Expect-Status "${base}api/v1/system" $auth 401
Write-Host 'Default categories, API scope and revocation OK.'
$escaped = [Uri]::EscapeDataString(([Net.IPAddress]::Parse($Target)).ToString())
function Read-History([string]$Range) {
    Invoke-RestMethod -UseBasicParsing -Uri ("${base}api/history?range=$Range&target=$escaped") -TimeoutSec 15 -WebSession $session
}
foreach ($range in 'day','week','month','year') {
    $r = Read-History $range
    if (!$r.step -or $r.end -le $r.start) { throw "Invalid $range response." }
    Write-Host "$range OK ($($r.step) seconds per bucket)"
}
$report = @(Read-History all)
if ($report.Count -eq 1 -and $report[0] -is [array]) { $report = $report[0] }
if ($report.Count -ne 4 -or ($report.range -join ',') -ne 'day,week,month,year') {
    throw 'The service did not return all four PDF report periods. Confirm the updated build is installed.'
}
if (@($report | Select-Object -ExpandProperty now -Unique).Count -ne 1) {
    throw 'The PDF report ranges have different snapshot timestamps.'
}
Write-Host 'PDF report snapshot OK (day, week, month, year).'
$historyPage = Invoke-RestMethod -UseBasicParsing -Uri "${base}ui/alerts/history" -WebSession $session
if ($null -eq $historyPage.alerts -or $null -eq $historyPage.unread) { throw 'Alert history unavailable.' }
$delivery = Invoke-RestMethod -UseBasicParsing -Uri "${base}ui/alert-delivery" -WebSession $session
if ($null -eq $delivery.queued -or !$delivery.testState) { throw 'Alert delivery status unavailable.' }
$matchesPage = Invoke-RestMethod -UseBasicParsing -Uri "${base}ui/alerts/search?q=probe&size=10&page=1" -WebSession $session
if ($matchesPage.size -ne 10 -or $matchesPage.page -ne 1) { throw 'Alert search or paging unavailable.' }
$logPage = Invoke-RestMethod -UseBasicParsing -Uri "${base}ui/logs/search?level=Warning&size=10&page=1" -WebSession $session
if ($logPage.size -ne 10 -or $logPage.page -ne 1) { throw 'Application log paging unavailable.' }
$ai = Invoke-RestMethod -UseBasicParsing -Uri "${base}ui/ai" -WebSession $session
if (!$ai.provider) { throw 'AI Assist provider settings unavailable.' }
$manifest = Invoke-RestMethod -UseBasicParsing -Uri "${base}ui/report" -WebSession $session
if (!$manifest.targets -or !$manifest.windows.monitorHost) { throw 'Complete report manifest unavailable.' }
foreach ($range in 'day','week','month','year') {
    $trend = Invoke-RestMethod -UseBasicParsing -Uri ("${base}ui/resource-history?range=$range&at=" + $manifest.now) -WebSession $session
    if ($trend.range -ne $range -or !$trend.step -or $trend.now -ne $manifest.now) { throw "Invalid $range resource history." }
}
Write-Host 'Alert history, application report and four system trend periods OK.'
$before = (Read-History day).latest
$interval = [int]$config.IntervalSeconds
$deadline = [DateTime]::UtcNow.AddSeconds(2 * $interval + 15)
do {
    Start-Sleep -Seconds ([Math]::Min(5,$interval))
    $current = (Read-History day).latest
    if ($null -ne $current -and ($null -eq $before -or $current[0] -gt $before[0])) {
        Write-Host "New probe for $Target. Status $($current[1]). Configured interval $interval s."
        Admin-Post 'auth/logout' @{} | Out-Null
        return
    }
} while ([DateTime]::UtcNow -lt $deadline)
throw "No new probe was recorded for $Target. Check service.log and the dashboard."
