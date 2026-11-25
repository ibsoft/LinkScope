[CmdletBinding()]
param(
    [Parameter(Mandatory)][uri]$Server,
    [string[]]$Categories,
    [Security.SecureString]$Token
)
$ErrorActionPreference = 'Stop'
if (!$Server.IsAbsoluteUri -or $Server.UserInfo -or $Server.Query -or $Server.Fragment -or $Server.AbsolutePath -ne '/') { throw 'Specify the server origin only.' }
$local = $Server.DnsSafeHost -in '127.0.0.1','::1','localhost'
if ($Server.Scheme -ne 'https' -and !($local -and $Server.Scheme -eq 'http')) { throw 'Remote requests require HTTPS.' }
if (!$Token) { $Token = Read-Host 'LinkScope API token' -AsSecureString }
$uri = $Server.GetLeftPart([UriPartial]::Authority) + '/api/v1/system'
if ($Categories) { $uri += '?categories=' + [Uri]::EscapeDataString(($Categories -join ',')) }
# HttpClient validates the peer certificate. Disable redirects so an API key stays at this origin.
Add-Type -AssemblyName System.Net.Http
$handler = New-Object Net.Http.HttpClientHandler
$handler.AllowAutoRedirect = $false
$handler.UseProxy = $false
$client = New-Object Net.Http.HttpClient($handler)
$response = $null
$prior = [Net.ServicePointManager]::SecurityProtocol
try {
    [Net.ServicePointManager]::SecurityProtocol = $prior -bor [Net.SecurityProtocolType]::Tls12
    $client.Timeout = [TimeSpan]::FromSeconds(20)
    $credential = New-Object Net.NetworkCredential('', $Token)
    $client.DefaultRequestHeaders.Authorization = New-Object Net.Http.Headers.AuthenticationHeaderValue('Bearer',$credential.Password)
    $response = $client.GetAsync($uri).GetAwaiter().GetResult()
    $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    if (!$response.IsSuccessStatusCode) { throw "LinkScope returned HTTP $([int]$response.StatusCode). $body" }
    $body
} finally {
    if ($response) { $response.Dispose() }; $client.Dispose(); $handler.Dispose()
    [Net.ServicePointManager]::SecurityProtocol = $prior
}
