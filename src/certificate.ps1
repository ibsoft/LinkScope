$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$root = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'LinkScope'
$pointer = Join-Path $root 'self-signed.thumbprint'
$cert = $null
if (Test-Path -LiteralPath $pointer) {
    $thumb = [IO.File]::ReadAllText($pointer).Trim()
    if ($thumb -match '^[A-Fa-f0-9]{40}$') { $cert = Get-Item -LiteralPath "Cert:\LocalMachine\My\$thumb" -ErrorAction SilentlyContinue }
}
if (!$cert -or !$cert.HasPrivateKey -or $cert.NotAfter -lt (Get-Date).AddDays(30)) {
    $names = @('localhost',[Environment]::MachineName)
    $domain = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName
    if ($domain) { $names += ([Environment]::MachineName + '.' + $domain) }
    $cert = New-SelfSignedCertificate -Type SSLServerAuthentication -DnsName ($names | Select-Object -Unique) -CertStoreLocation Cert:\LocalMachine\My -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -KeyExportPolicy NonExportable -Provider 'Microsoft Software Key Storage Provider' -NotAfter (Get-Date).AddYears(2) -FriendlyName 'LinkScope HTTPS'
}
# Preserve the existing certificate and thumbprint; update only its display name.
if ($cert.FriendlyName -eq 'Unixfor LinkScope HTTPS') { $cert.FriendlyName = 'LinkScope HTTPS' }
$rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
try {
    $keyPath = Join-Path (Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Microsoft\Crypto\Keys') $rsa.Key.UniqueName
    $sid = (New-Object Security.Principal.NTAccount('NT SERVICE','LinkScope')).Translate([Security.Principal.SecurityIdentifier])
    $acl = Get-Acl -LiteralPath $keyPath
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid,'Read','Allow')
    $acl.SetAccessRule($rule); Set-Acl -LiteralPath $keyPath -AclObject $acl
} finally { $rsa.Dispose() }
[IO.File]::WriteAllBytes((Join-Path $root 'LinkScope-public.cer'),$cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
[IO.File]::WriteAllText($pointer,$cert.Thumbprint)
