# Creates a TLS certificate so PRISM is served over HTTPS.
#
#   powershell -ExecutionPolicy Bypass -File scripts\make-tls-cert.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\make-tls-cert.ps1 -HostNames prism.corp.local,10.0.0.5
#
# Writes backend\data\tls\prism.crt and prism.key. Start PRISM.bat notices them
# and starts PRISM on https://localhost:8000 instead of http.
#
# In an organisation, prefer a certificate from your own certificate authority:
# copy it to the same two files (PEM format), or point PRISM_TLS_CERT_FILE and
# PRISM_TLS_KEY_FILE at it. This script makes a *self-signed* certificate,
# which browsers warn about until it is trusted; it can add it to your own
# (current user) trusted list, and only after asking.
#
# Needs openssl, which comes with Git for Windows. Nothing is downloaded.

param(
    [string[]]$HostNames = @(),
    [int]$Days = 825
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$OutDir = Join-Path $Root 'backend\data\tls'
$CertFile = Join-Path $OutDir 'prism.crt'
$KeyFile = Join-Path $OutDir 'prism.key'

$openssl = (Get-Command openssl -ErrorAction SilentlyContinue).Source
if (-not $openssl) {
    foreach ($candidate in @("$env:ProgramFiles\Git\usr\bin\openssl.exe", "${env:ProgramFiles(x86)}\Git\usr\bin\openssl.exe",
                             "$env:LOCALAPPDATA\Programs\Git\usr\bin\openssl.exe")) {
        if ($candidate -and (Test-Path $candidate)) { $openssl = $candidate; break }
    }
}
if (-not $openssl) {
    Write-Host 'openssl was not found. Install Git for Windows (it includes openssl), or copy a certificate' -ForegroundColor Yellow
    Write-Host "from your organisation's certificate authority to $CertFile and $KeyFile (PEM format)." -ForegroundColor Yellow
    exit 1
}

if ((Test-Path $CertFile) -or (Test-Path $KeyFile)) {
    $answer = Read-Host 'A certificate already exists. Replace it? (y/N)'
    if ($answer -notmatch '^(y|yes)$') { Write-Host 'Kept the existing certificate.'; exit 0 }
}

$names = @('localhost', '127.0.0.1', '::1', $env:COMPUTERNAME) + $HostNames | Where-Object { $_ } | Select-Object -Unique
$san = ($names | ForEach-Object { if ($_ -match '^[0-9.]+$' -or $_ -match ':') { "IP:$_" } else { "DNS:$_" } }) -join ','

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
& $openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days $Days `
    -keyout $KeyFile -out $CertFile -subj '/CN=PRISM' `
    -addext "subjectAltName=$san" -addext 'keyUsage=digitalSignature,keyEncipherment' -addext 'extendedKeyUsage=serverAuth' 2>$null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $CertFile)) { throw 'openssl could not create the certificate.' }

# The private key is readable only by the current user (and administrators/SYSTEM).
$acl = Get-Acl $KeyFile
$acl.SetAccessRuleProtection($true, $false)
foreach ($identity in @("$env:USERDOMAIN\$env:USERNAME", 'BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM')) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'Allow')))
}
Set-Acl $KeyFile $acl

Write-Host ''
Write-Host "  Certificate created for: $($names -join ', ')" -ForegroundColor Green
Write-Host "    $CertFile"
Write-Host "    $KeyFile  (private key - keep it secret)"
Write-Host ''
Write-Host '  Browsers will warn about this self-signed certificate until it is trusted.'
$answer = Read-Host '  Trust it for your Windows account now? Windows will ask you to confirm. (y/N)'
if ($answer -match '^(y|yes)$') {
    Import-Certificate -FilePath $CertFile -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
    Write-Host '  Trusted. Restart PRISM (and the browser) to use https://localhost:8000' -ForegroundColor Green
} else {
    Write-Host '  Not trusted. PRISM still uses HTTPS; the browser will show a warning you can accept.'
}
