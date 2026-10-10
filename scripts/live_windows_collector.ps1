# PRISM live Windows collector.
#
# Reads NEW events from this computer's own Windows event logs every few
# seconds and pushes them to PRISM's live feed (POST /api/live/events):
#   - Security: logons (4624), failed logons (4625), explicit credentials
#     (4648), privileged logons (4672), network share access (5140)
#   - System: new services installed (7045)
#   - Sysmon, if installed: process creation (1), process access (10),
#     file creation (11), DNS queries (22)
#
# It only READS event logs and sends them to the PRISM address you give it
# (this computer by default). It changes nothing on the system.
#
# The Security and Sysmon logs can only be read by an administrator (or a
# member of "Event Log Readers"). Run this from an administrator PowerShell to
# include them; without that, only the System log is collected.
#
#   powershell -ExecutionPolicy Bypass -File scripts\live_windows_collector.ps1
#   ... -Server http://127.0.0.1:8000 -IntervalSeconds 3 -LookBackMinutes 10

param(
    [string]$Server = 'http://127.0.0.1:8000',
    [int]$IntervalSeconds = 3,
    # 0 = only events that happen after the collector starts.
    [int]$LookBackMinutes = 0,
    # PRISM's API access code; read from backend\data\.prism_token when omitted.
    [string]$Token = '',
    # Local-only by default: refuse to send this computer's events anywhere else.
    [switch]$AllowRemote
)

$ErrorActionPreference = 'Stop'
try { $Host.UI.RawUI.WindowTitle = 'PRISM live collector - close this window to stop' } catch { }
$computer = $env:COMPUTERNAME.ToUpper()
$endpoint = $Server.TrimEnd('/') + '/api/live/events'
$serverHost = ([Uri]$Server).Host
if (-not $AllowRemote -and $serverHost -notin @('127.0.0.1', 'localhost', '::1', '[::1]')) {
    Write-Host "  Refusing to send events to $serverHost`: local-only mode keeps this computer's data on this computer." -ForegroundColor Red
    Write-Host '  Add -AllowRemote only if sending them to another machine is intended.'
    exit 1
}
if (-not $Token) { $Token = $env:PRISM_AUTH_TOKEN }
if (-not $Token) {
    $tokenFile = Join-Path (Split-Path -Parent $PSScriptRoot) 'backend\data\.prism_token'
    if (Test-Path $tokenFile) { $Token = (Get-Content $tokenFile -Raw).Trim() }
}
$authHeaders = @{}
if ($Token) { $authHeaders['X-PRISM-Token'] = $Token }
# PRISM on this computer may use a self-signed HTTPS certificate
# (scripts\make-tls-cert.ps1). Accept it only for this computer's own address.
if ($Server -like 'https://*' -and $serverHost -in @('127.0.0.1', 'localhost', '::1', '[::1]')) {
    Add-Type -TypeDefinition @"
using System.Net;
using System.Net.Security;
public static class PrismLocalTls {
    public static void Install() {
        ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) => {
            if (errors == SslPolicyErrors.None) return true;
            var request = sender as HttpWebRequest;
            if (request == null) return false;
            var host = request.RequestUri.Host;
            return host == "127.0.0.1" || host == "localhost" || host == "[::1]";
        };
    }
}
"@
    [PrismLocalTls]::Install()
}
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

$sources = @(
    @{ Log = 'Security'; Ids = @(4624, 4625, 4648, 4672, 5140); Kind = 'security'; NeedsAdmin = $true },
    @{ Log = 'System'; Ids = @(7045); Kind = 'security'; NeedsAdmin = $false },
    @{ Log = 'Microsoft-Windows-Sysmon/Operational'; Ids = @(1, 10, 11, 22); Kind = 'sysmon'; NeedsAdmin = $true }
)

# Accounts that log on constantly as part of Windows itself.
$noiseAccounts = '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|DWM-\d+|UMFD-\d+|.*\$)$'

function Get-EventData($event) {
    $data = @{}
    foreach ($node in ([xml]$event.ToXml()).Event.EventData.Data) { if ($node.Name) { $data[$node.Name] = [string]$node.'#text' } }
    return $data
}

function Convert-Security($event) {
    $d = Get-EventData $event
    if ($event.Id -eq 4624 -and ($d.LogonType -eq '5' -or $d.TargetUserName -match $noiseAccounts)) { return $null }
    if ($event.Id -eq 4672 -and $d.SubjectUserName -match $noiseAccounts) { return $null }
    $user = $d.TargetUserName
    if (-not $user) { $user = $d.SubjectUserName }
    if ($d.TargetDomainName -and $user) { $user = "$($d.TargetDomainName)\$user" }
    return [ordered]@{
        RecordId        = "$computer-$($event.LogName)-$($event.RecordId)"
        TimeCreated     = $event.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        EventID         = [string]$event.Id
        Computer        = $computer
        WorkstationName = $d.WorkstationName
        TargetUserName  = $user
        SubjectUserName = $d.SubjectUserName
        LogonType       = $d.LogonType
        IpAddress       = $d.IpAddress
        ShareName       = $d.ShareName
        ProcessName     = $d.ProcessName
        ServiceFileName = $d.ImagePath
        Status          = $d.Status
    }
}

function Convert-Sysmon($event) {
    $d = Get-EventData $event
    $time = $event.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    if ($event.Id -eq 22) {
        # DNS query: sent in the DNS (Zeek-style) shape PRISM already understands.
        if (-not $d.QueryName) { return $null }
        return [ordered]@{ uid = "$computer-dns-$($event.RecordId)"; timestamp = $time; query = $d.QueryName; host = $computer; process = $d.Image }
    }
    return [ordered]@{
        RecordId       = "$computer-sysmon-$($event.RecordId)"
        EventID        = [string]$event.Id
        UtcTime        = $time
        Computer       = $computer
        User           = $d.User
        Image          = $(if ($d.Image) { $d.Image } else { $d.SourceImage })
        ParentImage    = $d.ParentImage
        CommandLine    = $d.CommandLine
        TargetFilename = $d.TargetFilename
        TargetImage    = $d.TargetImage
        GrantedAccess  = $d.GrantedAccess
    }
}

function Send-Records($records, $stream) {
    if ($records.Count -eq 0) { return }
    $uri = "${endpoint}?source=$stream"
    # Sent in chunks: the first poll can carry hours of history.
    for ($i = 0; $i -lt $records.Count; $i += 1000) {
        $chunk = @($records[$i..([Math]::Min($i + 999, $records.Count - 1))])
        $body = ($chunk | ForEach-Object { $_ | ConvertTo-Json -Compress }) -join "`n"
        $result = Invoke-RestMethod -Method Post -Uri $uri -Headers $authHeaders -Body ([Text.Encoding]::UTF8.GetBytes($body)) -ContentType 'application/x-ndjson'
        Write-Host ("  {0:HH:mm:ss}  {1,-28} sent {2,4}   accepted {3,4}" -f (Get-Date), $stream, $chunk.Count, $result.accepted)
    }
}

Write-Host ''
Write-Host '  PRISM live Windows collector' -ForegroundColor White
Write-Host "  Computer: $computer    Sending to: $endpoint"
try { Invoke-RestMethod ($Server.TrimEnd('/') + '/api/health') -TimeoutSec 5 | Out-Null }
catch { Write-Host "  PRISM is not reachable at $Server. Start it first (Start PRISM.bat)." -ForegroundColor Red; exit 1 }

# Decide which logs can be read, and where each one starts.
$active = @()
foreach ($source in $sources) {
    try { $latest = Get-WinEvent -LogName $source.Log -MaxEvents 1 -ErrorAction Stop }
    catch {
        $reason = if ($source.NeedsAdmin -and -not $isAdmin) { 'needs an administrator PowerShell' } elseif ($_.Exception.Message -match 'not found|No events|could not be found') { 'not installed or empty' } else { $_.Exception.Message }
        Write-Host ("  - {0,-40} skipped ({1})" -f $source.Log, $reason) -ForegroundColor Yellow
        continue
    }
    $start = $latest.RecordId
    if ($LookBackMinutes -gt 0) {
        $since = (Get-Date).AddMinutes(-$LookBackMinutes)
        $old = Get-WinEvent -FilterHashtable @{ LogName = $source.Log; StartTime = $since } -ErrorAction SilentlyContinue | Select-Object -Last 1
        if ($old) { $start = $old.RecordId - 1 }
    }
    $source.Last = [long]$start
    $active += $source
    Write-Host ("  + {0,-40} collecting" -f $source.Log) -ForegroundColor Green
}
if ($active.Count -eq 0) { Write-Host '  No readable event logs. Run from an administrator PowerShell.' -ForegroundColor Red; exit 1 }
Write-Host "  Watching for new events every $IntervalSeconds s. Press Ctrl+C to stop."
Write-Host ''

while ($true) {
    foreach ($source in $active) {
        $ids = ($source.Ids | ForEach-Object { "EventID=$_" }) -join ' or '
        $xpath = "*[System[($ids) and EventRecordID > $($source.Last)]]"
        $events = @(Get-WinEvent -LogName $source.Log -FilterXPath $xpath -ErrorAction SilentlyContinue | Sort-Object RecordId)
        if ($events.Count -eq 0) { continue }
        $source.Last = [long]$events[-1].RecordId
        $records = New-Object System.Collections.ArrayList
        foreach ($event in $events) {
            $record = if ($source.Kind -eq 'sysmon') { Convert-Sysmon $event } else { Convert-Security $event }
            if ($record) { [void]$records.Add($record) }
        }
        $stream = 'win-' + $computer.ToLower() + '-' + ($source.Log -replace '^Microsoft-Windows-', '' -replace '/.*$', '').ToLower()
        try { Send-Records $records $stream }
        catch { Write-Host "  Could not reach PRISM: $($_.Exception.Message)" -ForegroundColor Red }
    }
    Start-Sleep -Seconds $IntervalSeconds
}
