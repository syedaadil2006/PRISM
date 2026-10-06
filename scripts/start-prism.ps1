# PRISM launcher (called by "Start PRISM.bat").
#
# 1. Checks the computer: Windows version, 64-bit, processor, memory, free
#    disk space and internet access.
# 2. Checks what PRISM needs: Python 3.11+, Node.js 18+, the Python packages,
#    the dashboard packages and the built dashboard.
# 3. If anything is missing, lists exactly what will be downloaded, from
#    where, and where it will go, then ASKS before installing anything.
# 4. Starts PRISM on http://localhost:8000 and opens the browser.
#
# Everything is installed for the current user only: no administrator
# rights, no system-wide changes, and no changes to security settings.
# Downloads come only from official sources (python.org / winget, nodejs.org,
# pypi.org, npmjs.org).
#
# Optional environment variables (mainly for testing):
#   PRISM_PORT        port to use instead of 8000
#   PRISM_NO_BROWSER  set to 1 to skip opening the browser
#   PRISM_ASSUME_YES  set to 1 to answer "yes" to the install question

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$PythonVersion = '3.12.10'
$MinPython = [version]'3.11'
$MinNode = [version]'18.0'
$MinRamGB = 4
$MinFreeGB = 2
$Port = 8000
if ($env:PRISM_PORT) { $Port = [int]$env:PRISM_PORT }
$HealthUrl = "http://127.0.0.1:$Port/api/health"

function Title($text) { Write-Host ''; Write-Host $text -ForegroundColor Cyan; Write-Host ('-' * $text.Length) -ForegroundColor DarkCyan }
function Row($label, $value, $state) {
    $colour = @{ OK = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; NEED = 'Yellow' }[$state]
    Write-Host ('  {0,-22} {1,-46} ' -f $label, $value) -NoNewline
    Write-Host "[$state]" -ForegroundColor $colour
}
function Info($text) { Write-Host "  $text" }

function Update-SessionPath {
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
    $portableNode = Join-Path $Root '.tools\node'
    if (Test-Path (Join-Path $portableNode 'node.exe')) { $env:Path = "$portableNode;$env:Path" }
}

function Get-FileHashText($path) {
    if (-not (Test-Path $path)) { return '' }
    return (Get-FileHash -Algorithm SHA256 -Path $path).Hash
}

function Test-PrismHealth {
    try { Invoke-WebRequest -Uri $HealthUrl -UseBasicParsing -TimeoutSec 2 | Out-Null; return $true } catch { return $false }
}

function Open-Browser { if (-not $env:PRISM_NO_BROWSER) { Start-Process "http://localhost:$Port" } }

# Returns @{ Exe; Args; Version } for a working Python 3.11+, or $null.
# The Microsoft Store "python.exe" placeholder prints nothing, so it is skipped.
function Find-Python {
    $candidates = @()
    if (Get-Command py -ErrorAction SilentlyContinue) { $candidates += , @('py', @('-3.12')); $candidates += , @('py', @('-3')) }
    if (Get-Command python -ErrorAction SilentlyContinue) { $candidates += , @('python', @()) }
    $installed = @(Get-ChildItem "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe" -ErrorAction SilentlyContinue) +
                 @(Get-ChildItem "$env:ProgramFiles\Python3*\python.exe" -ErrorAction SilentlyContinue)
    foreach ($exe in ($installed | Sort-Object FullName -Descending)) { $candidates += , @($exe.FullName, @()) }
    foreach ($candidate in $candidates) {
        try {
            $out = & $candidate[0] @($candidate[1]) -c "import sys; print('%d.%d.%d' % sys.version_info[:3])" 2>$null
            if ($LASTEXITCODE -eq 0 -and $out) {
                $version = [version](($out | Select-Object -Last 1).Trim())
                if ($version -ge $MinPython) { return @{ Exe = $candidate[0]; Args = $candidate[1]; Version = $version } }
            }
        } catch { }
    }
    return $null
}

function Get-NodeVersion {
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) { return $null }
    try {
        $out = & node --version 2>$null
        if ($LASTEXITCODE -eq 0 -and $out) { return [version]($out.Trim().TrimStart('v')) }
    } catch { }
    return $null
}

function Test-Internet {
    try { Invoke-WebRequest -Uri 'https://www.python.org' -Method Head -UseBasicParsing -TimeoutSec 6 | Out-Null; return $true } catch { return $false }
}

# ------------------------------------------------------------ installers ----

function Install-Python {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Info 'Installing Python 3.12 with winget (Microsoft package manager)...'
        & winget install --exact --id Python.Python.3.12 --scope user --silent --accept-package-agreements --accept-source-agreements | Out-Host
        Update-SessionPath
        if (Find-Python) { return }
        Info 'winget did not finish; using the official python.org installer instead.'
    }
    $installer = Join-Path $env:TEMP "python-$PythonVersion-amd64.exe"
    Info "Downloading Python $PythonVersion from python.org..."
    Invoke-WebRequest -UseBasicParsing -OutFile $installer -Uri "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-amd64.exe"
    Info 'Installing Python for the current user...'
    $proc = Start-Process -FilePath $installer -Wait -PassThru -ArgumentList @('/passive', 'InstallAllUsers=0', 'PrependPath=1', 'Include_launcher=1', 'Include_test=0')
    if ($proc.ExitCode -ne 0) { throw "The Python installer failed (exit code $($proc.ExitCode))." }
    Update-SessionPath
}

function Install-PortableNode {
    Info 'Looking up the current Node.js LTS release on nodejs.org...'
    $releases = Invoke-RestMethod -Uri 'https://nodejs.org/dist/index.json' -UseBasicParsing
    $lts = $releases | Where-Object { $_.lts -and ($_.files -contains 'win-x64-zip') } | Select-Object -First 1
    if (-not $lts) { throw 'Could not find a Node.js LTS release to download.' }
    $name = "node-$($lts.version)-win-x64"
    $zip = Join-Path $env:TEMP "$name.zip"
    Info "Downloading Node.js $($lts.version) (portable, kept inside the PRISM folder)..."
    Invoke-WebRequest -UseBasicParsing -OutFile $zip -Uri "https://nodejs.org/dist/$($lts.version)/$name.zip"
    $tools = Join-Path $Root '.tools'
    $target = Join-Path $tools 'node'
    New-Item -ItemType Directory -Force -Path $tools | Out-Null
    if (Test-Path $target) { Remove-Item -Recurse -Force $target }
    Expand-Archive -Path $zip -DestinationPath $tools -Force
    Rename-Item -Path (Join-Path $tools $name) -NewName 'node'
    Remove-Item $zip -ErrorAction SilentlyContinue
    Update-SessionPath
}

# ------------------------------------------------------------------ main ----

Write-Host ''
Write-Host '  PRISM launcher' -ForegroundColor White
Write-Host '  From Alert Noise to One Attack Story' -ForegroundColor DarkGray
Update-SessionPath

if (Test-PrismHealth) {
    Info "PRISM is already running on http://localhost:$Port"
    Open-Browser
    exit 0
}

# --- 1. System check ---------------------------------------------------------
Title 'Step 1 of 3: checking this computer'
$hardFail = $false
$os = Get-CimInstance Win32_OperatingSystem
$build = [int]$os.BuildNumber
$osOk = $build -ge 10240
Row 'Windows' "$($os.Caption) (build $build)" $(if ($osOk) { 'OK' } else { 'FAIL' })
if (-not $osOk) { $hardFail = $true }

$is64 = [Environment]::Is64BitOperatingSystem
Row 'Architecture' $(if ($is64) { '64-bit' } else { '32-bit' }) $(if ($is64) { 'OK' } else { 'FAIL' })
if (-not $is64) { $hardFail = $true }

$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
Row 'Processor' ("{0} ({1} cores)" -f ($cpu.Name -replace '\s+', ' ').Trim(), $cpu.NumberOfCores) 'OK'

$ramGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
Row 'Memory (RAM)' "$ramGB GB (minimum $MinRamGB GB)" $(if ($ramGB -ge $MinRamGB) { 'OK' } else { 'WARN' })

$drive = (Get-Item $Root).PSDrive
$freeGB = [math]::Round($drive.Free / 1GB, 1)
$diskOk = $freeGB -ge $MinFreeGB
Row 'Free disk space' "$freeGB GB on drive $($drive.Name): (minimum $MinFreeGB GB)" $(if ($diskOk) { 'OK' } else { 'FAIL' })

$listening = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
$portOwner = $null
if ($listening) { $portOwner = (Get-Process -Id ($listening | Select-Object -First 1).OwningProcess -ErrorAction SilentlyContinue).ProcessName }
Row "Port $Port" $(if ($listening) { "in use by $portOwner" } else { 'free' }) $(if ($listening) { 'FAIL' } else { 'OK' })

if ($hardFail) { throw 'This computer does not meet the minimum requirements (64-bit Windows 10 or newer).' }

# --- 2. Software check (nothing is installed yet) -----------------------------
Title 'Step 2 of 3: checking what PRISM needs'
$plan = New-Object System.Collections.ArrayList

$python = Find-Python
if ($python) { Row 'Python 3.11+' "Python $($python.Version)" 'OK' }
else {
    Row 'Python 3.11+' 'not found' 'NEED'
    [void]$plan.Add(@{ Key = 'python'; Download = $true; Text = 'Python 3.12 (about 25 MB) from winget or python.org, installed for your user account only' })
}

$nodeVersion = Get-NodeVersion
if ($nodeVersion -and $nodeVersion -ge $MinNode) { Row 'Node.js 18+' "Node.js $nodeVersion" 'OK' }
else {
    Row 'Node.js 18+' $(if ($nodeVersion) { "Node.js $nodeVersion is too old" } else { 'not found' }) 'NEED'
    [void]$plan.Add(@{ Key = 'node'; Download = $true; Text = 'Node.js LTS (about 30 MB) from nodejs.org, unpacked into the PRISM folder (.tools\node)' })
}

$venvPython = Join-Path $Root '.venv\Scripts\python.exe'
$venvWorks = $false
if (Test-Path $venvPython) { try { & $venvPython -c "import sys" 2>$null; $venvWorks = ($LASTEXITCODE -eq 0) } catch { } }
$requirements = Join-Path $Root 'backend\requirements.txt'
$reqStamp = Join-Path $Root '.venv\prism-requirements.sha256'
$reqHash = Get-FileHashText $requirements
$packagesOk = $false
if ($venvWorks -and (Test-Path $reqStamp) -and ((Get-Content $reqStamp -Raw).Trim() -eq $reqHash)) {
    try { & $venvPython -c "import fastapi, uvicorn, networkx, pydantic_settings, multipart" 2>$null; $packagesOk = ($LASTEXITCODE -eq 0) } catch { }
}
if ($packagesOk) { Row 'Backend packages' 'installed' 'OK' }
else {
    Row 'Backend packages' $(if ($venvWorks) { 'missing or out of date' } else { 'not set up' }) 'NEED'
    [void]$plan.Add(@{ Key = 'backend'; Download = $true; Text = 'PRISM backend packages (about 40 MB) from pypi.org, into the PRISM folder (.venv)' })
}

$frontend = Join-Path $Root 'frontend'
$lockFile = Join-Path $frontend 'package-lock.json'
$modulesStamp = Join-Path $frontend 'node_modules\.prism-lock.sha256'
$lockHash = Get-FileHashText $lockFile
$modulesOk = (Test-Path $modulesStamp) -and ((Get-Content $modulesStamp -Raw).Trim() -eq $lockHash)
if ($modulesOk) { Row 'Dashboard packages' 'installed' 'OK' }
else {
    Row 'Dashboard packages' 'missing or out of date' 'NEED'
    [void]$plan.Add(@{ Key = 'frontend'; Download = $true; Text = 'Dashboard packages (about 100 MB) from npmjs.org, into the PRISM folder (frontend\node_modules)' })
}

$builtIndex = Join-Path $frontend 'dist\index.html'
$needsBuild = -not (Test-Path $builtIndex)
if (-not $needsBuild) {
    $builtAt = (Get-Item $builtIndex).LastWriteTime
    $sources = @(Get-ChildItem (Join-Path $frontend 'src') -Recurse -File) +
               @(Get-Item (Join-Path $frontend 'index.html'), (Join-Path $frontend 'package.json'), (Join-Path $frontend 'vite.config.ts') -ErrorAction SilentlyContinue)
    $needsBuild = [bool]($sources | Where-Object { $_.LastWriteTime -gt $builtAt } | Select-Object -First 1)
}
if (-not $needsBuild) { Row 'Dashboard build' 'up to date' 'OK' }
else {
    Row 'Dashboard build' 'needs building' 'NEED'
    [void]$plan.Add(@{ Key = 'build'; Download = $false; Text = 'Build the dashboard on this computer (no download)' })
}

if ($listening) { throw "Port $Port is already used by another program ($portOwner). Close it and run PRISM again." }

# --- 3. Ask, then install -----------------------------------------------------
if ($plan.Count -gt 0) {
    Title 'Step 3 of 3: setup needed'
    Info 'To run PRISM, the launcher needs to do the following:'
    $i = 1
    foreach ($item in $plan) { Info ("  {0}. {1}" -f $i, $item.Text); $i++ }
    Write-Host ''
    Info 'Nothing is installed system-wide, no administrator rights are needed,'
    Info 'and no security or antivirus settings are changed.'

    $needsDownload = [bool]($plan | Where-Object { $_.Download })
    if ($needsDownload) {
        if (-not (Test-Internet)) { throw 'An internet connection is needed for the first-time setup. Connect to the internet and run PRISM again.' }
        if (-not $diskOk) { throw "Not enough free disk space ($freeGB GB). Free up at least $MinFreeGB GB and run PRISM again." }
    }

    Write-Host ''
    if ($env:PRISM_ASSUME_YES) { $answer = 'Y'; Info 'Install now? [Y/N]: Y (PRISM_ASSUME_YES)' }
    else { $answer = Read-Host '  Do you allow the launcher to do this now? [Y/N]' }
    if ($answer -notmatch '^\s*(y|yes)\s*$') {
        Write-Host ''
        Info 'Nothing was installed. To set PRISM up yourself, follow "Manual setup" in README.md,'
        Info 'or run this launcher again and answer Y.'
        exit 2
    }

    foreach ($item in $plan) {
        Write-Host ''
        Write-Host "  > $($item.Text)" -ForegroundColor Cyan
        switch ($item.Key) {
            'python' {
                Install-Python
                $python = Find-Python
                if (-not $python) { throw 'Python could not be installed automatically. Install Python 3.12 from https://www.python.org/downloads/ and run PRISM again.' }
                Info "Python $($python.Version) is ready."
            }
            'node' {
                Install-PortableNode
                $nodeVersion = Get-NodeVersion
                if (-not $nodeVersion -or $nodeVersion -lt $MinNode) { throw 'Node.js could not be installed automatically. Install the LTS version from https://nodejs.org/ and run PRISM again.' }
                Info "Node.js $nodeVersion is ready."
            }
            'backend' {
                if (-not $venvWorks) {
                    # A missing venv, or one copied from another computer, is rebuilt.
                    if (Test-Path (Join-Path $Root '.venv')) { Remove-Item -Recurse -Force (Join-Path $Root '.venv') }
                    & $python.Exe @($python.Args) -m venv (Join-Path $Root '.venv')
                    if ($LASTEXITCODE -ne 0) { throw 'Could not create the Python environment.' }
                }
                & $venvPython -m pip install --disable-pip-version-check -q -r $requirements
                if ($LASTEXITCODE -ne 0) { throw 'Installing the backend packages failed. Check the internet connection and try again.' }
                Set-Content -Path $reqStamp -Value $reqHash -Encoding ascii
                Info 'Backend packages are ready.'
            }
            'frontend' {
                Push-Location $frontend
                try {
                    if (Test-Path $lockFile) { & npm ci --no-audit --no-fund --loglevel=error } else { & npm install --no-audit --no-fund --loglevel=error }
                    if ($LASTEXITCODE -ne 0) { throw 'Installing the dashboard packages failed. Check the internet connection and try again.' }
                } finally { Pop-Location }
                Set-Content -Path $modulesStamp -Value $lockHash -Encoding ascii
                Info 'Dashboard packages are ready.'
            }
            'build' {
                Push-Location $frontend
                try {
                    & npm run build --silent
                    if ($LASTEXITCODE -ne 0) { throw 'Building the dashboard failed.' }
                } finally { Pop-Location }
                Info 'Dashboard is built.'
            }
        }
    }
} else {
    Title 'Step 3 of 3: everything is already installed'
}

# --- Start PRISM --------------------------------------------------------------
Write-Host ''
Info 'Starting PRISM...'
$serverCommand = "title PRISM server - close this window to stop PRISM & `"$venvPython`" -m uvicorn app.main:app --app-dir backend --port $Port"
Start-Process -FilePath 'cmd.exe' -ArgumentList '/k', $serverCommand -WorkingDirectory $Root -WindowStyle Minimized

$deadline = (Get-Date).AddSeconds(90)
while (-not (Test-PrismHealth)) {
    if ((Get-Date) -gt $deadline) { throw 'PRISM did not start within 90 seconds. Open the minimised "PRISM server" window to see the error.' }
    Start-Sleep -Seconds 1
}
Write-Host "  PRISM is running on http://localhost:$Port" -ForegroundColor Green
Info 'To stop PRISM, close the minimised "PRISM server" window.'
Open-Browser
exit 0
