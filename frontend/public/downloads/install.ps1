# CyberShield Agent — Windows Installer v1.2
# Run as Administrator:
#   Right-click PowerShell -> "Run as Administrator"
#   cd to folder containing cybershield-agent.exe
#   .\install.ps1 -AgentToken "tok_..." -CustomerId "cust_..." -Domain "example.com"

param(
    [Parameter(Mandatory=$true)]  [string]$AgentToken,
    [Parameter(Mandatory=$true)]  [string]$CustomerId,
    [Parameter(Mandatory=$true)]  [string]$Domain,
    [Parameter(Mandatory=$false)] [string]$Lang         = "en",
    [Parameter(Mandatory=$false)] [string]$ApiUrl       = "https://cybershield-10-production.up.railway.app",
    [Parameter(Mandatory=$false)] [string]$SlackWebhook = ""
)

$ErrorActionPreference = "Stop"

$installDir  = "C:\ProgramData\CyberShield"
$binaryName  = "cybershield-agent.exe"
$configFile  = "$installDir\config.json"
$logDir      = "$installDir\logs"
$serviceName = "CyberShieldAgent"

Write-Host ""
Write-Host "====================================" -ForegroundColor Cyan
Write-Host "  CyberShield Agent Installer v1.2" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan
Write-Host ""

# ── Admin check ────────────────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
if (-not $isAdmin) {
    Write-Host "ERROR: Run as Administrator (right-click PowerShell -> Run as Administrator)" -ForegroundColor Red
    exit 1
}

# ── 1. Directories ─────────────────────────────────────────────────────────────
Write-Host "Step 1/5: Creating install directory..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
New-Item -ItemType Directory -Force -Path $logDir     | Out-Null
Write-Host "  OK: $installDir" -ForegroundColor Green

# ── 2. Copy binary ─────────────────────────────────────────────────────────────
Write-Host "Step 2/5: Installing binary..." -ForegroundColor Yellow
if (-not (Test-Path ".\$binaryName")) {
    Write-Host "ERROR: $binaryName not found in current folder." -ForegroundColor Red
    Write-Host "Download it from: https://digitalcybershield.com/install" -ForegroundColor Yellow
    exit 1
}
# Remove Zone.Identifier mark-of-the-web so Windows won't block execution
Unblock-File -Path ".\$binaryName" -ErrorAction SilentlyContinue
Copy-Item ".\$binaryName" "$installDir\$binaryName" -Force
Write-Host "  OK: Copied to $installDir\" -ForegroundColor Green

# ── 3. Write config.json (UTF-8 without BOM) ───────────────────────────────────
Write-Host "Step 3/5: Writing config..." -ForegroundColor Yellow
$configObj = [ordered]@{
    agent_token   = $AgentToken
    customer_id   = $CustomerId
    domain        = $Domain
    api_url       = $ApiUrl
    lang          = $Lang
    tier          = "free"
    slack_webhook = $SlackWebhook
    kakao_token   = ""
}
$jsonString = $configObj | ConvertTo-Json -Depth 3

# Write UTF-8 WITHOUT BOM — BOM causes Go's json.Decoder to fail
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($configFile, $jsonString, $utf8NoBom)

Write-Host "  OK: $configFile (UTF-8, no BOM)" -ForegroundColor Green

# ── 4. Register Windows Service ────────────────────────────────────────────────
Write-Host "Step 4/5: Registering Windows Service..." -ForegroundColor Yellow

# Remove existing service cleanly
$existingSvc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existingSvc) {
    Write-Host "  Removing existing service..."
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    & sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 3
    Write-Host "  Removed old service." -ForegroundColor Gray
}

# IMPORTANT: sc.exe requires space after = and the whole command on ONE LINE.
# Using backtick line-continuation breaks the binPath= argument parsing.
$binPathValue = "`"$installDir\$binaryName`" -config `"$configFile`""
& sc.exe create $serviceName binPath= $binPathValue start= auto DisplayName= "CyberShield Security Agent"
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: sc.exe create failed (exit code $LASTEXITCODE)" -ForegroundColor Red
    exit 1
}

& sc.exe description $serviceName "CyberShield real-time security monitoring — brute-force detection, port scanning, malicious IP alerts."
& sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/10000/restart/30000
& sc.exe config $serviceName type= own

Write-Host "  OK: Service registered (auto-start on boot)" -ForegroundColor Green

# ── 5. Start service ───────────────────────────────────────────────────────────
Write-Host "Step 5/5: Starting service..." -ForegroundColor Yellow
Start-Sleep -Milliseconds 500

try {
    Start-Service -Name $serviceName -ErrorAction Stop
} catch {
    Write-Host "  WARNING: Start-Service threw an error: $_" -ForegroundColor Yellow
    Write-Host "  Trying sc.exe start as fallback..." -ForegroundColor Yellow
    & sc.exe start $serviceName | Out-Null
    Start-Sleep -Seconds 3
}

# Wait up to 15 s for the service to reach Running state
$maxWait = 15
$elapsed = 0
$status  = $null
while ($elapsed -lt $maxWait) {
    Start-Sleep -Seconds 1
    $elapsed++
    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($null -ne $svc) {
        $status = $svc.Status
        if ($status -eq "Running") { break }
    }
}

if ($status -eq "Running") {
    Write-Host "  OK: Service is RUNNING" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "  WARNING: Service status = $status after ${maxWait}s" -ForegroundColor Yellow
    Write-Host "  This usually means the binary couldn't read config.json." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Diagnosis steps:" -ForegroundColor Cyan
    Write-Host "    1. Check log: Get-Content '$logDir\agent.log' -Tail 30"
    Write-Host "    2. Check Event Viewer: Windows Logs -> Application -> Source: CyberShieldAgent"
    Write-Host "    3. Test manually: & '$installDir\$binaryName' -config '$configFile'"
}

Write-Host ""
Write-Host "====================================" -ForegroundColor Cyan
Write-Host "  Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "  Domain   : $Domain"
Write-Host "  Customer : $CustomerId"
Write-Host "  Token    : $($AgentToken.Substring(0,[Math]::Min(12,$AgentToken.Length)))..."
Write-Host "  Logs     : $logDir\agent.log"
Write-Host ""
Write-Host "  Useful commands:"
Write-Host "    Status   : Get-Service CyberShieldAgent"
Write-Host "    Logs     : Get-Content '$logDir\agent.log' -Wait -Tail 50"
Write-Host "    Stop     : Stop-Service CyberShieldAgent"
Write-Host "    Uninstall: Stop-Service CyberShieldAgent; sc.exe delete CyberShieldAgent; Remove-Item '$installDir' -Recurse -Force"
Write-Host "====================================" -ForegroundColor Cyan
