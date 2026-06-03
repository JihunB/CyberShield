# CyberShield Agent — Windows Installer
# Run as Administrator in PowerShell:
#   Right-click PowerShell → "Run as Administrator"
#   cd to the folder containing cybershield-agent.exe and this script
#   .\install.ps1 -AgentToken "tok_abc" -CustomerId "cust_xyz" -Domain "example.com"
#
# What this script does:
#   1. Copies the agent exe to C:\ProgramData\CyberShield\
#   2. Writes config.json with your credentials
#   3. Registers a Windows Service (runs as SYSTEM, starts on boot)
#   4. Starts the service immediately
#
# To uninstall:
#   Stop-Service CyberShieldAgent
#   sc.exe delete CyberShieldAgent
#   Remove-Item "C:\ProgramData\CyberShield" -Recurse

param(
    [Parameter(Mandatory=$true)]  [string]$AgentToken,
    [Parameter(Mandatory=$true)]  [string]$CustomerId,
    [Parameter(Mandatory=$true)]  [string]$Domain,
    [Parameter(Mandatory=$false)] [string]$Lang         = "en",
    [Parameter(Mandatory=$false)] [string]$ApiUrl       = "https://cybershield-api.up.railway.app",
    [Parameter(Mandatory=$false)] [string]$SlackWebhook = ""
)

$ErrorActionPreference = "Stop"

$installDir = "C:\ProgramData\CyberShield"
$binaryName = "cybershield-agent.exe"
$configFile = "$installDir\config.json"
$logDir     = "$installDir\logs"
$serviceName = "CyberShieldAgent"

Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "  CyberShield Agent Windows Installer"    -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

# ── Check admin ───────────────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
if (-not $isAdmin) {
    Write-Error "Please run this script as Administrator."
    exit 1
}

# ── 1. Create directories ─────────────────────────────────────────────────────
Write-Host "▶ Creating directories" -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
New-Item -ItemType Directory -Force -Path $logDir     | Out-Null

# Restrict config dir to SYSTEM + Administrators only
$acl = Get-Acl $installDir
$acl.SetAccessRuleProtection($true, $false)
$adminRule  = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","Allow")
$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","Allow")
$acl.AddAccessRule($adminRule); $acl.AddAccessRule($systemRule)
Set-Acl $installDir $acl
Write-Host "  ✓ Directories created with restricted permissions"

# ── 2. Copy binary ────────────────────────────────────────────────────────────
Write-Host "▶ Installing agent binary" -ForegroundColor Yellow
if (-not (Test-Path ".\$binaryName")) {
    Write-Error "$binaryName not found. Download from https://cybershield.io/downloads/windows"
}
Copy-Item ".\$binaryName" "$installDir\$binaryName" -Force
Write-Host "  ✓ Binary copied to $installDir"

# ── 3. Write config.json ──────────────────────────────────────────────────────
Write-Host "▶ Writing configuration" -ForegroundColor Yellow
$config = @{
    agent_token   = $AgentToken
    customer_id   = $CustomerId
    domain        = $Domain
    api_url       = $ApiUrl
    lang          = $Lang
    tier          = "free"
    slack_webhook = $SlackWebhook
    kakao_token   = ""
} | ConvertTo-Json -Depth 3

$config | Set-Content -Path $configFile -Encoding UTF8

# Restrict config file to SYSTEM + Administrators only
$aclConfig = Get-Acl $configFile
$aclConfig.SetAccessRuleProtection($true, $false)
$aclConfig.AddAccessRule($adminRule); $aclConfig.AddAccessRule($systemRule)
Set-Acl $configFile $aclConfig
Write-Host "  ✓ Config written to $configFile (restricted)"

# ── 4. Register Windows Service ───────────────────────────────────────────────
# Windows Services are the equivalent of launchd on macOS.
# NSSM (Non-Sucking Service Manager) wraps any exe as a proper Windows Service.
# Here we use sc.exe (built-in) for simplicity.
# The service runs as LocalSystem (highest privilege — needed to read Event Log).
Write-Host "▶ Registering Windows Service" -ForegroundColor Yellow

# Remove existing service if present
$existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existingService) {
    Stop-Service  -Name $serviceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 2
}

$binPath = "`"$installDir\$binaryName`" -config `"$configFile`""
sc.exe create $serviceName `
    binPath= $binPath `
    start= auto `
    DisplayName= "CyberShield Security Agent" | Out-Null

sc.exe description $serviceName "CyberShield real-time security monitoring agent for SMBs." | Out-Null

# Configure service recovery: restart on failure (3 attempts)
sc.exe failure $serviceName reset= 3600 actions= restart/30000/restart/60000/restart/120000 | Out-Null

Write-Host "  ✓ Windows Service registered (auto-start on boot)"

# ── 5. Start service ──────────────────────────────────────────────────────────
Write-Host "▶ Starting service" -ForegroundColor Yellow
Start-Service -Name $serviceName
Start-Sleep -Seconds 3

$svc = Get-Service -Name $serviceName
if ($svc.Status -eq "Running") {
    Write-Host "  ✓ Service is running" -ForegroundColor Green
} else {
    Write-Warning "  ⚠ Service status: $($svc.Status) — check Event Viewer → Windows Logs → Application"
}

Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "  Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "  Domain monitored:  $Domain"
Write-Host "  Agent token:       $($AgentToken.Substring(0, [Math]::Min(12, $AgentToken.Length)))..."
Write-Host "  Log directory:     $logDir"
Write-Host ""
Write-Host "  Commands:"
Write-Host "    Check status:  Get-Service CyberShieldAgent"
Write-Host "    View logs:     Get-Content '$logDir\agent.log' -Wait -Tail 50"
Write-Host "    Stop:          Stop-Service CyberShieldAgent"
Write-Host "    Uninstall:     Stop-Service CyberShieldAgent; sc.exe delete CyberShieldAgent"
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
