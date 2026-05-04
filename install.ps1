# CyberMind CLI Installer for Windows (PowerShell)
# Usage: (iwr https://cybermindcli1.vercel.app/install.ps1 -UseBasicParsing).Content | iex
# Usage: $env:CYBERMIND_KEY="cp_live_xxx"; (iwr https://cybermindcli1.vercel.app/install.ps1 -UseBasicParsing).Content | iex

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$GITHUB_RAW = "https://raw.githubusercontent.com/thecnical/cybermind/main/cli"
$BINARY_URL = "$GITHUB_RAW/cybermind-windows-amd64.exe"
$INSTALL_DIR = "$env:LOCALAPPDATA\CyberMind"
$EXE_PATH = "$INSTALL_DIR\cybermind.exe"
$CBM_PATH = "$INSTALL_DIR\cbm.exe"

Write-Host ""
Write-Host " ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ███╗██╗███╗   ██╗██████╗" -ForegroundColor Cyan
Write-Host "⚡ CyberMind CLI Installer v5.4.6" -ForegroundColor Green
Write-Host ""

# Create install dir
if (-not (Test-Path $INSTALL_DIR)) {
    New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null
}

Write-Host "[*] Downloading CyberMind CLI from GitHub..." -ForegroundColor Yellow
$TMP = "$env:TEMP\cybermind-install.exe"

try {
    (New-Object System.Net.WebClient).DownloadFile($BINARY_URL, $TMP)
    $size = (Get-Item $TMP).Length
    if ($size -lt 1MB) { throw "Downloaded file too small ($size bytes)" }
    Copy-Item $TMP $EXE_PATH -Force
    Copy-Item $TMP $CBM_PATH -Force
    Remove-Item $TMP -Force
    Write-Host "[✓] Installed: $EXE_PATH" -ForegroundColor Green
} catch {
    Write-Host "[!] Binary download failed: $_" -ForegroundColor Red
    Write-Host "[!] Trying to build from source..." -ForegroundColor Yellow
    # Fallback: clone and build
    $SRC = "$env:TEMP\cybermind-src"
    git clone --depth=1 https://github.com/thecnical/cybermind.git $SRC 2>$null
    Push-Location "$SRC\cli"
    go mod tidy
    go build -ldflags="-X main.Version=5.4.6" -o $EXE_PATH .
    Copy-Item $EXE_PATH $CBM_PATH -Force
    Pop-Location
    Remove-Item $SRC -Recurse -Force
    Write-Host "[✓] Built and installed from source" -ForegroundColor Green
}

# Add to PATH
$currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($currentPath -notlike "*$INSTALL_DIR*") {
    [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$INSTALL_DIR", "User")
    $env:PATH += ";$INSTALL_DIR"
    Write-Host "[✓] Added to PATH: $INSTALL_DIR" -ForegroundColor Green
}

# Save API key
if ($env:CYBERMIND_KEY) {
    $cfgDir = "$env:USERPROFILE\.cybermind"
    if (-not (Test-Path $cfgDir)) { New-Item -ItemType Directory -Path $cfgDir -Force | Out-Null }
    '{"key":"' + $env:CYBERMIND_KEY + '"}' | Set-Content "$cfgDir\config.json"
    Write-Host "[✓] API key saved" -ForegroundColor Green
}

Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host "⚡ CyberMind CLI installed!" -ForegroundColor Green
Write-Host ""
Write-Host "  Verify:    cybermind --version" -ForegroundColor Cyan
Write-Host "  AI Chat:   cybermind" -ForegroundColor Cyan
Write-Host "  Doctor:    cybermind /doctor" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Restart your terminal for PATH changes to take effect." -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host ""
