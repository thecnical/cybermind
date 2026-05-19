# Installation Guide

Platform-specific installation instructions for CyberMind CLI v6.0.

---

## Table of Contents

- [System Requirements](#system-requirements)
- [Linux / Kali Linux](#linux--kali-linux)
- [Windows](#windows)
- [macOS](#macos)
- [Docker](#docker)
- [VSCode Extension](#vscode-extension)
- [Uninstallation](#uninstallation)
- [Troubleshooting](#troubleshooting)

---

## System Requirements

| Requirement | Minimum | Recommended |
|---|---|---|
| OS | Linux (Kali), Windows 10+, macOS 12+ | Latest version |
| RAM | 4 GB | 8 GB+ |
| Disk Space | 50 MB | 100 MB+ (with tool cache) |
| Internet | Required for backend | Stable connection |
| Shell | Bash/Zsh (Linux/macOS), PowerShell (Windows) | Latest version |

---

## Linux / Kali Linux

### One-Line Install

```bash
CYBERMIND_KEY=YOUR_KEY curl -sL https://cybermindcli.com/install.sh | bash
```

This installs to `/usr/local/bin/cybermind` and creates config at `~/.cybermind/`.

### Manual Install

```bash
# Download binary
curl -L -o cybermind https://cybermindcli.com/releases/latest/cybermind-linux-amd64
chmod +x cybermind
sudo mv cybermind /usr/local/bin/

# Configure
mkdir -p ~/.cybermind
echo "api_key: YOUR_KEY" > ~/.cybermind/config.yaml
```

### Install Required Tools (Kali)

```bash
# Recon tools
sudo apt update
sudo apt install -y nmap masscan subfinder amass httpx nuclei

# Hunt tools
sudo apt install -y sqlmap dalfox ffuf gobuster

# Exploitation tools
sudo apt install -y metasploit-framework
```

### Verify Install

```bash
cybermind --version
# Expected: CyberMind CLI v6.0

cybermind --help
# Shows all commands
```

---

## Windows

### One-Line Install (PowerShell as Administrator)

```powershell
$env:CYBERMIND_KEY="YOUR_KEY"; (iwr https://cybermindcli.com/install.ps1 -UseBasicParsing).Content | iex
```

### Manual Install

```powershell
# Download binary
Invoke-WebRequest -Uri "https://cybermindcli.com/releases/latest/cybermind-windows-amd64.exe" -OutFile "cybermind.exe"

# Add to PATH (optional)
$env:Path += ";$PWD\cybermind.exe"
# Or move to system location:
Move-Item cybermind.exe C:\Windows\System32\

# Configure
mkdir $env:USERPROFILE\.cybermind
"api_key: YOUR_KEY" | Out-File "$env:USERPROFILE\.cybermind\config.yaml"
```

### Install Required Tools (Windows)

```powershell
# Install Chocolatey (if not installed)
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install tools
choco install nmap -y
choco install python -y
pip install nuclei subfinder httpx
```

### Verify Install

```powershell
cybermind.exe --version
# Expected: CyberMind CLI v6.0
```

---

## macOS

### One-Line Install

```bash
CYBERMIND_KEY=YOUR_KEY curl -sL https://cybermindcli.com/install-mac.sh | bash
```

### Manual Install

```bash
# Download binary
curl -L -o cybermind https://cybermindcli.com/releases/latest/cybermind-darwin-amd64
chmod +x cybermind
sudo mv cybermind /usr/local/bin/

# Configure
mkdir -p ~/.cybermind
echo "api_key: YOUR_KEY" > ~/.cybermind/config.yaml
```

### Install Required Tools (macOS)

```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install tools
brew install nmap
brew install go
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### Verify Install

```bash
cybermind --version
# Expected: CyberMind CLI v6.0
```

---

## Docker

### Pull Image

```bash
docker pull cybermind/cli:latest
```

### Run Container

```bash
docker run -it --rm \
  -e CYBERMIND_KEY=YOUR_KEY \
  -v ~/.cybermind:/root/.cybermind \
  cybermind/cli:latest /bin/bash
```

### Run Direct Command

```bash
docker run --rm \
  -e CYBERMIND_KEY=YOUR_KEY \
  cybermind/cli:latest /recon example.com
```

---

## VSCode Extension

### Install from Marketplace

```bash
code --install-extension cybermind.cybermind-vscode
```

### Or Install from VSCode

1. Open VSCode
2. Go to Extensions (Ctrl+Shift+X)
3. Search "CyberMind"
4. Click Install

### Configure Extension

```json
{
  "cybermind.apiKey": "cp_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "cybermind.backendUrl": "https://cybermind-backend.onrender.com"
}
```

### Features

- Right-click URL → "CyberMind: Recon this target"
- Inline AI suggestions in code
- Bug bounty report generation
- Direct CLI integration in terminal

---

## Uninstallation

### Linux / macOS

```bash
# Remove binary
sudo rm /usr/local/bin/cybermind

# Remove config
rm -rf ~/.cybermind

# Remove from shell profile
# Edit ~/.bashrc or ~/.zshrc and remove any cybermind aliases
```

### Windows

```powershell
# Remove binary
Remove-Item C:\Windows\System32\cybermind.exe

# Remove config
Remove-Item $env:USERPROFILE\.cybermind -Recurse

# Remove from PATH
# Edit System Environment Variables and remove cybermind path
```

### Docker

```bash
docker rmi cybermind/cli:latest
```

---

## Troubleshooting

### "command not found: cybermind"

**Linux/macOS:**
```bash
# Reload shell
source ~/.bashrc
# Or open new terminal

# Check installation
which cybermind
# Should show: /usr/local/bin/cybermind
```

**Windows:**
```powershell
# Restart PowerShell
# Check PATH
$env:Path -split ';' | Select-String cybermind
```

### "Invalid API key"

```bash
# Verify key at https://cybermindcli.com/dashboard
cybermind config --key YOUR_KEY
```

### "Permission denied" (Linux)

```bash
# Fix permissions
sudo chmod +x /usr/local/bin/cybermind
```

### "Backend unreachable"

```bash
# Check internet connection
ping cybermindcli.com

# Set backend URL manually
cybermind config --backend https://cybermind-backend.onrender.com
```

### "Rate limit exceeded"

```bash
# Free tier: 20 requests/day
# Wait 60 seconds and try again
# Or upgrade: cybermind upgrade pro
```

### Windows PowerShell Execution Policy Error

```powershell
# Set execution policy (as Admin)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### macOS "cannot be opened because the developer cannot be verified"

```bash
# Allow app
xattr -cr /usr/local/bin/cybermind
```

---

## Next Steps

After installation, read [GETTING_STARTED.md](GETTING_STARTED.md) for your first scan.
