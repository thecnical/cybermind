# Getting Started with CyberMind CLI

Welcome to CyberMind — the world's most powerful AI-driven offensive security CLI. This guide will get you from zero to your first vulnerability hunt in 5 minutes.

---

## Prerequisites

| Requirement | Details |
|---|---|
| OS | Linux (Kali recommended), Windows 10+, macOS 12+ |
| Internet | Required for AI backend communication |
| API Key | Free key from [cybermindcli.com](https://cybermindcli.com) |
| Disk Space | ~50 MB for binary + tool cache |
| RAM | 4 GB minimum (8 GB recommended for large scans) |

---

## Step 1: Get Your API Key

1. Visit [cybermindcli.com](https://cybermindcli.com)
2. Click **Sign Up** and create an account
3. Verify your email
4. Go to **Dashboard → API Keys**
5. Copy your key (format: `cp_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`)

---

## Step 2: Install CyberMind

### Linux / Kali (Recommended)

```bash
CYBERMIND_KEY=YOUR_KEY curl -sL https://cybermindcli.com/install.sh | bash
```

This installs to `/usr/local/bin/cybermind` and creates the config directory at `~/.cybermind/`.

### Windows (PowerShell as Admin)

```powershell
$env:CYBERMIND_KEY="YOUR_KEY"; (iwr https://cybermindcli.com/install.ps1 -UseBasicParsing).Content | iex
```

Adds `cybermind.exe` to your PATH.

### macOS

```bash
CYBERMIND_KEY=YOUR_KEY curl -sL https://cybermindcli.com/install-mac.sh | bash
```

---

## Step 3: Verify Installation

```bash
cybermind --version
# Expected: CyberMind CLI v6.0

cybermind --help
# Shows all available commands and modes
```

---

## Step 4: Your First Scan

### 4a. AI Security Chat (Interactive)

```bash
cybermind
```

This opens the TUI (Terminal User Interface). Type any security question:

```
You: How do I test for SQL injection?
CyberMind: [Detailed guide with exact sqlmap commands]
```

### 4b. Quick Recon

```bash
cybermind /recon example.com
```

Output includes:
- Subdomain enumeration commands
- Port scanning strategy
- Technology stack detection
- WAF detection
- OSINT sources

### 4c. Vulnerability Hunt (Pro+)

```bash
cybermind /hunt example.com
```

This runs a full vulnerability hunt and returns:
- Confirmed vulnerabilities with exploit commands
- XSS payloads
- Parameter exploitation guides
- Missing coverage analysis
- Bug bounty report draft

### 4d. Search and Rescue (SAR)

```bash
cybermind /sar example.com
```

Finds exposed data without exploiting:
- Credentials, API keys
- Sensitive data leaks
- Cloud misconfigurations
- Remediation steps

---

## Step 5: Understanding Output

Every mode returns structured output:

```json
{
  "success": true,
  "mode": "hunt",
  "analysis": "...AI-generated report...",
  "provider": "groq",
  "model": "llama-3.3-70b",
  "time": "2.4s",
  "target": "example.com",
  "stats": {
    "vulns_found": 3,
    "xss_found": 1,
    "params_found": 12,
    "tools_run": 8,
    "open_ports": 4
  }
}
```

---

## Step 6: Manual vs Auto Mode

### Auto Mode (Default)
```bash
cybermind /hunt target.com
```
Runs everything automatically. Best for speed.

### Manual Mode
```bash
cybermind /hunt target.com --manual
```

You control each step:
```
Step 1: Run subfinder
Command: subfinder -d target.com -silent
Execute? [y/n/skip]: y
[Output shown]

Step 2: Probe live URLs
Command: cat subdomains.txt | httpx -silent
Execute? [y/n/skip]: y
...
```

---

## Step 7: Configuration

### View Current Config
```bash
cybermind config --show
```

### Set API Key
```bash
cybermind config --key cp_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Set Backend URL (for self-hosted)
```bash
cybermind config --backend https://your-backend.com
```

### Enable Telegram Alerts
```bash
cybermind config --telegram-bot-token YOUR_BOT_TOKEN
cybermind config --telegram-chat-id YOUR_CHAT_ID
```

### Set Default Mode
```bash
cybermind config --default-mode deep
```

---

## Step 8: Upgrade Your Plan

| Plan | Command | What You Get |
|---|---|---|
| Free | Default | 20 req/day, core modes |
| Starter | `cybermind upgrade starter` | 50 req/day, Hunt + API + Chain |
| Pro | `cybermind upgrade pro` | 200 req/day, BizLogic + VibeHack + Bug-Detect |
| Elite | `cybermind upgrade elite` | Unlimited, All 22 modes + Abhimanyu + RedTeam |

---

## Next Steps

- Read [MODES.md](MODES.md) for detailed usage of every mode
- Read [API.md](API.md) for backend API integration
- Read [ARCHITECTURE.md](ARCHITECTURE.md) to understand how it works
- Join [Discord](https://discord.gg/cybermind) for community support

---

## Troubleshooting

### "Invalid API key"
- Check your key at [cybermindcli.com/dashboard](https://cybermindcli.com/dashboard)
- Run `cybermind config --key YOUR_KEY`

### "Rate limit exceeded"
- Free tier: 20 requests/day. Upgrade for more.
- Wait 60 seconds and try again.

### "Backend unreachable"
- Check internet connection
- Run `cybermind config --backend https://cybermind-backend.onrender.com`

### "Command not found" (after install)
- Linux/macOS: `source ~/.bashrc` or open a new terminal
- Windows: Restart PowerShell

---

## Quick Reference Card

```bash
# Core (Free)
cybermind                              # AI chat
cybermind /recon <target>              # Reconnaissance
cybermind /osint <target>              # OSINT
cybermind /scan <target>               # Network scan
cybermind /cve CVE-2024-1234           # CVE lookup

# Advanced (Pro+)
cybermind /hunt <target>               # Vuln hunt
cybermind /api <target>                # API security
cybermind /chain <target>              # Vuln chaining
cybermind /devsec <repo>               # Code security

# Elite
cybermind /abhimanyu <target>          # Exploitation
cybermind /red-team <company>          # Red team
cybermind /omega <target>              # All modes
cybermind /sar <target>                # Search & rescue

# Utility
cybermind report                       # Generate report
cybermind poc                          # Generate PoC
cybermind config --show                # View config
```
