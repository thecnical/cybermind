# FAQ — Frequently Asked Questions

Common questions and troubleshooting for CyberMind CLI v6.0.

---

## Installation

### Q: Installation failed on Linux

**A:** Check permissions and try again:
```bash
sudo curl -sL https://cybermindcli.com/install.sh | bash
```

### Q: "command not found: cybermind" after install

**A:** Reload your shell:
```bash
source ~/.bashrc
# Or open new terminal
```

### Q: Windows PowerShell execution policy error

**A:** Set execution policy:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Q: macOS "cannot be opened because the developer cannot be verified"

**A:** Allow the app:
```bash
xattr -cr /usr/local/bin/cybermind
```

---

## API Keys

### Q: How do I get an API key?

**A:** Visit [cybermindcli.com](https://cybermindcli.com), sign up, and go to Dashboard → API Keys.

### Q: "Invalid API key" error

**A:** Verify your key at the dashboard and set it again:
```bash
cybermind config --key YOUR_KEY
```

### Q: Can I share my API key?

**A:** No. Your API key is tied to your account and plan. Sharing violates ToS.

### Q: How do I rotate my API key?

**A:** Go to Dashboard → API Keys → Revoke old → Create new.

---

## Plans & Pricing

### Q: What's included in each plan?

**A:**
- **Free:** 20 req/day, core modes (Chat, Recon, OSINT, Scan, CVE, Threat, Payload, Anon, Locate)
- **Starter:** 50 req/day, + Hunt, API, Chain, DevSec
- **Pro:** 200 req/day, + BizLogic, VibeHack, Bug-Detect, Pipeline
- **Elite:** Unlimited, all 22 modes + Abhimanyu, RedTeam, Omega, Manual modes

### Q: Can I upgrade/downgrade?

**A:** Yes, anytime:
```bash
cybermind upgrade pro
cybermind upgrade free
```

### Q: What happens if I hit my limit?

**A:** You'll get a 429 error. Wait until tomorrow or upgrade your plan.

### Q: Do requests roll over?

**A:** No. Requests reset daily at midnight UTC.

---

## Modes

### Q: What's the difference between auto and manual mode?

**A:**
- **Auto:** AI decides everything, commands execute automatically
- **Manual:** AI suggests steps, you confirm each one

### Q: How do I use SAR mode?

**A:**
```bash
cybermind /sar target.com
```
SAR finds exposed data (credentials, PII, cloud misconfigs) without exploiting.

### Q: What does Omega mode do?

**A:** Omega runs ALL 22 modes sequentially with maximum depth. Takes 2-4 hours.
```bash
cybermind /omega target.com
```

### Q: Which mode should I use?

**A:**
- Quick intel → `/recon` or `/anon`
- Find vulnerabilities → `/hunt`
- Exploit vulns → `/abhimanyu`
- Test API → `/api`
- Full automation → `/omega`
- Rescue/secure → `/sar`

---

## Backend Issues

### Q: "Backend unreachable" error

**A:** Check internet connection and backend URL:
```bash
cybermind config --backend https://cybermind-backend.onrender.com
cybermind --health
```

### Q: Slow AI response

**A:** AI providers may be slow. Try again or check your internet connection.

### Q: "AI analysis failed" error

**A:** This is a temporary issue. Wait 30 seconds and try again.

---

## Tools

### Q: Do I need to install Kali tools?

**A:** For Linux (Kali), yes. For Windows/macOS, some tools work natively, others require WSL/VM.

### Q: Can I use CyberMind without installing tools?

**A:** Yes. CyberMind provides AI guidance. You can execute commands manually or on your own system.

### Q: How do I install required tools on Kali?

**A:**
```bash
sudo apt update
sudo apt install -y nmap masscan subfinder amass httpx nuclei sqlmap dalfox ffuf gobuster metasploit-framework
```

### Q: Tool not found error

**A:** Install the tool or add it to PATH:
```bash
cybermind config --tool-path /custom/path/to/tool
```

---

## Output & Reports

### Q: Where are reports saved?

**A:** `~/.cybermind/reports/` (Linux/macOS) or `%USERPROFILE%\.cybermind\reports\` (Windows).

### Q: How do I generate a PDF report?

**A:**
```bash
cybermind report --format pdf
```
Requires pandoc to be installed.

### Q: Can I export findings to JSON?

**A:** Yes, use the API directly or save CLI output to file:
```bash
cybermind /hunt target.com > findings.json
```

---

## Brain Orchestrator

### Q: How does the brain decide which mode to run?

**A:** The brain analyzes:
- Target type (crypto, enterprise, fintech, mobile, cloud, web)
- Technology stack (React, PHP, Node.js, etc.)
- WAF detection (Cloudflare, Akamai, etc.)
- Current pipeline state
- User preferences (manual, SAR, omega)

### Q: Can I override brain decisions?

**A:** Yes, use manual mode or specify mode directly:
```bash
cybermind /hunt target.com  # Skip brain
cybermind /brain target.com --manual  # Brain suggests, you confirm
```

### Q: What's the difference between `/brain` and `/omega`?

**A:**
- `/brain`: AI decides optimal mode sequence
- `/omega`: Runs ALL modes sequentially (no decision making)

---

## Telegram Alerts

### Q: How do I set up Telegram alerts?

**A:**
```bash
cybermind config --telegram-bot-token YOUR_BOT_TOKEN
cybermind config --telegram-chat-id YOUR_CHAT_ID
```

### Q: What triggers alerts?

**A:**
- Critical vulnerabilities found
- Bug bounty target updates
- Daily/weekly summary reports (if enabled)

### Q: How do I get my chat ID?

**A:** Message your bot, then visit:
```
https://api.telegram.org/bot<TOKEN>/getUpdates
```

---

## Troubleshooting

### Q: CyberMind crashes unexpectedly

**A:** Check logs:
```bash
cat ~/.cybermind/logs/error.log
```
Report to support@cybermindcli.com with logs.

### Q: Commands hang forever

**A:** Ctrl+C to cancel. Check internet connection. Try with timeout:
```bash
cybermind config --timeout 60
```

### Q: Strange AI output / hallucinations

**A:** AI can sometimes produce incorrect output. Verify commands before execution, especially in manual mode. Report persistent issues.

### Q: Rate limit exceeded

**A:** Wait 60 seconds. Free tier: 20 req/day. Upgrade for more.

---

## Privacy

### Q: Does CyberMind log my scans?

**A:** No. We log:
- API usage (endpoint, timestamp, status)
- Error logs (no sensitive data)
We do NOT log tool output, targets, or findings.

### Q: Is my data encrypted?

**A:** API keys are SHA-256 hashed. Database uses encryption at rest (Supabase).

### Q: Can I delete my data?

**A:** Email support@cybermindcli.com to request data deletion.

---

## Support

### Q: How do I get help?

**A:**
- **Email:** support@cybermindcli.com
- **Discord:** [discord.gg/cybermind](https://discord.gg/cybermind)
- **Docs:** [cybermindcli.com/docs](https://cybermindcli.com/docs)

### Q: How do I report a bug?

**A:** Email bugs@cybermindcli.com with:
- CyberMind version (`cybermind --version`)
- OS and version
- Steps to reproduce
- Error logs

### Q: How do I request a feature?

**A:** Email features@cybermindcli.com or post in Discord.

---

## Still Need Help?

Join our [Discord community](https://discord.gg/cybermind) for real-time support from the team and other users.
