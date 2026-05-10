# CyberMind CLI v5.5.0

> AI-powered offensive security CLI with 16-agent parallel attack pipeline, autonomous OMEGA planning, and real tool execution on Kali Linux.

[![Version](https://img.shields.io/badge/version-5.5.0-cyan)](https://cybermindcli.com)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-blue)](https://cybermindcli.com/install)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## What Makes CyberMind Different

| Feature | CyberMind | PentAGI | Darkmoon |
|---|---|---|---|
| **16 Parallel Agents** | ✅ Real execution | ✅ Docker-based | ❌ |
| **Windows Support** | ✅ Full | ❌ Linux only | ❌ Web only |
| **Bug Bounty Focus** | ✅ HackerOne/Bugcrowd | ❌ | ❌ |
| **Free Tier** | ✅ 20 req/day | ✅ Self-host | ❌ Enterprise |
| **One-command Install** | ✅ | ❌ Docker needed | ❌ |
| **Knowledge Graph** | ✅ Cross-target intel | ✅ | ❌ |
| **Long-term Memory** | ✅ Per-target | ✅ pgvector | ❌ |
| **VSCode Extension** | ✅ | ❌ | ❌ |
| **Telegram Alerts** | ✅ | ❌ | ❌ |

## Install

**Linux/Kali:**
```bash
CYBERMIND_KEY=YOUR_KEY curl -sL https://cybermindcli.com/install.sh | bash
```

**Windows (PowerShell):**
```powershell
$env:CYBERMIND_KEY="YOUR_KEY"; (iwr https://cybermindcli.com/install.ps1 -UseBasicParsing).Content | iex
```

**macOS:**
```bash
CYBERMIND_KEY=YOUR_KEY curl -sL https://cybermindcli.com/install-mac.sh | bash
```

Get your free API key at [cybermindcli.com](https://cybermindcli.com)

## OMEGA — 16-Agent Parallel Attack Pipeline

```bash
cybermind /plan target.com              # Full OMEGA: 16 agents in parallel
cybermind /plan target.com --mode quick # Quick scan (~30 min)
cybermind /plan target.com --mode deep  # Deep scan (~4 hours)
```

**16 Specialist Agents:**

| Phase | Agent | Tools |
|---|---|---|
| Recon | Passive OSINT | whois, dig, theHarvester, asnmap |
| Recon | Subdomain Enum | subfinder, amass, puredns, dnsx, alterx |
| Recon | Port Scan | naabu, nmap, masscan |
| Recon | HTTP Fingerprint | httpx, whatweb, wafw00f, gowitness |
| Recon | JS Intelligence | jsluice, katana, gau |
| Recon | Secret Scanner | trufflehog, gitleaks, nuclei |
| Hunt | XSS Hunter | dalfox, kxss, bxss |
| Hunt | SQLi Agent | sqlmap, ghauri |
| Hunt | SSRF Agent | nuclei, interactsh |
| Hunt | Nuclei Templates | nuclei (9000+ templates) |
| Hunt | OAuth/JWT | jwt_tool, nuclei |
| Hunt | Business Logic | ffuf, custom HTTP tests |
| Hunt | WAF Bypass | sqlmap tampers, dalfox bypass |
| Exploit | Cloud Misconfig | cloud_enum, pacu, nuclei |
| Exploit | HTTP Smuggling | nuclei, smuggler |
| Exploit | Exploit Verify | searchsploit, nuclei, msfconsole |

## All Commands

```bash
# OMEGA (Linux)
cybermind /plan <target>              # 16-agent autonomous pipeline
cybermind /recon <target>             # 30+ tool recon chain
cybermind /hunt <target>              # 40+ tool vuln hunt
cybermind /abhimanyu <target>         # Exploit engine
cybermind /chain <target>             # Vuln chain analysis + real execution
cybermind /vibe-hack <target>         # Autonomous AI hacking session (SSE)
cybermind /red-team <company>         # 7-day red team campaign
cybermind /bizlogic <target>          # Business logic bug hunter

# Cross-platform (Windows/macOS/Linux)
cybermind                             # AI security chat (TUI)
cybermind /scan <target>              # Native network scan
cybermind /osint <target>             # DNS + Shodan OSINT
cybermind /cve CVE-2024-1234          # CVE intelligence
cybermind /threat <ip|domain>         # Threat intel
cybermind /payload windows x64        # AI payload generator
cybermind /devsec <github-url>        # Code security scanner
cybermind report                      # Generate pentest report
```

## Architecture

```
OMEGA Brain
├── 16 Specialist Agents (parallel goroutines)
├── Knowledge Graph (cross-target intel)
├── Long-term Memory (per-target JSON)
├── Reasoning Engine (confidence-scored branches)
└── AI Synthesis (findings → report)
```

## Plans

| Plan | Price | Requests/day |
|---|---|---|
| Free | ₹0 | 20 |
| Starter | ₹299/mo | 50 |
| Pro | ₹1,999/mo | 200 |
| Elite | ₹3,999/mo | Unlimited |

[Get started →](https://cybermindcli.com)

## Related Tools

- [Aegis](https://github.com/thecnical/aegis) — Deep autonomous pentest engine
- [Phantom Strike](https://github.com/thecnical/phantom-strike) — Offensive security toolkit

## License

MIT — For authorized security testing only.
