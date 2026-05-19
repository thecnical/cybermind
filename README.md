# CyberMind CLI v6.0

> **The world's most powerful AI-driven offensive security CLI.** 22 autonomous modes, manual & auto execution, OMEGA brain orchestration, SAR rescue mode, Web3/mobile/cloud exploitation, and real Kali tool integration. **Free tier available.**

[![Version](https://img.shields.io/badge/version-6.0-cyan)](https://cybermindcli.com)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-blue)](https://cybermindcli.com/install)
[![License](https://img.shields.io/badge/license-Proprietary-red)](https://cybermindcli.com/terms)
[![Free Tier](https://img.shields.io/badge/free%20tier-20%20req%2Fday-green)](https://cybermindcli.com)
[![Modes](https://img.shields.io/badge/modes-22-orange)](https://cybermindcli.com/docs/modes)

---

## Table of Contents

- [What is CyberMind](#what-is-cybermind)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [22 Offensive Security Modes](#22-offensive-security-modes)
- [OMEGA Brain Orchestrator](#omega-brain-orchestrator)
- [Manual vs Auto Mode](#manual-vs-auto-mode)
- [SAR — Search and Rescue](#sar--search-and-rescue)
- [Architecture](#architecture)
- [Plans & Pricing](#plans--pricing)
- [Documentation](#documentation)
- [License](#license)

---

## What is CyberMind

CyberMind is a commercial AI-powered offensive security CLI designed for:

- **Bug Bounty Hunters** — Automated recon, hunting, chaining, and report generation
- **Red Teamers** — Multi-phase adversary simulation with 7-day campaigns
- **Penetration Testers** — Deep exploitation with real tool execution
- **Security Researchers** — Web3, mobile, cloud, and AI/ML attack surface analysis
- **Developers** — DevSecOps integration and code security scanning

### What Makes CyberMind Different

| Feature | CyberMind v6.0 | Others |
|---|---|---|
| **22 Attack Modes** | ✅ Recon, Hunt, Abhimanyu, RedTeam, SAR, Omega, and 16 more | ❌ 3-5 modes max |
| **Manual + Auto Control** | ✅ Every mode supports step-by-step manual execution | ❌ Auto only |
| **Web3/Blockchain Attacks** | ✅ Smart contract, DeFi, NFT, wallet exploitation | ❌ Web only |
| **Mobile Exploitation** | ✅ iOS/Android deeplink, storage, SSL pinning bypass | ❌ Not supported |
| **Cloud Attacks** | ✅ AWS/Azure/GCP/K8s metadata, IAM, container escape | ❌ Limited |
| **AI/ML Security** | ✅ Prompt injection, model inversion, adversarial examples | ❌ None |
| **SAR Mode** | ✅ Rescue-focused: find exposed data, credentials, PII | ❌ None |
| **Windows Support** | ✅ Full native | ❌ Linux/Docker only |
| **VSCode Extension** | ✅ Integrated IDE experience | ❌ Not available |
| **Telegram Alerts** | ✅ Real-time bug notifications | ❌ Not available |

---

## Installation

### One-Line Install

**Linux / Kali Linux:**
```bash
CYBERMIND_KEY=YOUR_KEY curl -sL https://cybermindcli.com/install.sh | bash
```

**Windows (PowerShell — Admin):**
```powershell
$env:CYBERMIND_KEY="YOUR_KEY"; (iwr https://cybermindcli.com/install.ps1 -UseBasicParsing).Content | iex
```

**macOS:**
```bash
CYBERMIND_KEY=YOUR_KEY curl -sL https://cybermindcli.com/install-mac.sh | bash
```

Get your free API key at [cybermindcli.com](https://cybermindcli.com).

### Manual Install

```bash
# Download binary
curl -L -o cybermind https://cybermindcli.com/releases/latest/cybermind-linux-amd64
chmod +x cybermind
sudo mv cybermind /usr/local/bin/

# Configure
cybermind config --key YOUR_API_KEY
```

### VSCode Extension

```bash
# Install from VSCode marketplace
code --install-extension cybermind.cybermind-vscode
```

---

## Quick Start

```bash
# 1. AI Security Chat (default TUI)
cybermind

# 2. Quick recon on a target
cybermind /recon target.com

# 3. Full vulnerability hunt
cybermind /hunt target.com

# 4. Autonomous exploitation (Elite plan)
cybermind /abhimanyu target.com

# 5. OMEGA — full pipeline with brain orchestration
cybermind /plan target.com --mode deep

# 6. SAR — search and rescue (find exposed data)
cybermind /sar target.com

# 7. API security testing
cybermind /api target.com

# 8. Business logic bug hunting
cybermind /bizlogic target.com
```

---

## 22 Offensive Security Modes

### Core Modes (All Plans)

| Mode | Command | Description | Plan |
|---|---|---|---|
| **Chat** | `cybermind` | AI security assistant (TUI) | Free |
| **Recon** | `/recon <target>` | Passive + active reconnaissance (12+ types) | Free |
| **OSINT** | `/osint <target>` | Full open-source intelligence | Free |
| **Scan** | `/scan <target>` | Native network scanning | Free |
| **CVE** | `/cve CVE-XXXX-YYYY` | CVE intelligence & exploit guidance | Free |
| **Threat** | `/threat <ip>` | Threat intelligence lookup | Free |
| **Payload** | `/payload <os> <arch>` | AI payload generator | Free |
| **Anon** | `/anon <target>` | Zero-contact passive recon | Free |
| **Locate** | `/locate <target>` | Asset discovery & geolocation | Free |

### Advanced Modes (Pro+)

| Mode | Command | Description | Plan |
|---|---|---|---|
| **Hunt** | `/hunt <target>` | Active vulnerability hunting (40+ tools) | Pro |
| **API** | `/api <target>` | REST, GraphQL, gRPC, WebSocket, SOAP testing | Pro |
| **Chain** | `/chain <target>` | Vulnerability chaining & impact escalation | Pro |
| **DevSec** | `/devsec <repo>` | Developer security & code review | Pro |
| **BizLogic** | `/bizlogic <target>` | Business logic flaw hunting | Pro |
| **VibeHack** | `/vibe-hack <target>` | Autonomous vibe-coded hacking (SSE stream) | Pro |
| **Bug-Detect** | `/bug-detect <target>` | Automated bug detection & triage | Pro |
| **Pipeline** | `/pipeline <target>` | Automated tool pipeline orchestration | Pro |

### Elite Modes (Elite Plan)

| Mode | Command | Description | Plan |
|---|---|---|---|
| **Abhimanyu** | `/abhimanyu <target>` | Autonomous exploitation engine (manual + auto) | Elite |
| **RedTeam** | `/red-team <company>` | 7-phase adversary simulation | Elite |
| **Omega** | `/omega <target>` | Runs ALL 22 modes sequentially | Elite |
| **Manual-Hunt** | `/manual-hunt <target>` | Step-by-step user-guided hunting | Elite |
| **Manual-Abhi** | `/manual-abhimanyu <target>` | User-controlled exploit execution | Elite |
| **RevEng** | `/reveng <binary>` | Reverse engineering & binary analysis | Elite |
| **Storigar** | `/storigar <target>` | Intelligence narrative & threat stories | Elite |
| **Brain** | `/brain <target>` | Central AI orchestrator & mode delegation | Elite |

### Special Modes

| Mode | Command | Description |
|---|---|---|
| **SAR** | `/sar <target>` | Search and Rescue: recon → locate → osint → hunt (rescue-focused) |
| **Report** | `cybermind report` | Generate pentest/HackerOne-ready report |
| **PoC** | `cybermind poc` | Generate working proof-of-concept |

---

## OMEGA Brain Orchestrator

The OMEGA brain is the central AI that decides which modes to run, in what order, and with what parameters. It adapts to every target type automatically.

```bash
# Full OMEGA with brain orchestration
cybermind /plan target.com              # Auto-detects best modes
cybermind /plan target.com --mode quick # ~30 min scan
cybermind /plan target.com --mode deep  # ~4 hours full depth
cybermind /plan target.com --omega      # Run ALL modes sequentially
```

**How Brain Works:**

1. **Target Classification** — Crypto, Enterprise, Fintech, Mobile, Cloud, Web
2. **Tech Stack Detection** — WordPress, React, PHP, Node.js, Java, GraphQL, etc.
3. **WAF Detection** — Cloudflare, Akamai, AWS WAF, Imperva, F5
4. **Mode Selection** — Brain picks the optimal mode sequence for the target
5. **Smart Focus** — XSS for React, SQLi for PHP, SSRF for Node.js, etc.
6. **Chain Detection** — Identifies vulnerability chains (XSS→CSRF→ATO, SSRF→RCE)
7. **Adaptive Bypass** — Includes WAF-specific bypass strategies automatically

**Example Brain Decision Flow:**
```
Target: defi-protocol.com
  → Classified as: CRYPTO/WEB3
  → Tech: React + Node.js + GraphQL
  → WAF: Cloudflare detected
  → Brain decides: anon → osint → api → hunt(xss,idor,ssrf) → chain → poc
  → WAF bypass: sqlmap_tamper=space2comment,between,randomcase
```

---

## Manual vs Auto Mode

Every powerful mode supports **both** manual and automatic execution.

### Auto Mode (Default)
```bash
cybermind /abhimanyu target.com           # Full autonomous exploitation
cybermind /hunt target.com               # Full autonomous hunt
cybermind /recon target.com             # Full autonomous recon
```
AI decides everything. Commands execute automatically. Best for speed.

### Manual Mode
```bash
cybermind /abhimanyu target.com --manual   # One step at a time
cybermind /hunt target.com --manual        # User-guided hunt
cybermind /recon target.com --manual      # Step-by-step recon
```

**How Manual Mode Works:**
1. AI suggests the first step (tool + command)
2. You review and confirm (`y` / `n` / `skip`)
3. AI executes and shows output
4. AI suggests the next step based on results
5. Repeat until complete

**Use Manual Mode When:**
- You want to learn the methodology
- You need fine-grained control over sensitive targets
- You want to customize commands before execution
- You're testing in a restricted environment

---

## SAR — Search and Rescue

SAR mode is designed for **victim rescue**, not exploitation. It focuses on finding and securing exposed data.

```bash
cybermind /sar target.com
```

**SAR Pipeline:**
```
recon → locate → osint → hunt → report
```

**What SAR Finds:**
- Exposed credentials, API keys, tokens
- Sensitive data leaks (PII, SSN, health records)
- Open directories, .git, .env files
- Weak authentication, missing MFA
- Cloud storage misconfigurations (S3, Azure, GCP)
- Subdomain takeover candidates
- IDOR leaking other users' data

**SAR Output:**
- Remediation steps (not exploit commands)
- Risk-scored findings
- Responsible disclosure guidance

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CyberMind CLI v6.0                        │
│                     (Go Binary)                             │
├─────────────────────────────────────────────────────────────┤
│  TUI │ Commands │ Config │ History │ Reports               │
├─────────────────────────────────────────────────────────────┤
│  22 Modes │ Manual/Auto │ SAR │ Omega │ Brain               │
├─────────────────────────────────────────────────────────────┤
│              HTTP/JSON ↔ Backend API                        │
│         https://cybermind-backend.onrender.com              │
├─────────────────────────────────────────────────────────────┤
│                     Backend (Node.js)                       │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐           │
│  │  Recon  │ │  Hunt   │ │Abhimanyu│ │ RedTeam │           │
│  │  API    │ │ BizLogic│ │  Chain  │ │  Brain  │ ... 22 modes│
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘           │
│       └────────────┴────┬────┴────────────┘                │
│                    ┌────┴────┐                            │
│                    │ AI Router│                            │
│                    │Parallel  │                            │
│                    │Groq│Cerebras│OpenRouter│Gemini│...  │
│                    └─────────┘                            │
├─────────────────────────────────────────────────────────────┤
│                    Kali Tool Integration                     │
│  nmap │ sqlmap │ dalfox │ nuclei │ nuclei │ metasploit      │
│  subfinder │ amass │ httpx │ ffuf │ jwt_tool │ burp         │
└─────────────────────────────────────────────────────────────┘
```

### Components

| Component | Technology | Purpose |
|---|---|---|
| CLI | Go 1.21+ | Cross-platform binary |
| Backend | Node.js 18+ + Express | API routing, AI orchestration |
| AI Router | Parallel Promise.any() | Multi-provider AI with fallback |
| Database | Supabase PostgreSQL | Users, API keys, usage logs |
| Auth | API Key (per-user) | Plan enforcement, rate limiting |
| Agents | Node.js cron + Telegram | Bug monitoring, daily reports |

---

## Plans & Pricing

| Plan | Price | Requests/day | Modes |
|---|---|---|---|
| **Free** | ₹0 | 20 | Chat, Recon, OSINT, Scan, CVE, Threat, Payload, Anon, Locate |
| **Starter** | ₹299/mo | 50 | Free + Hunt, API, Chain, DevSec |
| **Pro** | ₹1,999/mo | 200 | Starter + BizLogic, VibeHack, Bug-Detect, Pipeline |
| **Elite** | ₹3,999/mo | Unlimited | All 22 modes + Abhimanyu, RedTeam, Omega, Manual modes |

**Payment:** UPI, Cards, Netbanking via PayU.

---

## Documentation

Full documentation is available in the `docs/` folder:

| Doc | Description |
|---|---|
| [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) | First steps, config, basic usage |
| [docs/MODES.md](docs/MODES.md) | Detailed usage for all 22 modes |
| [docs/API.md](docs/API.md) | Backend API endpoint reference |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design & data flow |
| [docs/INSTALLATION.md](docs/INSTALLATION.md) | Platform-specific installation |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Env vars, plans, API keys |
| [docs/SECURITY.md](docs/SECURITY.md) | Responsible disclosure, legal |
| [docs/FAQ.md](docs/FAQ.md) | Common questions & troubleshooting |

---

## VSCode Extension

```bash
code --install-extension cybermind.cybermind-vscode
```

Features:
- Right-click any URL → "CyberMind: Recon this target"
- Inline AI suggestions in code
- Bug bounty report generation
- Direct CLI integration in terminal

---

## Telegram Alerts

```bash
cybermind config --telegram-bot-token YOUR_BOT_TOKEN
cybermind config --telegram-chat-id YOUR_CHAT_ID
```

Get real-time notifications for:
- Critical vulnerabilities found
- Bug bounty targets updated
- Daily/weekly summary reports

---

## Related Tools

- [Aegis](https://github.com/thecnical/aegis) — Deep autonomous pentest engine
- [Phantom Strike](https://github.com/thecnical/phantom-strike) — Offensive security toolkit

---

## Support

- **Website:** [cybermindcli.com](https://cybermindcli.com)
- **Docs:** [cybermindcli.com/docs](https://cybermindcli.com/docs)
- **Discord:** [discord.gg/cybermind](https://discord.gg/cybermind)
- **Email:** support@cybermindcli.com

---

## License

**Proprietary — All rights reserved.**

For authorized security testing only. By using CyberMind, you agree to:
1. Only test targets you own or have explicit written permission to test
2. Follow responsible disclosure practices
3. Not use CyberMind for illegal, unethical, or malicious purposes

© 2026 Chandan Pandey ([github.com/thecnical](https://github.com/thecnical))
