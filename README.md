<div align="center">

<br/>

```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ███╗██╗███╗   ██╗██████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗ ████║██║████╗  ██║██╔══██╗
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔████╔██║██║██╔██╗ ██║██║  ██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╔╝██║██║██║╚██╗██║██║  ██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚═╝ ██║██║██║ ╚████║██████╔╝
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝
```

### ⚡ AI-Powered Offensive Security CLI — Recon + Hunt + AI Analysis

[![Version](https://img.shields.io/badge/version-2.4.1-00FFFF?style=for-the-badge)](https://github.com/thecnical/cybermind)
[![License](https://img.shields.io/badge/license-MIT-8A2BE2?style=for-the-badge)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-268BEE?style=for-the-badge&logo=kalilinux&logoColor=white)](#kali-linux--ubuntu-installation)
[![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)](#windows-installation)
[![Stars](https://img.shields.io/github/stars/thecnical/cybermind?style=for-the-badge&color=yellow)](https://github.com/thecnical/cybermind/stargazers)

[![Buy Me A Coffee](https://img.shields.io/badge/☕%20Buy%20Me%20A%20Coffee-chandanpandit-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/chandanpandit)

*Created by [Chandan Pandey](https://github.com/thecnical)*

**CyberMind is an open-source AI-powered offensive security CLI built for Kali Linux — featuring a fully automated 16-tool recon pipeline, a 6-phase vulnerability hunt engine, and deep AI analysis. Built for penetration testers, bug bounty hunters, and red teamers.**

</div>

---

## What is CyberMind?

CyberMind is a single Go binary that combines two things: a powerful automated attack pipeline and an AI cybersecurity assistant. On Kali Linux, it runs real tools — nmap, subfinder, nuclei, dalfox, katana, and more — then sends structured findings to AI for deep analysis. On Windows, it provides the full AI chat experience.

The tool is built around two core modes:

**`/recon`** — Maps the attack surface. Runs 16 tools across 6 phases: passive OSINT, subdomain enumeration, port scanning, HTTP fingerprinting, directory discovery, and vulnerability scanning. Each phase feeds its output into the next. Results are sent to AI as a structured payload — per-tool findings, open ports, WAF status, live URLs, technologies — and the AI returns a ranked attack surface analysis with exact exploitation commands.

**`/hunt`** — Finds vulnerabilities. Takes the recon output and goes deeper: collects historical URLs from Wayback Machine and AlienVault, deep-crawls with katana, discovers hidden parameters with x8, hunts XSS with dalfox, runs full nuclei template coverage, and runs nmap vuln scripts. Results are sent to AI which produces a bug bounty report with confirmed findings, PoCs, and CVSS scores.

The two modes chain automatically — after `/recon` completes, CyberMind prompts you to start `/hunt` using the recon context (live URLs, open ports, WAF status) so hunt tools run against confirmed live targets instead of guessing.

---

## Kali Linux / Ubuntu Installation

```bash
git clone https://github.com/thecnical/cybermind.git
cd cybermind
chmod +x install.sh && sudo ./install.sh
```

The install script builds the CLI, installs it to `/usr/local/bin`, and automatically installs all 23 recon + hunt tools. No manual setup needed.

After install, verify:

```bash
cybermind --version
cybermind /doctor    # check all tools are installed
```

---

## Windows Installation

Windows supports the full AI chat experience. `/recon` and `/hunt` require Kali Linux.

**Step 1** — Install [Go](https://go.dev/dl) and [Git](https://git-scm.com/download/win)

**Step 2** — Build:
```powershell
git clone https://github.com/thecnical/cybermind.git
cd cybermind\cli
go build -o cybermind.exe .
```

**Step 3** — Install globally (run as Administrator):
```powershell
Move-Item cybermind.exe C:\Windows\System32\cybermind.exe
```

---

## Auto Recon Mode — `/recon` 🐧 Kali Linux Only

Fully automated 16-tool recon pipeline across 6 phases. Each phase feeds its output into the next.

```bash
cybermind /recon example.com
cybermind /recon 192.168.1.1
cybermind /recon example.com --tools nmap,httpx,nuclei   # specific tools only
```

**Pipeline:**

| Phase | Tools | What it discovers |
|-------|-------|-------------------|
| 1 — Passive OSINT | whois, theHarvester, dig | Registration, emails, DNS records |
| 2 — Subdomain Enum | subfinder, amass, dnsx | Subdomains → live hosts |
| 3 — Port Scanning | rustscan → naabu → nmap (cascade), masscan | Open ports, services, WAF |
| 4 — HTTP Fingerprint | httpx, whatweb, tlsx | Live URLs, tech stack, TLS certs |
| 5 — Dir Discovery | ffuf → feroxbuster → gobuster (cascade) | Hidden endpoints, directories |
| 6 — Vuln Scanning | nuclei, nikto, katana | CVEs, misconfigs, crawled endpoints |

**Adaptive behavior:**
- Port 443/8443 found → tlsx auto-queued
- WAF detected → Phase 5 rate-limited to 10 req/s, nuclei excludes aggressive templates
- No open ports after Phase 3 → Phases 4/5/6 skipped
- IP target → domain-only tools skipped automatically

After recon completes, CyberMind prompts: **"Start Hunt Mode on these results? [y/N]"**

---

## Hunt Mode — `/hunt` 🐧 Kali Linux Only

6-phase vulnerability hunting pipeline. Chains directly from recon output or runs standalone.

```bash
cybermind /hunt example.com
cybermind /hunt example.com --tools dalfox,nuclei   # specific tools
```

**Pipeline:**

| Phase | Tool | What it does |
|-------|------|--------------|
| 1 — URL Collection | gau, waybackurls | Historical URLs from Wayback Machine + AlienVault |
| 2 — Deep Crawl | katana | JS endpoints, forms, API paths (depth 5) |
| 3 — Parameter Discovery | x8 | Hidden GET/POST parameters (IDOR/SSRF/LFI surface) |
| 4 — XSS Hunting | dalfox | Automated XSS with DOM verification |
| 5 — Vuln Scan | nuclei | Full template coverage (critical/high/medium/low) |
| 6 — Network Vulns | nmap | `--script vuln` on known open ports |

**Context chaining:**
- Phase 1 URLs → fed into dalfox (XSS) and nuclei (vuln scan)
- Phase 2 crawled URLs → merged with recon live URLs for deeper coverage
- Recon WAF status → dalfox adds delay, nuclei excludes aggressive templates
- Recon open ports → nmap scans only known ports (much faster)

**AI output:** Confirmed vulnerabilities with PoCs, XSS payloads, hidden parameter analysis, and a ready-to-submit bug bounty report template.

---

## Tool Management

```bash
cybermind /doctor          # check all 23 tools, auto-install missing ones
cybermind /install-tools   # install all recon + hunt tools
cybermind /tools           # quick status check
```

`/doctor` is the recommended first step — it shows exactly which tools are installed and automatically installs any that are missing.

---

## Updating

```bash
cybermind update
```

Pulls latest code, rebuilds binary, installs to `/usr/local/bin`, and auto-installs any new tools added in the update.

---

## AI Chat — All Platforms

```bash
cybermind                              # interactive chat
cybermind "how to exploit CVE-2021-44228"
cybermind scan 192.168.1.1 full
cybermind recon target.com osint
cybermind exploit CVE-2021-44228 10.0.0.1
cybermind payload windows x64
cybermind tool sqlmap "find SQLi in login form"
cybermind tool nmap "scan for SMB vulnerabilities"
cybermind history                      # view saved conversations
cybermind clear                        # wipe local history
```

**AI features:**
- Zero restrictions — all cybersecurity questions answered
- Adaptive skill detection (beginner → expert)
- Language detection — responds in Hindi/Urdu if you write in it
- 9 AI providers, 40+ models, parallel execution with auto-fallback
- No data collection, no accounts, no tracking

---

## Privacy

All conversations are stateless — the server processes and immediately forgets. Chat history is saved only on your machine at `~/.cybermind/history.json`. No logs, no accounts, no analytics.

```bash
torsocks cybermind "your question"     # route through Tor
proxychains cybermind /recon target    # use proxy chain
```

---

## Security

- Target validation: only `[a-zA-Z0-9.\-_:/\[\]]+` accepted — prevents tool flag injection
- No shell execution: all tools run via `exec.Command` with separate args — no shell injection possible
- Output sanitization: ANSI codes stripped, 6000 char cap per tool before AI submission

---

## License

MIT — see [LICENSE](LICENSE).

---

## Disclaimer

CyberMind is for authorized security research, penetration testing with written permission, CTF competitions, and cybersecurity education. Never use against systems you do not own or have explicit written authorization to test.

---

<div align="center">

Made with ⚡ by [Chandan Pandey](https://github.com/thecnical)

[GitHub](https://github.com/thecnical/cybermind) · [Buy Me A Coffee](https://buymeacoffee.com/chandanpandit)

</div>
