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

### ⚡ AI-Powered Offensive Security CLI — Plan + Recon + Hunt + Exploit

[![Version](https://img.shields.io/badge/version-2.5.2-00FFFF?style=for-the-badge)](https://github.com/thecnical/cybermind)
[![License](https://img.shields.io/badge/license-MIT-8A2BE2?style=for-the-badge)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-268BEE?style=for-the-badge&logo=kalilinux&logoColor=white)](#kali-linux--ubuntu-installation)
[![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)](#windows-installation)
[![Stars](https://img.shields.io/github/stars/thecnical/cybermind?style=for-the-badge&color=yellow)](https://github.com/thecnical/cybermind/stargazers)

[![Buy Me A Coffee](https://img.shields.io/badge/☕%20Buy%20Me%20A%20Coffee-chandanpandit-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/chandanpandit)

*Created by [Chandan Pandey](https://github.com/thecnical)*

**CyberMind is an open-source AI-powered offensive security CLI built for Kali Linux — featuring OMEGA Planning Mode (AI-first attack planning), a fully automated 20-tool recon pipeline, an 11-tool vulnerability hunt engine, and a full 6-phase Abhimanyu exploit mode. Built for penetration testers, bug bounty hunters, and red teamers.**

</div>

---

## 🆕 What's New in v2.5.2

### ⚡ OMEGA Planning Mode — AI builds your attack plan first

```bash
cybermind /plan target.com
```

The most intelligent entry point on Linux. Instead of running tools blindly, `/plan` collects passive intelligence first — DNS, Shodan, HTTP headers, tech stack — then sends everything to AI. The AI returns a deep **9-phase attack plan** with exact tool flags tailored to your target.

**9 phases:**
1. Passive OSINT (whois, theHarvester, dig)
2. Subdomain Enumeration (reconftw, subfinder, amass, dnsx)
3. Port Scanning (rustscan → nmap → naabu → masscan)
4. HTTP Fingerprinting (httpx, whatweb, tlsx, wafw00f)
5. Directory Discovery (ffuf, feroxbuster, gobuster)
6. Vulnerability Scanning (nuclei 500 threads, nikto, katana)
7. Hunt Mode (waymore, gau, gospider, x8, arjun, dalfox, kxss, ssrfmap, tplmap)
8. Secret Hunting (trufflehog, secretfinder, subjs, mantra, cariddi)
9. Exploitation (sqlmap, commix, wpscan, hydra, metasploit, jwt_tool, graphw00f)

**WAF-aware:** Cloudflare, Akamai, Imperva bypass strategies built in automatically.
**Target-specific:** WordPress gets wpscan, GraphQL gets graphw00f, JWT gets jwt_tool.

### 🤖 New Free AI Providers
- **GitHub Models:** GPT-4o, Llama 3.3 70B, DeepSeek R1, Phi-4 — 150 req/day free
- **Cloudflare Workers AI:** Llama 70B, DeepSeek R1, Qwen 72B — 10,000 neurons/day free
- Total: **11 providers, 50+ models** in the fallback chain

### 🔄 Cold Start Auto-Wake
CLI now automatically wakes the backend and retries — no more manual resend needed.

---

## What is CyberMind?

CyberMind is a single Go binary that combines two things: a powerful automated attack pipeline and an AI cybersecurity assistant. On Kali Linux, it runs real tools — nmap, subfinder, nuclei, dalfox, katana, reconftw, and more — then sends structured findings to AI for deep analysis. On Windows, it provides the full AI chat experience.

**Key principle: Tool Exhaustion.** Each tool runs its most powerful command first. If it returns empty output, CyberMind automatically tries fallback commands. Only after ALL command variants are exhausted does it move to the next tool. No shortcuts. No skipping.

---

## Complete Linux Workflow (Recommended Order)

```bash
# 1. Install
curl -sL https://cybermindcli1.vercel.app/install.sh | bash

# 2. Save API key
cybermind --key cp_live_xxxxx

# 3. Install all tools (one time)
cybermind /install-tools

# 4. OMEGA Planning Mode — AI builds your attack plan
cybermind /plan target.com

# 5. Deep recon (if manual control needed)
cybermind /recon target.com

# 6. Vulnerability hunt
cybermind /hunt target.com

# 7. Exploit confirmed vulnerabilities (Elite plan)
cybermind /abhimanyu target.com

# 8. Generate pentest report
cybermind report
```

---

## Kali Linux / Ubuntu Installation

```bash
git clone https://github.com/thecnical/cybermind.git
cd cybermind
chmod +x install.sh && sudo ./install.sh
```

The install script builds the CLI, installs it to `/usr/local/bin`, and automatically installs all 21 recon + hunt tools including reconftw.

After install, verify:

```bash
cybermind --version
cybermind /doctor    # check all tools, auto-install missing ones
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

Fully automated 20-tool recon pipeline across 6 phases. Each phase feeds its output into the next. Tools auto-update before running.

```bash
cybermind /recon example.com
cybermind /recon 192.168.1.1
cybermind /recon example.com --tools nmap,httpx,nuclei   # specific tools only
```

**Pipeline:**

| Phase | Tools | What it discovers |
|-------|-------|-------------------|
| 1 — Passive OSINT | whois, theHarvester, dig | Registration, emails, DNS records, SPF chains |
| 2 — Subdomain Enum | subfinder, amass, **reconftw**, dnsx | Subdomains → live hosts (passive+active+brute+permutations) |
| 3 — Port Scanning | rustscan → naabu → nmap (cascade), masscan | Open ports, services, OS, WAF detection |
| 4 — HTTP Fingerprint | httpx, whatweb, tlsx | Live URLs, tech stack, TLS/JA3 certs, CSP |
| 5 — Dir Discovery | ffuf → feroxbuster → gobuster (cascade) | Hidden endpoints, API paths, backup files |
| 6 — Vuln Scanning | katana, nuclei, nikto | CVEs, misconfigs, XSS, SQLi, SSRF, exposures |

After recon completes, CyberMind prompts: **"Start Hunt Mode on these results? [y/N]"**

---

## Hunt Mode — `/hunt` 🐧 Kali Linux Only

11-tool vulnerability hunting pipeline across 6 phases. Chains directly from recon output or runs standalone. Tools auto-update before running.

```bash
cybermind /hunt example.com
cybermind /hunt example.com --tools dalfox,nuclei   # specific tools
```

**Pipeline:**

| Phase | Tools | What it does |
|-------|-------|--------------|
| 1 — URL Collection | waymore, gau, waybackurls | Historical URLs from Wayback + OTX + CommonCrawl + URLScan |
| 2 — Deep Crawl | gospider, katana | JS endpoints, forms, API paths (depth 10, 500 concurrency) |
| 3 — Parameter Discovery | paramspider, arjun, x8 | Hidden GET/POST parameters (IDOR/SSRF/LFI/XSS surface) |
| 4 — XSS Hunting | xsstrike, dalfox | AI-powered WAF bypass XSS + DOM verification |
| 5 — Vuln Scan | gf, nuclei | Pattern filtering + full template coverage (all severities) |
| 6 — Network Vulns | nmap | `--script vuln,exploit,auth,ssl-heartbleed,smb-vuln*` |

After hunt completes, CyberMind prompts: **"Start ABHIMANYU MODE? [y/N]"**

---

## Abhimanyu Mode — `/abhimanyu` ⚔️ 🐧 Kali Linux Only

Full 6-phase exploit engine. Named after Abhimanyu from Mahabharata — enters the Chakravyuh, fights every layer. Auto-chains from hunt results or runs standalone.

**Linux only.** Does not run on Windows or macOS.

```bash
cybermind /abhimanyu example.com           # full exploit (all phases)
cybermind /abhimanyu example.com sqli      # SQLi only
cybermind /abhimanyu example.com rce       # RCE/CMDi only
cybermind /abhimanyu example.com auth      # Auth brute force
cybermind /abhimanyu example.com postexploit  # Post-exploitation
cybermind /abhimanyu example.com lateral   # Lateral movement
cybermind /abhimanyu example.com exfil     # Exfiltration
```

**Pipeline:**

| Phase | Tools | What it does |
|-------|-------|--------------|
| 1 — Web Exploitation | sqlmap, commix, wpscan, nikto | SQLi dump, RCE/CMDi, WordPress enum, web vulns |
| 2 — Auth Attacks | hydra, john, hashcat | Brute force SSH/FTP/SMB/RDP, crack hashes (NTLM, MD5) |
| 3 — CVE/Exploit Search | searchsploit, msfconsole | Known exploits for detected services, Metasploit db_nmap |
| 4 — Post-Exploitation | linpeas, pspy, bloodhound-python | PrivEsc enum, process monitoring, AD graph collection |
| 5 — Lateral Movement | crackmapexec, evil-winrm, impacket-secretsdump | SMB shares, WinRM access, NTLM hash dump |
| 6 — Persistence + Exfil | curl, iodine | Exfil channel test, DNS tunneling |

**Session persistence:** Results saved to `/tmp/cybermind_abhimanyu_<target>/session.json`. Next run automatically loads previous findings and continues from where it left off.

**Persistence mechanisms generated:**
- crontab reverse shell
- systemd service backdoor
- rc.local persistence
- SSH authorized_keys injection

**Reverse shells generated:**
- bash, python3, php, nc_mkfifo, socat, powershell
- msfvenom payloads (linux/windows/php)

**Auto-chain:** `/recon` → `/hunt` → `/abhimanyu` — fully autonomous pipeline.

---

CyberMind integrates [reconftw](https://github.com/six2dez/reconftw) as a Phase 2 meta-tool. reconftw runs its own full subdomain pipeline internally — passive OSINT, active brute-force, permutations, certificate transparency, analytics, DNS records — catching everything that subfinder and amass might miss.

reconftw is automatically installed by `/install-tools`. To install manually:

```bash
git clone https://github.com/six2dez/reconftw.git /opt/reconftw
cd /opt/reconftw && ./install.sh
sudo ln -sf /opt/reconftw/reconftw.sh /usr/local/bin/reconftw
```

---

## Tool Management

```bash
cybermind /doctor          # check all 44 tools (recon+hunt+abhimanyu), auto-install missing
cybermind /install-tools   # install all recon + hunt tools (including reconftw)
cybermind /tools           # quick tool status check
```

`/doctor` checks all 44 tools across 3 modes and auto-installs any that are missing. It also runs automatically after `cybermind update`.

---

## Updating

```bash
cybermind update
```

Pulls latest code, rebuilds binary, installs to `/usr/local/bin`, then automatically runs `/doctor` to install any new tools and fix any missing ones.

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
- Uncensored models tried first (dolphin-uncensored, hermes-405b, deepseek-chat)
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
- Output sanitization: ANSI codes stripped, 50000 char cap per tool before AI submission
- Tool exhaustion: primary command → fallbacks → give up (never skips silently)

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
