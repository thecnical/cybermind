# CyberMind Modes — Complete Reference

CyberMind v6.0 has **22 offensive security modes** across 4 categories: Core, Advanced, Elite, and Special. Every mode supports both **automatic** and **manual** execution.

---

## Mode Quick Reference

| Mode | Plan | Auto | Manual | Purpose |
|---|---|---|---|---|
| Chat | Free | Yes | Yes | AI security assistant |
| Recon | Free | Yes | Yes | Passive + active recon |
| OSINT | Free | Yes | Yes | Open-source intelligence |
| Scan | Free | Yes | Yes | Network scanning |
| CVE | Free | Yes | Yes | CVE intelligence |
| Threat | Free | Yes | Yes | Threat intel |
| Payload | Free | Yes | Yes | Payload generation |
| Anon | Free | Yes | No | Anonymous recon |
| Locate | Free | Yes | Yes | Asset discovery |
| Hunt | Pro | Yes | Yes | Vulnerability hunting |
| API | Pro | Yes | Yes | API security testing |
| Chain | Pro | Yes | Yes | Vulnerability chaining |
| DevSec | Pro | Yes | Yes | Code security |
| BizLogic | Pro | Yes | Yes | Business logic bugs |
| VibeHack | Pro | Yes | No | Vibe-coded hacking |
| Bug-Detect | Pro | Yes | No | Bug detection |
| Pipeline | Pro | Yes | No | Tool pipeline |
| Abhimanyu | Elite | Yes | Yes | Autonomous exploitation |
| RedTeam | Elite | Yes | Yes | Red team simulation |
| Omega | Elite | Yes | No | All modes sequential |
| RevEng | Elite | Yes | Yes | Reverse engineering |
| Storigar | Elite | Yes | Yes | Intelligence narrative |
| Brain | Elite | Yes | Yes | AI orchestrator |
| SAR | All | Yes | No | Search and rescue |

---

## Core Modes (Free Tier)

### Chat
```bash
cybermind
```
Interactive AI security assistant. Ask anything about:
- Vulnerability classes and exploitation
- Tool usage and command syntax
- Bug bounty methodology
- CVE analysis
- Network security concepts

**Example:**
```
You: How do I bypass Cloudflare WAF for SQL injection?
CyberMind: [Provides specific tamper scripts, headers, and techniques]
```

---

### Recon
```bash
cybermind /recon <target> [type]
```

**Types:** `passive`, `active`, `subdomain`, `osint`, `web`, `network`, `dns_active`, `asn_recon`, `cloud_recon`, `github_recon`, `js_recon`, `tech_fingerprint`, `network_fingerprint`, `js_analysis`, `cms_detect`, `incremental`, `monitor`, `html_report`, `tier1_recon`

**Example:**
```bash
cybermind /recon example.com passive       # No direct contact
cybermind /recon example.com subdomain   # Full subdomain enum
cybermind /recon example.com cloud_recon  # S3/Azure/GCP discovery
cybermind /recon example.com tier1_recon # Highest impact tools
```

**What it does:**
- Discovers subdomains (subfinder, amass, puredns, alterx)
- Maps attack surface (httpx, whatweb, wafw00f)
- Finds secrets in JS (jsluice, trufflehog, SecretFinder)
- Detects technology stack (wappalyzer, CMSeeK)
- Enumerates cloud assets (cloud_enum, S3Scanner)
- Maps ASN and IP ranges (asnmap, mapcidr)

---

### OSINT
```bash
cybermind /osint <target>
```

**What it does:**
- Email and employee enumeration (theHarvester, Hunter.io)
- Social media intelligence
- Leaked credential discovery (HaveIBeenPwned, DeHashed)
- GitHub dorking for secrets
- Pastebin and breach database searches
- Infrastructure mapping via Shodan/Censys

---

### Scan
```bash
cybermind /scan <target> [type]
```

**Types:** `quick`, `full`, `stealth`, `web`, `vuln`, `subdomain`, `network`, `ad`

**Example:**
```bash
cybermind /scan 192.168.1.1 full
cybermind /scan target.com web
```

---

### CVE
```bash
cybermind /cve CVE-2024-1234
```

Returns:
- CVE description and CVSS score
- Affected products and versions
- Public exploits and PoCs
- Mitigation steps
- Nuclei template availability

---

### Threat
```bash
cybermind /threat <ip|domain>
```

Returns:
- IP reputation (AbuseIPDB, VirusTotal)
- Associated malware/phishing campaigns
- Historical threat actor activity
- Related IOCs

---

### Payload
```bash
cybermind /payload <os> <arch> [options]
```

**Example:**
```bash
cybermind /payload windows x64 --lhost 10.0.0.1 --lport 4444
cybermind /payload linux amd64 --format elf
cybermind /payload android arm --stageless
```

Generates msfvenom-style payloads with AI-optimized options.

---

### Anon
```bash
cybermind /anon <target>
```

**Zero-contact passive reconnaissance.** No packets sent to target.

**Sources:**
- WHOIS, DNS records (public resolvers)
- Shodan, Censys (public queries)
- Certificate transparency logs (crt.sh)
- Archive.org, Wayback Machine
- GitHub public repos
- Social media (public profiles)

**Use when:** You need intel without alerting the target.

---

### Locate
```bash
cybermind /locate <target>
```

**Asset discovery and geolocation:**
- IP geolocation
- CDN detection
- Server location mapping
- Related infrastructure discovery
- Hosting provider identification

---

## Advanced Modes (Pro+)

### Hunt
```bash
cybermind /hunt <target> [--manual] [--sar]
```

**Full vulnerability hunting with 40+ tools.**

**What it finds:**
- XSS (dalfox, kxss, bxss)
- SQL Injection (sqlmap, ghauri)
- SSRF (nuclei, interactsh)
- LFI/RFI (ffuf, nuclei)
- RCE/SSTI (custom payloads)
- IDOR/BOLA (ffuf, nuclei)
- Business logic flaws
- WAF bypass opportunities

**SAR Mode:**
```bash
cybermind /hunt target.com --sar
```
Focuses on data exposure, credentials, PII. Provides remediation.

**Manual Mode:**
```bash
cybermind /hunt target.com --manual
```
One step at a time with user confirmation.

**Output includes:**
- Executive summary with risk score
- Confirmed vulnerabilities with exploit commands
- XSS payloads and PoCs
- Parameter exploitation guides
- Chain opportunities
- Bug bounty report draft with bounty estimates

---

### API
```bash
cybermind /api <target> [type]
```

**Types:** `rest`, `graphql`, `grpc`, `websocket`, `soap`, `all`

**What it tests:**
- **REST:** Authentication bypass, BOLA, mass assignment, rate limits
- **GraphQL:** Introspection, batching abuse, query depth DoS, field duplication
- **gRPC:** Method enumeration, proto fuzzing, metadata injection
- **WebSocket:** Message tampering, authentication bypass, XSS via WS
- **SOAP:** XXE, WS-Security bypass, XML injection

**Example:**
```bash
cybermind /api api.target.com graphql
cybermind /api target.com all
```

---

### Chain
```bash
cybermind /chain <target>
```

**Vulnerability chaining and impact escalation.**

**What it does:**
- Analyzes all found vulnerabilities
- Identifies chainable combinations
- Calculates CVSS uplift from chaining
- Provides step-by-step chain PoCs

**Example chains:**
- SSRF + Open Port 80 → SSRF→RCE (confidence 0.75)
- XSS + CSRF Token → XSS→Account Takeover (confidence 0.80)
- SQLi + Admin Panel → Full Compromise (confidence 0.85)
- IDOR + GraphQL Batching → Mass Data Exfiltration

**Output:**
```
Chain 1: SSRF + IDOR → PII Leak
[Step-by-step PoC]
CVSS uplift: +2.3
```

---

### DevSec
```bash
cybermind /devsec <github-url> | <findings-json>
```

**Developer security and code review.**

**What it analyzes:**
- Dependency vulnerabilities (CVE mapping)
- Secret leakage in code
- Insecure configurations
- Missing security headers
- Docker/container security
- CI/CD pipeline security

**Output:**
- Severity classification (Critical/High/Medium/Low)
- CVE mapping with CVSS scores
- Remediation steps with exact fix commands
- MITRE ATT&CK mapping
- Priority action list

---

### BizLogic
```bash
cybermind /bizlogic <target>
```

**Business logic vulnerability hunting.**

**What it finds:**
- Race conditions (price manipulation, double-spend)
- IDOR chains across multiple endpoints
- Workflow bypasses
- Authorization flaws
- Payment logic bugs
- Account takeover via logic flaws

**Output includes:**
- Attack matrix for each workflow
- Step-by-step exploitation
- Automation scripts (Python/Bash)
- Fix recommendations

---

### VibeHack
```bash
cybermind /vibe-hack <target>
```

**Autonomous vibe-coded hacking session.** Uses Server-Sent Events (SSE) for real-time streaming.

**What it does:**
- AI autonomously hacks the target
- Streams findings in real-time
- Adapts strategy based on discoveries
- Generates code on-the-fly

**Use when:** You want to observe AI creative hacking.

---

### Bug-Detect
```bash
cybermind /bug-detect <target>
```

**Automated bug detection and triage.**

Runs a fast automated scan and triages findings:
- False positive filtering
- Confidence scoring
- Severity ranking
- Quick win identification

---

### Pipeline
```bash
cybermind /pipeline <target> [--tools <list>]
```

**Automated tool pipeline orchestration.**

Chains multiple tools with automatic output passing:
```
subfinder → dnsx → httpx → nuclei → dalfox → sqlmap
```

**Custom pipelines:**
```bash
cybermind /pipeline target.com --tools "subfinder,httpx,nuclei"
```

---

## Elite Modes (Elite Plan)

### Abhimanyu
```bash
cybermind /abhimanyu <target> [--manual] [--vuln-type <type>]
```

**The autonomous exploitation engine.** Named after the warrior who fought inside the Chakravyuh.

**What it does:**
- Takes confirmed vulnerabilities
- Generates exact executable exploit commands
- Provides post-exploitation steps
- Suggests persistence mechanisms
- Generates reverse shells
- Recommends Metasploit modules

**Vuln types:** `all`, `sqli`, `xss`, `ssrf`, `lfi`, `rce`, `ssti`, `xxe`, `deserialization`, `jwt`, `oauth`, `race`, `prototype_pollution`, `graphql`, `business_logic`, `cloud`, `web3`, `mobile`, `ai_ml`

**Auto Mode:**
```bash
cybermind /abhimanyu target.com
```
Runs full exploitation autonomously.

**Manual Mode:**
```bash
cybermind /abhimanyu target.com --manual
```
```
Step 1: SQLi exploitation
Command: sqlmap -u "..." --batch --dump-all
Execute? [y/n]: y

Step 2: XSS exploitation
Command: dalfox url "..." --waf-bypass
Execute? [y/n]: y
...
```

**Knowledge base includes:**
- Web exploitation (SQLi, XSS, SSRF, LFI, RCE, XXE, SSTI)
- Advanced attacks (HTTP smuggling, cache poisoning, JWT attacks)
- Cloud attacks (AWS metadata, Azure tokens, K8s escape)
- Web3 attacks (reentrancy, flash loans, NFT approval abuse)
- Mobile attacks (deeplink hijacking, cert pinning bypass)
- AI/ML attacks (prompt injection, model inversion)
- WAF bypass for all major vendors

---

### RedTeam
```bash
cybermind /red-team <company> [--phase <1-7>]
```

**7-phase adversary simulation.**

**Phases:**
| Phase | Name | Focus |
|---|---|---|
| 1 | OSINT | LinkedIn, Shodan, Censys, theHarvester |
| 2 | Phishing | Pretext templates, lure documents |
| 3 | Exploitation | Credential stuffing, phishing simulation |
| 4 | Lateral Movement | BloodHound, AD analysis, privilege escalation |
| 5 | Deep Access | Additional escalation, persistence prep |
| 6 | Persistence | Scheduled tasks, registry, services |
| 7 | Report | Executive summary, timeline, remediation |

**Example:**
```bash
cybermind /red-team "Example Corp" --phase 1
cybermind /red-team "Example Corp" --phase 4
```

**Requires:** Elite plan + authorized scope definition.

---

### Omega
```bash
cybermind /omega <target>
```

**The ultimate mode.** Runs ALL 22 modes sequentially with maximum depth.

**Pipeline:**
```
anon → recon → osint → api → hunt → chain → abhimanyu → poc → report
```

**Estimated time:** 2-4 hours for full pipeline.

**Use when:** You want absolutely everything. Best for critical targets.

---

### Manual-Hunt
```bash
cybermind /manual-hunt <target>
```

**Step-by-step user-guided vulnerability hunting.**

AI guides you through the entire hunt methodology:
1. Recon strategy selection
2. Tool execution with explanations
3. Result interpretation
4. Next step recommendation
5. Confirmation before each action

**Best for:** Learning bug bounty methodology.

---

### Manual-Abhimanyu
```bash
cybermind /manual-abhimanyu <target>
```

**User-controlled exploit execution.**

AI generates exploit commands but YOU decide:
- Which vulnerabilities to exploit
- Which payloads to use
- When to stop
- How to pivot

**Best for:** Controlled penetration tests with client oversight.

---

### RevEng
```bash
cybermind /reveng <binary|file>
```

**Reverse engineering and binary analysis.**

**What it does:**
- Static analysis (strings, entropy, sections)
- Dynamic analysis suggestions
- Decompilation guidance (Ghidra, IDA, radare2)
- API hooking strategies
- Exploit development from binary

---

### Storigar
```bash
cybermind /storigar <target>
```

**Intelligence narrative and threat story building.**

Creates a comprehensive threat narrative:
- Target profile
- Attack surface story
- Likely threat actors
- Historical incidents
- Predictive risk assessment

**Output format:** Professional intelligence report.

---

### Brain
```bash
cybermind /brain <target> [--manual] [--sar] [--omega]
```

**Central AI orchestrator.**

The brain decides which modes to run and in what order. It understands all 22 modes.

**Options:**
- `--manual`: Brain suggests, you confirm each step
- `--sar`: Force SAR rescue pipeline
- `--omega`: Force Omega full pipeline

**Example:**
```bash
cybermind /brain defi-protocol.com
# Brain detects: crypto target → runs anon → osint → api → hunt → chain

cybermind /brain enterprise.com --sar
# Brain runs rescue-focused pipeline
```

---

## Special Modes

### SAR (Search and Rescue)
```bash
cybermind /sar <target>
```

**Rescue-focused pipeline.**

**Pipeline:** `recon → locate → osint → hunt → report`

**Focus:**
- Exposed credentials and API keys
- PII and sensitive data leaks
- Cloud misconfigurations
- Weak authentication
- Subdomain takeovers

**Output:** Remediation steps, not exploits.

**Use when:** You're helping secure a target, not attacking it.

---

### Report
```bash
cybermind report [--format <html|md|pdf>]
```

**Generate professional pentest report.**

**Formats:**
- HTML: Self-contained with CSS
- Markdown: GitHub-compatible
- PDF: Print-ready (via pandoc)

**Includes:**
- Executive summary
- Technical findings
- Risk ratings
- Remediation roadmap
- Timeline

---

### PoC
```bash
cybermind poc <vuln-id>
```

**Generate working proof-of-concept.**

Creates:
- Complete PoC script
- Step-by-step reproduction
- Impact demonstration
- HackerOne-ready submission draft

---

## Mode Selection Guide

**"I need to quickly understand a target"**
→ `/recon` (passive) or `/anon`

**"I want to find vulnerabilities"**
→ `/hunt` or `/manual-hunt`

**"I found vulns, now I need to exploit them"**
→ `/abhimanyu` or `/manual-abhimanyu`

**"I'm testing an API"**
→ `/api`

**"I need to simulate an attacker"**
→ `/red-team`

**"I want everything automated"**
→ `/omega`

**"I need to find exposed data"**
→ `/sar`

**"I'm reviewing code"**
→ `/devsec`

**"I need a professional report"**
→ `cybermind report`

**"I want AI to decide the best approach"**
→ `/brain`
