# Changelog

All notable changes to CyberMind are documented here.

## [4.6.0] - 2026-04-27

### Added — reconFTW Full Integration
- **Mode-aware reconFTW execution**: quick (`-s`), deep (`-r --parallel`), overnight (`-a --deep --parallel`)
- **14 subdomain file types parsed**: passive, brute, permutations, cert transparency, NOERROR, vhosts, takeover candidates
- **18 vulnerability file types parsed**: XSS, SQLi, SSRF, LFI, SSTI, CRLF, smuggling, cache poisoning, IDOR, XXE, RCE, takeover
- **11 live URL file types parsed**: webs, katana, waymore, gau, urlfinder, gospider, hakrawler
- **Tech stack extraction** from reconFTW httpx output → fed into agentic brain
- **WAF detection** from reconFTW wafw00f output → adaptive rate limiting
- **Secrets/API key extraction** from reconFTW (trufflehog, gitleaks, mantra, JSA)
- **Email OSINT** from reconFTW (emailfinder, theHarvester, h8mail)
- **Subdomain takeover candidates** auto-flagged from reconFTW output
- **Cloud bucket exposure** detection (S3Scanner + cloud_enum output parsed)
- **JavaScript file URLs** extracted from reconFTW (subjs, JSA, mantra)
- `ReadReconFTWSummary()` — human-readable summary of all reconFTW findings
- `ReadReconFTWTechStack()`, `ReadReconFTWWAF()`, `ReadReconFTWSecrets()`, `ReadReconFTWEmails()` — dedicated parsers
- `ReadReconFTWTakeoverCandidates()`, `ReadReconFTWCloudBuckets()`, `ReadReconFTWJSFiles()`, `ReadReconFTWOpenPorts()` — new parsers
- `reconFTWOutDirs()` + `readReconFTWFile()` — shared helpers eliminating code duplication
- `ReconContext` enriched with `ReconFTWDone`, `ReconFTWSecrets`, `ReconFTWEmails`, `ReconFTWTakeover`, `ReconFTWBuckets`, `ReconFTWJSFiles`, `ReconFTWVulns`
- Brain memory: `RecordReconFTWFindings()` — records reconFTW findings for smarter future scans
- Brain memory: `GetReconFTWRecommendation()` — recommends optimal reconFTW mode based on history
- reconFTW config override file written before each run (maximizes output coverage)
- reconFTW auto-updates on re-install (`git pull` on existing install)
- Overnight mode timeout increased to 43200s (12h) to match reconFTW `-a --deep` runtime
- DNS resolvers list auto-downloaded for puredns/shuffledns (used inside reconFTW)

### Changed
- `reconftw` registry entry: timeout 21600→43200, mode-aware BuildArgs, 4 fallback variants
- `extractSubdomains()`: uses `result.Target` directly instead of parsing stdout for target
- `extractLiveURLs()`: uses `result.Target` directly for reconFTW file reading
- `GetModeSettings(ModeOvernight)`: MaxToolTimeout 21600→43200
- install.sh: reconFTW install now updates existing installs + validates wrapper script
- Version: 4.5.0 → 4.6.0

## [2.3.0] - 2026-04-06

### Added
- Full recon engine rewrite: 16 tools across 6 phases (whois, theHarvester, dig, subfinder, amass, dnsx, rustscan, naabu, nmap, masscan, httpx, whatweb, tlsx, ffuf, feroxbuster, gobuster, nuclei, nikto, katana)
- `ReconContext` struct — chained phase execution (each phase feeds the next)
- Cascade groups: `portscan` (rustscan → naabu → nmap) and `dirfuzz` (ffuf → feroxbuster → gobuster)
- Adaptive runtime decisions: auto-queue tlsx on port 443/8443, skip phases 4/5/6 if no open ports, WAF-adaptive rate limiting
- `WordlistResolver` — searches 5 candidate paths for seclists/dirb wordlists
- `ToolStatus` progress events with `StatusRunning/Done/Failed/Partial/Skipped/Timeout`
- `--tools` flag: `cybermind /recon <target> --tools nmap,httpx,nuclei`
- `/install-tools` command: installs all 12 apt + 7 Go recon tools in one shot
- `printReconSummary`: per-tool status table after recon completes
- `utils/markdown.go`: `StripMarkdown` — converts AI markdown to clean terminal text
- Structured `ReconPayload` sent to AI backend (per-tool findings map, open ports, WAF status, subdomains, live URLs, technologies)
- `install.sh` now prompts to install recon tools after CLI install
- Property-based tests: sanitize (Property 14), phase ordering (Property 11), result completeness (Property 9), StripMarkdown idempotency/length/markers (Properties 6/7/8)

### Changed
- `RunAutoRecon` signature: `(target string, requested []string, progress func(ToolStatus)) ReconResult`
- `SendAnalysis` now accepts `ReconPayload` struct instead of flat strings
- `sanitize()` uses regexp-based ANSI stripping instead of byte-by-byte
- `targetType()` uses `net.ParseIP` instead of manual dot-counting
- AI response passed through `StripMarkdown` before printing

### Backend (v3.1.0 → v3.2.0)
- `/analyze` endpoint handles structured `ReconPayload` with rich per-tool findings
- AI prompt produces structured plain-text report (SUMMARY/ATTACK SURFACE/CRITICAL FINDINGS/NEXT STEPS)
- `systemPrompt.js` updated with all 16 new tools and 6-phase pipeline knowledge
- `/recon` fallback updated to explain `/install-tools` and per-phase install commands

## [2.0.0] - 2026-04-01

### Added
- Full Kali Linux command mode: `scan`, `recon`, `exploit`, `payload`, `tool`
- 5 new backend routes: `/scan`, `/recon`, `/exploit`, `/tools`
- 9 AI providers: Groq, Cerebras, ai.cc, SambaNova, Mistral, NVIDIA, OpenRouter, HuggingFace, Bytez
- 25+ AI models with parallel execution and auto-fallback
- Massively upgraded system prompt with 100+ Kali Linux tools
- Identity override — always responds as CyberMind
- Production-ready project structure

## [1.0.0] - 2026-03-15

### Added
- Initial Go CLI with Bubble Tea interactive UI
- Node.js + Express backend
- Multi-provider AI router with fallback
- API key rotation (round-robin)
- Rate limiting (20 req/min per IP)
- Local chat history (~/.cybermind/history.json)
- Phase 1–8 implementation
