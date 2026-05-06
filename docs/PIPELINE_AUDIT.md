# Pipeline Audit (Omega, Recon, Hunt, Abhimanyu, Doctor, Help, Chat)

## Executive Verdict

The pipeline is **real but uneven**:
- real because commands are wired to actual tools and registries
- uneven because some tools are duplicated, some install hints are stale, and performance tuning is inconsistent

## Tool Coverage vs Real Bug Bounty Work

### Strong Coverage

- Recon: `subfinder`, `amass`, `dnsx`, `httpx`, `naabu`, `nmap`, `nuclei`
- URL/JS: `gau`, `waybackurls`, `katana`, `gospider`, `cariddi`, `subjs`
- Vuln hunt: `dalfox`, `arjun`, `paramspider`, `gf`, `ssrfmap`, `jwt_tool`
- Exploitation: `sqlmap`, `commix`, `hydra`, `searchsploit`, `msfconsole`
- OSINT/meta: `spiderfoot`, `recon-ng`, `reconftw`

### Gaps To Address Next (no implementation in this document)

- deterministic dedup of duplicate tool entries in registries
- stricter quality gate to block invalid/obsolete tool commands at compile time
- adaptive concurrency profiles per target size/WAF profile
- unified evidence model for repro artifacts and report output

## Mode-by-Mode Assessment

### Omega
- Good: planning-first model and phased orchestration
- Risk: install-method drift across Python/git/go tools

### Recon
- Good: broad attack-surface collection with modern ecosystem tools
- Risk: duplicated entries and mixed timeout quality

### Hunt
- Good: strong modern web vulns focus (XSS/SSRF/params/JS)
- Risk: very high resource defaults on some tools can create noisy runs

### Abhimanyu
- Good: wide exploit registry and post-exploit pathways
- Risk: includes advanced offensive modules that need stricter authorization guardrails

### Doctor + Help
- Good: doctor auto-heals dependencies and helps first-time users
- Risk: messaging should consistently distinguish Linux-only vs cross-platform

### CLI Chat (Linux/Windows/macOS)
- Good: available across platforms and useful for analysis workflows
- Risk: must keep clear boundary that heavy pipeline runs are Linux-first

## Speed Upgrade Plan (Requested, No Implementation Yet)

1. Add profile presets: `safe`, `fast`, `aggressive`
2. Introduce adaptive concurrency engine by tool category
3. Centralize crawl scheduler (multi-thread budget + retry queue)
4. Add result cache for passive sources and unchanged targets
5. Add distributed target queue for large program scopes
6. Add confidence scoring to reduce false positives before exploit stage

