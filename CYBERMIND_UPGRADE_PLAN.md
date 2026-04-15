# CyberMind — Full Upgrade & Fix Plan
**Date:** April 16, 2026  
**Version:** 4.0.0 → 4.1.0  
**Status:** In Progress

---

## Executive Summary

CyberMind has world-class tool coverage (120+ tools across 6 phases) but suffers from 5 critical architectural flaws that make it behave like a "dumb tool runner" instead of a true autonomous security agent. This document details every issue found, root cause analysis, and the exact fixes applied.

---

## Issues Found

### Issue 1 — Generic Plans for Every Target (CRITICAL)

**Problem:**  
`/plan` and `/scan` generate the same generic attack plan regardless of the target. A WordPress blog gets the same plan as a GraphQL API or a Kubernetes cluster.

**Root Cause:**  
`runOmegaPlan()` in `commands.go` calls `api.SendPlan(planReq)` which sends target intel to the AI, but the AI prompt is not instructing it to select tools based on tech stack. The `DisplayPlan()` function in `omega/plan.go` just renders whatever the AI returns — no local tool selection logic exists.

**What Should Happen:**
- WordPress detected → wpscan, xmlrpc brute, wp-scan nuclei templates
- GraphQL detected → graphw00f, graphql-cop, introspection attacks
- Node.js/Express → prototype pollution, JWT attacks, SSRF via redirects
- IIS/ASP.NET → SharpHound, .NET deserialization, ViewState attacks
- Cloudflare WAF → stealth mode, rate limiting, WAF bypass payloads
- Open port 22 → SSH brute, key enumeration
- Open port 3306 → MySQL brute, UDF injection

**Fix Applied:**  
Added `SelectToolsByIntel()` function in `omega/plan.go` that maps detected tech/ports/WAF to specific tool sets. The agentic loop now passes this tool selection to recon/hunt/abhimanyu phases.

---

### Issue 2 — Abhimanyu Mode Never Consulted (CRITICAL)

**Problem:**  
`/plan` runs recon → hunt → analysis but **never calls Abhimanyu**. The exploit engine with 50+ tools (sqlmap, commix, wpscan, hydra, linpeas, bloodhound, etc.) is completely bypassed in the agentic loop.

**Root Cause:**  
In `runAgenticOmega()`, the `case "exploit":` branch exists and calls `runAbhimanyuFromHunt()` — but the AI brain (`api.SendAgentDecision()`) and the pre-planned steps (`api.SendPlanSteps()`) never return `action: "exploit"` because the planning prompt doesn't include Abhimanyu as a valid action.

The local fallback `localAgentDecision()` also never returns `"exploit"` — it only returns `"recon"`, `"hunt"`, `"poc"`, or `"done"`.

**Fix Applied:**  
1. `localAgentDecision()` now returns `"exploit"` when hunt is done and bugs are found
2. Added explicit Abhimanyu consultation after hunt phase when vulnerabilities are confirmed
3. Added `shouldRunAbhimanyu()` helper that checks hunt findings for exploitable vulns

---

### Issue 3 — Agentic Brain Behaves Like a Binary Script (CRITICAL)

**Problem:**  
The "agentic" loop is actually just: recon → hunt → poc → done. It never:
- Adapts tool selection based on what was found
- Switches strategies when tools fail
- Prioritizes high-value endpoints
- Runs targeted follow-up scans
- Decides to go deeper on specific findings

**Root Cause:**  
`localAgentDecision()` is a simple state machine with 4 states. The AI-driven path (`api.SendAgentDecision()`) works but falls back to the dumb local logic when AI is unavailable or slow.

**Fix Applied:**  
Rewrote `localAgentDecision()` to be a proper decision engine:
- Checks for specific vuln types found and selects targeted follow-up
- Runs Abhimanyu with specific vuln focus (sqli, xss, rce) based on findings
- Adds a "deep_hunt" action for second-pass scanning with different tools
- Implements early exit when critical bugs are found in quick mode

---

### Issue 4 — Deep Scanning Not Happening (HIGH)

**Problem:**  
- nmap scans only top 1000 ports (misses services on non-standard ports)
- nuclei runs with generic tags (misses tech-specific templates)
- Directory discovery uses generic wordlists (misses target-specific paths)
- No full-port scan option
- No service version detection on found ports

**Root Cause:**  
`recon/registry.go` has nmap configured as `-T4 --top-ports 1000`. The hunt registry has nuclei with generic severity tags but no tech-specific template selection.

**Fix Applied:**  
1. Added `CYBERMIND_DEEP_SCAN=true` env var support — enables full 65535 port scan
2. nmap now runs `-sV` (service version detection) by default
3. nuclei now selects templates based on detected tech stack (WordPress → wordpress/, GraphQL → graphql/, etc.)
4. Added tech-aware directory wordlist selection (WordPress → wp-content paths, API → api-endpoints wordlist)

---

### Issue 5 — No Cross-Phase Intelligence Passing (HIGH)

**Problem:**  
Each phase runs in isolation. Recon finds WordPress but hunt doesn't run wpscan. Hunt finds SQLi params but Abhimanyu doesn't target them with sqlmap. Recon finds port 22 open but nobody runs SSH brute force.

**Root Cause:**  
`HuntContext` is populated from `ReconContext` but the tool selection in `hunt/registry.go` doesn't use `ctx.Technologies` to filter or prioritize tools. Tools run the same regardless of what recon found.

**Fix Applied:**  
1. Added `TechAwareToolFilter()` in `hunt/engine.go` — skips irrelevant tools based on tech stack
2. WordPress detected → wpscan runs first, graphw00f skipped
3. GraphQL detected → graphw00f runs first, wpscan skipped
4. No JS framework → subjs/mantra deprioritized
5. Abhimanyu now receives specific vuln targets from hunt (SQLi params → sqlmap, XSS URLs → dalfox deep mode)

---

### Issue 6 — Full Stack Integration Missing (MEDIUM)

**Problem:**  
The web frontend (`cybermind-web`) and backend (`cybermind-backend`) don't reflect the CLI's actual capabilities. The scan results from CLI aren't surfaced in the web UI. The web UI's "scan" button doesn't trigger the full agentic pipeline.

**Root Cause:**  
The web stack is a separate Next.js app that calls the backend API. The CLI's agentic loop results are saved to local files but not pushed to the backend/web.

**Fix Applied:**  
Added result streaming to backend — when CLI runs in `--web` mode, it POSTs scan results to the backend API in real-time so the web UI can display live progress.

---

## Architecture After Fixes

```
cybermind /plan target.com
         │
         ▼
  ┌─────────────────────────────────────────────────────────┐
  │  STEP 1: GatherTargetIntel()                            │
  │  DNS + HTTP headers + Shodan + TXT/NS/MX records        │
  │  → Detects: WordPress, Cloudflare, PHP, MySQL           │
  └──────────────────────┬──────────────────────────────────┘
                         │
                         ▼
  ┌─────────────────────────────────────────────────────────┐
  │  STEP 2: SelectToolsByIntel() [NEW]                     │
  │  WordPress → wpscan, xmlrpc, wp-nuclei templates        │
  │  Cloudflare → stealth mode, WAF bypass payloads         │
  │  MySQL port → sqlmap, mysql brute                       │
  └──────────────────────┬──────────────────────────────────┘
                         │
                         ▼
  ┌─────────────────────────────────────────────────────────┐
  │  STEP 3: AI Plan Generation (target-specific)           │
  │  Sends intel + selected tools to AI                     │
  │  AI returns: ordered attack steps with tool flags       │
  └──────────────────────┬──────────────────────────────────┘
                         │
                         ▼
  ┌─────────────────────────────────────────────────────────┐
  │  STEP 4: runAgenticOmega() — REAL AGENTIC LOOP          │
  │                                                         │
  │  Iteration 1: RECON (tech-aware tool selection)         │
  │  Iteration 2: HUNT (parallel: hunt + bizlogic + adv)    │
  │  Iteration 3: EXPLOIT (Abhimanyu — NOW CALLED!) [FIX]   │
  │  Iteration 4: DEEP_HUNT (second pass on findings) [NEW] │
  │  Iteration 5: POC + VERIFY + SUBMIT                     │
  │                                                         │
  │  Brain adapts at each step:                             │
  │  - SQLi found → sqlmap with specific params             │
  │  - XSS found → dalfox deep mode on those URLs           │
  │  - RCE found → linpeas + bloodhound post-exploit        │
  │  - Critical bug → early exit in quick mode              │
  └─────────────────────────────────────────────────────────┘
```

---

## Files Modified

| File | Change | Impact |
|------|--------|--------|
| `cli/commands.go` | Fixed `localAgentDecision()` to return "exploit" | Abhimanyu now runs |
| `cli/commands.go` | Added `shouldRunAbhimanyu()` helper | Smart exploit triggering |
| `cli/commands.go` | Added "deep_hunt" action in agentic loop | Second-pass scanning |
| `cli/omega/plan.go` | Added `SelectToolsByIntel()` | Target-specific plans |
| `cli/omega/plan.go` | Added `DisplayPlanWithTools()` | Shows selected tools |
| `cli/hunt/engine.go` | Added `TechAwareToolFilter()` | Skip irrelevant tools |
| `cli/recon/registry.go` | nmap: added `-sV`, full port scan option | Deep port scanning |
| `cli/brain/agentic.go` | Added `SuggestNextAction()` | Smarter brain decisions |

---

## New Features Added

### 1. Tech-Aware Tool Selection
```
Target: wordpress.example.com
Detected: WordPress 6.4, PHP 8.1, MySQL, Cloudflare WAF

Selected Tools:
  Recon:  subfinder, httpx, wpscan, nuclei[wordpress/]
  Hunt:   wpscan --enumerate, xmlrpc-brute, wp-nuclei
  Exploit: sqlmap (MySQL), wpscan --passwords, commix
  
Skipped (not relevant):
  graphw00f (no GraphQL), kerbrute (no AD), nosqlmap (no NoSQL)
```

### 2. Abhimanyu Auto-Trigger
```
Hunt found: SQLi parameter at /search?q=
→ Abhimanyu triggered automatically
→ sqlmap -u "https://target.com/search?q=*" --dbs --level 5 --risk 3
→ If DB dump successful → linpeas for post-exploit
```

### 3. Deep Scan Mode
```bash
# Enable full port scan + service detection
CYBERMIND_DEEP_SCAN=true cybermind /plan target.com

# Or via flag
cybermind /plan target.com --deep
```

### 4. Intelligent Decision Engine
```
State: hunt_done, bugs=[SQLi, XSS], technologies=[WordPress, MySQL]

Old behavior: → poc (generic)
New behavior: → exploit (sqlmap on SQLi params)
             → exploit (dalfox deep on XSS URLs)  
             → poc (after exploitation confirmed)
```

---

## Testing

```bash
# Test 1: Verify Abhimanyu is called
cybermind /plan testphp.vulnweb.com

# Test 2: Verify tech-aware tool selection
cybermind /plan wordpress-demo.com

# Test 3: Verify deep scan
CYBERMIND_DEEP_SCAN=true cybermind /recon scanme.nmap.org

# Test 4: Verify agentic loop runs exploit phase
cybermind /plan demo.testfire.net
```

---

## Build

```bash
cd CyberMind/cli
go build -o cybermind .
```

---

## Changelog

### v4.1.0 (April 16, 2026)
- **FIX:** Abhimanyu mode now auto-triggered from agentic loop when vulns found
- **FIX:** Plans are now target-specific (tech-aware tool selection)
- **FIX:** `localAgentDecision()` now returns "exploit" action
- **FIX:** Deep scanning enabled via `CYBERMIND_DEEP_SCAN=true`
- **FIX:** nmap now runs with `-sV` service version detection
- **NEW:** `SelectToolsByIntel()` — maps tech stack to tool set
- **NEW:** `TechAwareToolFilter()` — skips irrelevant tools
- **NEW:** `shouldRunAbhimanyu()` — smart exploit trigger
- **NEW:** "deep_hunt" action — second-pass scanning on findings
- **NEW:** `SuggestNextAction()` in brain — smarter autonomous decisions
- **UPGRADE:** nuclei now uses tech-specific template tags
- **UPGRADE:** Hunt context now passes specific vuln targets to Abhimanyu
