# CyberMind Backend API Reference

This document describes all backend endpoints for the CyberMind CLI v6.0.

**Base URL:** `https://cybermind-backend.onrender.com` (or your self-hosted instance)

**Authentication:** All endpoints require `X-API-Key` header or `Authorization: Bearer <key>`.

---

## Authentication

```bash
curl -H "X-API-Key: cp_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
     https://cybermind-backend.onrender.com/health
```

---

## Response Format

### Success
```json
{
  "success": true,
  "response": "AI-generated content",
  "provider": "groq",
  "model": "llama-3.3-70b",
  "time": "1.4s"
}
```

### Error
```json
{
  "success": false,
  "error": "Descriptive error message"
}
```

### Plan Gate Error
```json
{
  "success": false,
  "error": "Elite plan required for /abhimanyu",
  "upgrade_url": "https://cybermindcli.com/plans"
}
```

---

## Core Endpoints

### Health Check
```
GET /
GET /health
GET /ping
GET /wake
```

**No auth required.**

**Response:**
```json
{
  "status": "ok",
  "version": "5.5.0",
  "providers": {
    "groq": "configured",
    "openrouter": "configured",
    "cerebras": "not configured"
  }
}
```

---

### Chat
```
POST /chat
```

**Body:**
```json
{
  "prompt": "How do I test for SQL injection?",
  "context": [],
  "mode": "security"
}
```

---

### Scan
```
POST /scan
```

**Body:**
```json
{
  "target": "192.168.1.1",
  "type": "full",
  "options": "--stealth"
}
```

**Types:** `quick`, `full`, `stealth`, `web`, `vuln`, `subdomain`, `network`, `ad`

---

### Recon
```
POST /recon
POST /v1/recon
```

**Body:**
```json
{
  "target": "example.com",
  "type": "passive"
}
```

**Types:** `passive`, `active`, `subdomain`, `osint`, `web`, `network`, `dns_active`, `asn_recon`, `cloud_recon`, `github_recon`, `js_recon`, `tech_fingerprint`, `network_fingerprint`, `js_analysis`, `cms_detect`, `incremental`, `monitor`, `html_report`, `tier1_recon`

---

### Exploit
```
POST /exploit
POST /exploit/payload
```

**Body:**
```json
{
  "vulnerability": "CVE-2021-44228",
  "target": "10.0.0.1",
  "version": "2.14.1"
}
```

---

### Tools
```
GET /tools
GET /tools/:category
POST /tools/help
```

**Categories:** `recon`, `exploitation`, `passwords`, `wireless`, `postexploit`, `forensics`, `web`, `ad`

---

## Mode Endpoints

### Hunt
```
POST /hunt
POST /v1/hunt
```

**Body:**
```json
{
  "target": "example.com",
  "target_type": "domain",
  "findings": {},
  "xss_found": [],
  "vulns_found": [],
  "params_found": [],
  "tools_run": [],
  "waf_detected": false,
  "waf_vendor": "",
  "open_ports": [],
  "manual": false,
  "sar": false,
  "technologies": [],
  "subdomains": [],
  "live_urls": []
}
```

**Response:**
```json
{
  "success": true,
  "mode": "hunt",
  "analysis": "...",
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

### Abhimanyu
```
POST /abhimanyu
POST /v1/abhimanyu
```

**Body:**
```json
{
  "target": "example.com",
  "vuln_type": "all",
  "lhost": "attacker.com",
  "findings": {},
  "xss_found": [],
  "vulns_found": [],
  "params_found": [],
  "open_ports": [],
  "technologies": [],
  "live_urls": [],
  "manual": false,
  "step": "init",
  "prior_output": "",
  "session_id": ""
}
```

**Plan:** Elite required.

---

### Chain
```
POST /chain/analyze
POST /v1/chain/analyze
```

**Body:**
```json
{
  "bugs": [
    { "type": "ssrf", "url": "...", "severity": "high" },
    { "type": "idor", "url": "...", "severity": "medium" }
  ],
  "target": "example.com"
}
```

**Plan:** Pro required.

---

### RedTeam
```
POST /red-team/phase
POST /v1/redteam/phase
```

**Body:**
```json
{
  "company": "Example Corp",
  "phase": 3,
  "scope": {
    "domains": ["example.com"],
    "ip_ranges": ["10.0.0.0/24"]
  },
  "prior_summaries": []
}
```

**Plan:** Elite required. Phases 1-7.

---

### DevSec
```
POST /devsec/analyze
POST /v1/devsec/analyze
```

**Body:**
```json
{
  "findings": "npm audit output...",
  "target": "github.com/user/repo"
}
```

**Plan:** Starter+.

---

### VibeHack
```
POST /vibe-hack
POST /v1/vibehack
```

**Plan:** Pro required. Returns SSE stream.

---

## v6.0 Power Mode Endpoints

### Anon
```
POST /anon
POST /v1/anon
```

**Body:**
```json
{
  "target": "example.com",
  "depth": "standard",
  "sources": ["whois", "shodan", "certs", "github"]
}
```

**Plan:** Free.

---

### API Security
```
POST /api/api
POST /v1/api
```

**Body:**
```json
{
  "target": "api.example.com",
  "type": "rest",
  "endpoints": ["/api/v1/users", "/api/v1/orders"],
  "auth": "Bearer token..."
}
```

**Types:** `rest`, `graphql`, `grpc`, `websocket`, `soap`

**Plan:** Pro required.

---

### BizLogic
```
POST /bizlogic
POST /v1/bizlogic
```

**Body:**
```json
{
  "target": "example.com",
  "workflows": ["checkout", "registration", "password-reset"],
  "user_roles": ["admin", "user", "guest"]
}
```

**Plan:** Pro required.

---

### Brain
```
POST /brain
POST /v1/brain
```

**Body:**
```json
{
  "target": "example.com",
  "mode": "auto",
  "manual": false,
  "sar": false,
  "omega": false,
  "prior_context": ""
}
```

**Plan:** Elite required.

---

### Agent Decide (OMEGA Brain)
```
POST /agent/decide
GET  /agent/modes
POST /v1/agent/decide
GET  /v1/agent/modes
```

**POST Body:**
```json
{
  "target": "example.com",
  "iteration": 1,
  "phase": "init",
  "recon_done": false,
  "hunt_done": false,
  "abhi_done": false,
  "bugs_found": 0,
  "bug_types": [],
  "live_urls": [],
  "open_ports": [],
  "waf_detected": false,
  "waf_vendor": "",
  "technologies": [],
  "subdomains_found": 0,
  "tools_ran": [],
  "tools_failed": [],
  "findings_summary": {},
  "last_action": "",
  "skill_level": "intermediate",
  "focus_bugs": "",
  "mode": "deep",
  "manual": false,
  "sar": false,
  "omega": false,
  "prior_context": ""
}
```

**Response (POST):**
```json
{
  "success": true,
  "decision": {
    "action": "hunt",
    "reason": "Recon found React app with 47 subdomains",
    "vuln_focus": "xss",
    "tools_add": ["dalfox", "kxss"],
    "tools_skip": ["kerbrute", "hydra"],
    "waf_bypass": "random-agent,delay=1",
    "depth": "deep",
    "confidence": 82,
    "notes": "Focus on DOM XSS via URL params",
    "novel_attack": "HTTP request smuggling on CDN edge",
    "priority_endpoints": ["/api/v1/", "/graphql", "/admin"],
    "estimated_bugs": 2,
    "user_prompt": "",
    "all_modes_status": {
      "recon": "done",
      "hunt": "in_progress",
      "abhimanyu": "pending"
    }
  }
}
```

**GET /agent/modes Response:**
```json
{
  "success": true,
  "modes": [
    { "id": "recon", "name": "Reconnaissance", "auto": true, "manual": true },
    { "id": "abhimanyu", "name": "Abhimanyu", "auto": true, "manual": false, "plan": "elite" }
  ]
}
```

---

## Agent Endpoints

```
GET  /agents/status
POST /agents/sentry-webhook
POST /agents/test-alert
POST /agents/daily-report
POST /agents/bi/daily
POST /agents/bi/weekly
POST /agents/email/welcome
POST /agents/email/announce
POST /agents/email/weekly-digest
POST /agents/github/check
POST /agents/twitter/tweet
```

**Admin only.** Requires `X-Admin-Key` header.

---

## Versioned API

All endpoints are also available under `/v1/` prefix:

```
/v1/chat
/v1/recon
/v1/hunt
/v1/abhimanyu
/v1/chain
/v1/redteam
/v1/devsec
/v1/vibe
/v1/vibehack
/v1/anon
/v1/api
/v1/bizlogic
/v1/brain
/v1/agent/decide
/v1/agent/modes
```

The `/v1/` prefix is the stable API surface. Unversioned routes remain for backward compatibility.

---

## Rate Limits

| Plan | Rate Limit |
|---|---|
| Free | 20 requests/day |
| Starter | 50 requests/day |
| Pro | 200 requests/day |
| Elite | Unlimited |

Backend rate limit: 20 requests/minute per IP.

---

## Error Codes

| HTTP | Meaning |
|---|---|
| 400 | Bad request — invalid parameters |
| 401 | Unauthorized — invalid or missing API key |
| 403 | Forbidden — plan upgrade required |
| 429 | Too many requests — rate limit exceeded |
| 502 | Bad gateway — AI provider failure |
| 500 | Internal server error |
