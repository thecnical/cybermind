# CyberMind Architecture v6.0

## System Overview

CyberMind is a distributed offensive security system with three main components:

1. **CLI (Go)** — Cross-platform binary with 22 offensive security modes
2. **Backend (Node.js)** — API routing, AI orchestration, plan enforcement
3. **AI Router** — Multi-provider parallel AI with intelligent fallback

```
┌─────────────────────────────────────────────────────────────────┐
│                        User Layer                               │
│  CLI (Go) │ VSCode Extension │ Web Dashboard │ Telegram Bot     │
├─────────────────────────────────────────────────────────────────┤
│  22 Modes │ Manual/Auto │ SAR │ Omega │ Brain Orchestrator      │
├─────────────────────────────────────────────────────────────────┤
│                    HTTP/JSON API Layer                          │
│  POST /hunt │ POST /abhimanyu │ POST /agent/decide │ ...        │
├─────────────────────────────────────────────────────────────────┤
│                   Backend (Node.js + Express)                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐  │
│  │   Recon    │ │   Hunt     │ │Abhimanyu   │ │  RedTeam   │  │
│  │   API      │ │ BizLogic   │ │  Chain     │ │   Brain    │  │
│  │   Anon     │ │ DevSec     │ │ VibeHack   │ │  ... 22    │  │
│  └─────┬──────┘ └─────┬──────┘ └─────┬──────┘ └─────┬──────┘  │
│        └──────────────┴──────────────┴──────────────┘         │
│                          ↓                                     │
│              ┌───────────────────────┐                        │
│              │    AI Router Service  │                        │
│              │  Promise.any() Parallel│                       │
│              └───────────┬───────────┘                        │
│         ┌────────────────┼────────────────┐                   │
│         ↓                ↓                ↓                   │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │  Groq     │    │ Cerebras │    │OpenRouter│  ...        │
│  │ Llama 3   │    │ Llama 3  │    │  Claude   │              │
│  └──────────┘    └──────────┘    └──────────┘              │
├─────────────────────────────────────────────────────────────────┤
│                    Data Layer                                  │
│  Supabase PostgreSQL │ Users │ API Keys │ Usage Logs │       │
├─────────────────────────────────────────────────────────────────┤
│                    Kali Tool Integration                        │
│  nmap │ sqlmap │ dalfox │ nuclei │ metasploit │ 100+ tools   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Request Flow

### 1. CLI → Backend

```go
// CLI (Go)
cybermind /hunt target.com
  ↓
CLI validates command & target
  ↓
CLI checks plan via config
  ↓
CLI sends HTTP POST to backend:
  {
    "target": "target.com",
    "api_key": "cp_live_xxxx",
    "findings": {...},
    "mode": "hunt"
  }
```

### 2. Backend → AI Router

```javascript
// Backend (Node.js)
router.post('/hunt', async (req, res) => {
  // 1. Validate API key & plan
  const plan = await validatePlan(req.headers['x-api-key']);
  if (plan !== 'pro') return 403;

  // 2. Build prompt with tool findings
  const prompt = buildPrompt(req.body);

  // 3. Route to AI Router (parallel)
  const response = await aiRouter(prompt);

  // 4. Return response
  res.json({ success: true, analysis: response });
});
```

### 3. AI Router → AI Providers

```javascript
// AI Router
async function getAIResponse(prompt) {
  const providers = [
    { name: 'groq', fn: callGroq },
    { name: 'cerebras', fn: callCerebras },
    { name: 'openrouter', fn: callOpenRouter },
    // ... more providers
  ];

  // Fire all in parallel, return first valid response
  const result = await Promise.any(
    providers.map(p => p.fn(prompt))
  );

  return result;
}
```

---

## Component Architecture

### CLI (Go Binary)

```
cli/
├── main.go              // Command routing
├── config/              // Configuration management
├── modes/               // Mode implementations
│   ├── recon/          // Reconnaissance
│   ├── hunt/           // Vulnerability hunting
│   ├── abhimanyu/      // Exploitation
│   ├── brain/          // AI orchestrator
│   └── ... (22 modes)
├── tools/              // Tool integration
│   ├── nmap/
│   ├── sqlmap/
│   ├── nuclei/
│   └── ...
└── utils/              // Utilities
```

**Key Functions:**
- Command parsing and validation
- Platform detection (Linux/Windows/macOS)
- Tool execution with timeout/fallback
- Findings normalization
- HTTP client for backend communication

---

### Backend (Node.js + Express)

```
src/
├── app.js              // Express server setup
├── routes/             // API endpoints (22+ mode routes)
│   ├── agent-decide.js // Brain orchestrator
│   ├── abhimanyu.js    // Exploitation
│   ├── hunt.js         // Vulnerability hunt
│   ├── recon.js        // Reconnaissance
│   ├── anon.js         // Anonymous recon
│   ├── api.js          // API security
│   ├── bizlogic.js     // Business logic
│   ├── chain.js        // Vulnerability chaining
│   ├── redteam.js      // Red team simulation
│   ├── devsec.js       // Developer security
│   ├── vibehack.js     // Vibe-coded hacking
│   ├── brain.js        // Mode orchestrator
│   └── ...
├── services/
│   ├── aiRouter.js     // Parallel AI routing
│   ├── groq.js         // Groq API
│   ├── cerebras.js     // Cerebras API
│   ├── openrouter.js   // OpenRouter API
│   └── ...
├── middleware/
│   ├── rateLimiter.js  // Rate limiting
│   ├── apiKeyAuth.js   // API key validation
│   ├── abuseDetector.js // Abuse pattern detection
│   └── outputFilter.js // AI output sanitization
└── db/
    └── supabase.js      // Database client
```

---

### Brain Orchestrator (agent-decide.js)

The brain is the central AI that decides which modes to run and in what order.

**Input:**
- Target
- Current pipeline state (recon_done, hunt_done, etc.)
- Findings from tools
- WAF detection
- Technology stack
- User preferences (manual, SAR, omega)

**Process:**
1. Classify target type (crypto, enterprise, fintech, mobile, cloud, web)
2. Detect tech stack (React, PHP, Node.js, GraphQL, etc.)
3. Check WAF presence (Cloudflare, Akamai, AWS WAF)
4. Select optimal mode sequence
5. Generate smart vuln_focus based on tech
6. Include WAF bypass strategies
7. Return structured decision JSON

**Output:**
```json
{
  "action": "hunt",
  "reason": "Recon found React app with 47 subdomains",
  "vuln_focus": "xss",
  "tools_add": ["dalfox", "kxss"],
  "tools_skip": ["kerbrute", "hydra"],
  "waf_bypass": "random-agent,delay=1",
  "depth": "deep",
  "confidence": 82,
  "novel_attack": "HTTP request smuggling on CDN edge"
}
```

---

### AI Router (aiRouter.js)

Multi-provider parallel AI routing with intelligent fallback.

**Providers (priority order):**
1. Groq (Llama 3.3 70B) — Fastest, high quality
2. Cerebras (Llama 3.3 70B) — Very fast
3. OpenRouter (Claude 3.5, GPT-4) — Best quality
4. HuggingFace (Open models) — Fallback
5. Bytez — Fallback
6. SambaNova — Fallback
7. Mistral — Fallback
8. NVIDIA — Fallback

**Key Features:**
- Parallel execution with `Promise.any()`
- Automatic key rotation (round-robin)
- Response validation (filter empty/error responses)
- Provider-specific error handling
- Timeout control (30s per provider)

---

## Data Flow

### Recon Mode Flow

```
1. CLI: cybermind /recon target.com
   ↓
2. CLI validates target and API key
   ↓
3. CLI sends POST /recon to backend:
   {
     "target": "target.com",
     "type": "passive"
   }
   ↓
4. Backend validates API key (plan check)
   ↓
5. Backend builds prompt with recon guidance
   ↓
6. Backend calls AI Router (parallel providers)
   ↓
7. AI returns recon strategy with exact commands
   ↓
8. Backend returns response to CLI
   ↓
9. CLI displays results to user
   ↓
10. User executes commands (or CLI auto-executes)
```

### OMEGA Mode Flow

```
1. CLI: cybermind /plan target.com --mode deep
   ↓
2. CLI sends POST /agent/decide to backend with initial state
   ↓
3. Brain analyzes target and returns decision:
   {
     "action": "recon",
     "tools_add": ["subfinder", "nmap", "httpx"]
   }
   ↓
4. CLI executes recon tools
   ↓
5. CLI sends findings back to brain
   ↓
6. Brain analyzes findings, returns next decision:
   {
     "action": "hunt",
     "vuln_focus": "xss",
     "tools_add": ["dalfox", "kxss"]
   }
   ↓
7. CLI executes hunt tools
   ↓
8. Loop continues until brain says "done" or "poc"
   ↓
9. CLI generates final report
```

---

## State Management

### Per-Target State (CLI)

Stored in `~/.cybermind/brain/snapshots/{target}/`:

```json
{
  "target": "example.com",
  "start_time": "2026-05-20T00:00:00Z",
  "iterations": [
    {
      "iteration": 1,
      "action": "recon",
      "tools_ran": ["subfinder", "nmap"],
      "findings": {...}
    }
  ],
  "summary": {
    "subdomains_found": 47,
    "vulns_found": 3,
    "critical_findings": 1
  }
}
```

### User State (Database - Supabase)

```sql
profiles:
  - id
  - email
  - plan (free | starter | pro | elite)
  - created_at

api_keys:
  - id
  - user_id
  - key_hash
  - plan
  - created_at

usage_logs:
  - id
  - user_id
  - endpoint
  - status (success | fail)
  - created_at
```

---

## Security Architecture

### Authentication
- API key per user (format: `cp_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`)
- Key hash stored in database (SHA-256)
- Key rotation supported

### Authorization
- Plan enforcement at route level
- Free: 20 req/day, core modes only
- Pro: 200 req/day, advanced modes
- Elite: Unlimited, all modes

### Rate Limiting
- Per-IP rate limit: 20 requests/minute
- Per-user rate limit: Based on plan
- Sliding window algorithm

### Input Validation
- Target validation (domain/IP format)
- Length limits on all inputs
- Abuse pattern detection
- XSS prevention in responses

### Output Filtering
- AI output sanitization
- Sensitive data redaction
- Markdown rendering safety

---

## Design Principles

1. **Tool Exhaustion** — Run all relevant tools, not just quick checks
2. **Fallback-First** — Every tool has fallbacks for reliability
3. **Platform Awareness** — Linux-first for heavy workflows, cross-platform chat
4. **AI-First** — AI guides every decision, human stays in control
5. **Manual + Auto** — Every mode supports both execution styles
6. **Plan Gating** — Advanced modes require paid plans
7. **Privacy-First** — No tool output logged to backend, only AI prompts
8. **Fast Response** — Parallel AI routing for sub-second responses

