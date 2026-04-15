# CyberMind Edge Worker

Always-on Cloudflare Workers fallback for the Render backend.

## Deploy (one time)

```bash
# Install wrangler
npm install -g wrangler

# Login to Cloudflare
wrangler login

# Deploy
wrangler deploy

# Your worker URL: https://cybermind-api.thecnical.workers.dev
```

## How it works

```
CLI Request
    ↓
Render (Primary) — 4s timeout
    ↓ (if sleeping/down)
Cloudflare Worker — instant, always on
    ├── /ping, /health → local response
    ├── /agent/decide → tries Render (8s), falls back to local logic
    └── everything else → proxies to Render (25s timeout)
```

## Cost

- Cloudflare Workers free tier: 100,000 requests/day
- CyberMind typical usage: ~500 requests/day
- Cost: $0
