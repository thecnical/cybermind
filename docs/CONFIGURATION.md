# Configuration Guide

Complete guide to configuring CyberMind CLI v6.0.

---

## Table of Contents

- [Configuration File](#configuration-file)
- [API Key Setup](#api-key-setup)
- [Backend Configuration](#backend-configuration)
- [Telegram Alerts](#telegram-alerts)
- [Environment Variables](#environment-variables)
- [Plan Configuration](#plan-configuration)
- [Mode Defaults](#mode-defaults)
- [Tool Paths](#tool-paths)
- [Advanced Settings](#advanced-settings)

---

## Configuration File

CyberMind stores configuration in `~/.cybermind/config.yaml` (Linux/macOS) or `%USERPROFILE%\.cybermind\config.yaml` (Windows).

### Example Config

```yaml
api_key: cp_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
backend_url: https://cybermind-backend.onrender.com
default_mode: auto
telegram_bot_token: ""
telegram_chat_id: ""
plan: free
timeout: 30
max_retries: 3
```

---

## API Key Setup

### Get Your Key

1. Visit [cybermindcli.com](https://cybermindcli.com)
2. Sign up / Log in
3. Go to Dashboard → API Keys
4. Copy your key

### Set Key via CLI

```bash
cybermind config --key cp_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Set Key via Config File

```yaml
api_key: cp_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Verify Key

```bash
cybermind config --show
```

---

## Backend Configuration

### Default Backend

```yaml
backend_url: https://cybermind-backend.onrender.com
```

### Self-Hosted Backend

```yaml
backend_url: https://your-backend.com
```

### Set via CLI

```bash
cybermind config --backend https://your-backend.com
```

### Test Backend

```bash
cybermind --health
```

---

## Telegram Alerts

### Get Bot Token

1. Message [@BotFather](https://t.me/botfather) on Telegram
2. Send `/newbot`
3. Follow prompts to create bot
4. Copy the token (format: `123456789:ABCdefGHIjklMNOpqrSTUvwxYZ`)

### Get Chat ID

1. Message your bot
2. Visit: `https://api.telegram.org/bot<TOKEN>/getUpdates`
3. Find your `chat` object → `id`

### Configure via CLI

```bash
cybermind config --telegram-bot-token YOUR_BOT_TOKEN
cybermind config --telegram-chat-id YOUR_CHAT_ID
```

### Configure via File

```yaml
telegram_bot_token: "123456789:ABCdefGHIjklMNOpqrSTUvwxYZ"
telegram_chat_id: "123456789"
```

### Test Alerts

```bash
cybermind test-alert
```

---

## Environment Variables

You can also configure via environment variables:

| Variable | Description |
|---|---|
| `CYBERMIND_KEY` | Your API key |
| `CYBERMIND_BACKEND` | Backend URL |
| `CYBERMIND_CONFIG` | Custom config file path |
| `CYBERMIND_TIMEOUT` | Request timeout (seconds) |
| `CYBERMIND_MAX_RETRIES` | Max retry attempts |

### Example

```bash
export CYBERMIND_KEY=cp_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
export CYBERMIND_BACKEND=https://your-backend.com
cybermind /recon target.com
```

---

## Plan Configuration

### View Current Plan

```bash
cybermind plan --show
```

### Upgrade Plan

```bash
cybermind upgrade starter
cybermind upgrade pro
cybermind upgrade elite
```

### Plan Features

| Plan | Requests/day | Modes |
|---|---|---|
| Free | 20 | Core modes only |
| Starter | 50 | + Hunt, API, Chain, DevSec |
| Pro | 200 | + BizLogic, VibeHack, Bug-Detect, Pipeline |
| Elite | Unlimited | All 22 modes + Abhimanyu, RedTeam, Omega, Manual modes |

---

## Mode Defaults

### Set Default Mode

```bash
cybermind config --default-mode deep
```

### Available Modes

- `auto` — AI decides best approach
- `quick` — Fast scan (~30 min)
- `deep` — Full depth (~4 hours)
- `stealth` — Low-noise scanning

### Configure via File

```yaml
default_mode: deep
```

---

## Tool Paths

### Default Tool Paths

CyberMind automatically finds tools in your PATH. If tools are in non-standard locations, configure them:

```yaml
tool_paths:
  nmap: /usr/local/bin/nmap
  sqlmap: /opt/sqlmap/sqlmap.py
  nuclei: /usr/local/bin/nuclei
  subfinder: /usr/local/bin/subfinder
```

### Custom Tool Directory

```bash
cybermind config --tool-dir /opt/tools
```

---

## Advanced Settings

### Request Timeout

```yaml
timeout: 30  # seconds
```

### Max Retries

```yaml
max_retries: 3
```

### Parallel Workers

```yaml
parallel_workers: 4
```

### Output Format

```yaml
output_format: json  # json | text | markdown
```

### Log Level

```yaml
log_level: info  # debug | info | warn | error
```

---

## View All Config

```bash
cybermind config --show
```

**Output:**
```yaml
api_key: cp_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
backend_url: https://cybermind-backend.onrender.com
default_mode: auto
telegram_bot_token: ""
telegram_chat_id: ""
plan: free
timeout: 30
max_retries: 3
parallel_workers: 4
output_format: json
log_level: info
```

---

## Reset Config

```bash
cybermind config --reset
```

This resets to default values (except API key).

---

## Configuration Priority

1. Environment variables (highest)
2. Command-line flags
3. Config file
4. Defaults (lowest)

---

## Next Steps

After configuration, read [GETTING_STARTED.md](GETTING_STARTED.md) for your first scan.
