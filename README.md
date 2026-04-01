<div align="center">

```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ███╗██╗███╗   ██╗██████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗ ████║██║████╗  ██║██╔══██╗
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔████╔██║██║██╔██╗ ██║██║  ██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╔╝██║██║██║╚██╗██║██║  ██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚═╝ ██║██║██║ ╚████║██████╔╝
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝
```

**⚡ AI-Powered Cybersecurity CLI Tool for Kali Linux**

![Version](https://img.shields.io/badge/version-2.0.0-cyan)
![License](https://img.shields.io/badge/license-MIT-green)
![Go](https://img.shields.io/badge/Go-1.21+-blue)
![Node](https://img.shields.io/badge/Node.js-18+-green)
![Kali](https://img.shields.io/badge/Kali%20Linux-Compatible-red)

*Created by [Chandan Pandey](https://github.com/thecnical)*

</div>

---

## What is CyberMind?

CyberMind is an AI-powered cybersecurity assistant built for Kali Linux professionals.
It combines a Go-based interactive CLI with a Node.js backend that routes prompts through
9 AI providers (Groq, Cerebras, ai.cc, SambaNova, Mistral, NVIDIA, OpenRouter, HuggingFace, Bytez)
to deliver real, working cybersecurity commands and techniques.

> **Note:** The backend is hosted in a private repository for security.
> This public repo contains the CLI only.
> To self-host the backend, contact [github.com/thecnical](https://github.com/thecnical).

---

## Features

- **Interactive AI Chat** — ask any cybersecurity question, get real commands
- **Scan Mode** — AI-guided nmap/masscan/nuclei scan pipelines
- **Recon Mode** — OSINT, subdomain enum, passive/active recon
- **Exploit Mode** — CVE exploitation guides, Metasploit modules
- **Payload Mode** — msfvenom payload generation guides
- **Tool Mode** — deep-dive help for any Kali tool
- **9 AI Providers** — parallel execution, auto-fallback, never fails
- **Local History** — all chats saved to `~/.cybermind/history.json`
- **Rate Limited** — 20 req/min per IP, abuse protection
- **Cross-Platform** — Kali Linux, Ubuntu, Windows, macOS

---

## Installation

### Kali Linux / Ubuntu

```bash
# 1. Clone the repo
git clone https://github.com/thecnical/cybermind.git
cd cybermind

# 2. Setup backend
cd backend
npm install
cp .env.example .env
nano .env   # add your API keys

# 3. Build CLI
cd ../cli
go build -o cybermind
sudo mv cybermind /usr/local/bin/   # install globally

# 4. Start backend
cd ../backend
node src/app.js &

# 5. Run CLI
cybermind
```

### Windows

```powershell
git clone https://github.com/thecnical/cybermind.git
cd cybermind\backend
npm install
copy .env.example .env   # edit with your keys

cd ..\cli
go build -o cybermind.exe
.\cybermind.exe
```

---

## Environment Variables

Add these to `backend/.env`:

```env
PORT=3000

# AI Provider Keys (comma-separated for rotation)
GROQ_KEYS=your_groq_key
CEREBRAS_KEYS=your_cerebras_key
AICC_KEYS=your_aicc_key
SAMBANOVA_KEYS=your_sambanova_key
MISTRAL_KEYS=your_mistral_key
NVIDIA_KEYS=your_nvidia_key
OPENROUTER_KEYS=your_openrouter_key
HF_KEYS=your_huggingface_key
BYTEZ_KEYS=your_bytez_key
```

Get free API keys:
- Groq: https://console.groq.com
- Cerebras: https://cloud.cerebras.ai
- SambaNova: https://sambanova.ai
- Mistral: https://console.mistral.ai
- HuggingFace: https://huggingface.co/settings/tokens
- OpenRouter: https://openrouter.ai

---

## Usage

```bash
# Interactive AI chat
cybermind

# Scan a target
cybermind scan 192.168.1.1 full
cybermind scan example.com subdomain
cybermind scan 10.0.0.0/24 network

# Recon
cybermind recon example.com osint
cybermind recon example.com subdomain
cybermind recon target.com passive

# Exploitation
cybermind exploit CVE-2021-44228 10.0.0.1
cybermind exploit "apache struts" 192.168.1.100

# Payload generation
cybermind payload windows x64
cybermind payload linux x86
cybermind payload android

# Tool help
cybermind tool sqlmap "find SQLi in login form"
cybermind tool nmap "scan for SMB vulnerabilities"
cybermind tool hashcat "crack NTLM hashes"

# History
cybermind history
cybermind clear
cybermind help
```

---

## Scan Types

| Type | Description |
|------|-------------|
| `quick` | Top 1000 ports, service detection |
| `full` | All 65535 ports, scripts, OS detection |
| `stealth` | SYN scan, slow timing, avoid detection |
| `web` | nikto, whatweb, ffuf, directory bruteforce |
| `vuln` | nmap vuln scripts, nuclei, searchsploit |
| `subdomain` | subfinder, amass, dnsx, httpx pipeline |
| `network` | Subnet discovery, live hosts, services |
| `ad` | Active Directory: ldap, smb, kerberos, bloodhound |

---

## Recon Types

| Type | Description |
|------|-------------|
| `passive` | No direct contact — shodan, google dorks, whois |
| `active` | Direct scanning — nmap, httpx, nuclei |
| `subdomain` | Full subdomain enumeration pipeline |
| `osint` | Emails, employees, leaked creds, social media |
| `web` | Tech stack, directories, JS files, API keys |
| `network` | Topology, live hosts, banners |

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/chat` | General AI chat |
| POST | `/scan` | Scan guidance |
| POST | `/recon` | Recon guidance |
| POST | `/exploit` | Exploitation guide |
| POST | `/exploit/payload` | msfvenom payload |
| POST | `/tools/help` | Tool usage guide |
| GET | `/tools` | List all tools |

---

## Architecture

```
CyberMind/
├── backend/                 # Node.js + Express API
│   └── src/
│       ├── app.js           # Express server
│       ├── config/
│       │   ├── models.js    # AI model registry
│       │   └── systemPrompt.js  # Cybersecurity system prompt
│       ├── middleware/
│       │   ├── rateLimiter.js
│       │   └── auth.js
│       ├── routes/
│       │   ├── chat.js
│       │   ├── scan.js
│       │   ├── recon.js
│       │   ├── exploit.js
│       │   └── tools.js
│       ├── services/        # AI providers
│       │   ├── aiRouter.js  # Core parallel router
│       │   ├── groq.js
│       │   ├── cerebras.js
│       │   ├── aicc.js
│       │   ├── sambanova.js
│       │   ├── mistral.js
│       │   ├── nvidia.js
│       │   ├── openrouter.js
│       │   ├── huggingface.js
│       │   └── bytez.js
│       └── utils/
│           ├── keyRotation.js
│           ├── logger.js
│           ├── requestLogger.js
│           └── responseSelector.js
└── cli/                     # Go CLI
    ├── main.go              # Commands + banner
    ├── api/client.go        # Backend HTTP client
    ├── ui/                  # Bubble Tea TUI
    │   ├── model.go
    │   ├── view.go
    │   └── styles.go
    └── storage/             # Local history
        ├── history.go
        └── file.go
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

## License

MIT — see [LICENSE](LICENSE)

## Disclaimer

CyberMind is for authorized security research, penetration testing, and education only.
Never use against systems without explicit written permission.

---

<div align="center">
Made with ⚡ by <a href="https://github.com/thecnical">Chandan Pandey</a>
</div>
