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

### ⚡ AI-Powered Cybersecurity CLI Tool

[![Version](https://img.shields.io/badge/version-2.0.0-00FFFF?style=flat-square)](https://github.com/thecnical/cybermind)
[![License](https://img.shields.io/badge/license-MIT-8A2BE2?style=flat-square)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go)](https://go.dev)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-Ready-268BEE?style=flat-square&logo=kalilinux)](https://kali.org)
[![Made by](https://img.shields.io/badge/made%20by-thecnical-FF4444?style=flat-square)](https://github.com/thecnical)

<br/>

*Ask. Hack. Learn.*

<br/>

</div>

---

## Overview

**CyberMind** is a terminal-based AI assistant designed for cybersecurity professionals and researchers.
It connects to a powerful AI backend and delivers real, actionable cybersecurity guidance directly in your terminal —
no browser, no distractions, just pure command-line power.

Built for **Kali Linux**. Works everywhere Go runs.

---

## Features

```
⚡ Interactive AI Chat      Ask anything, get real commands
🔍 Scan Mode               AI-guided network & web scanning
🕵️  Recon Mode              OSINT, subdomain enum, passive/active recon
💥 Exploit Mode            CVE guides, service exploitation
🎯 Payload Mode            Payload generation guidance
🛠️  Tool Mode               Deep-dive help for any security tool
📜 Chat History            All sessions saved locally
🔄 Auto-Fallback           Never fails — multiple AI providers
```

---

## Installation

### Kali Linux / Ubuntu (Recommended)

```bash
# Clone
git clone https://github.com/thecnical/cybermind.git
cd cybermind

# One-command install
chmod +x install.sh && ./install.sh
```

### Manual Build

```bash
cd cli
go mod tidy
go build -o cybermind .

# Install globally (Linux)
sudo mv cybermind /usr/local/bin/
```

### Windows

```powershell
cd cli
go build -o cybermind.exe .
.\cybermind.exe
```

### Requirements

| Dependency | Version | Install |
|------------|---------|---------|
| Go | 1.21+ | [go.dev/dl](https://go.dev/dl) |
| Git | any | `apt install git` |

> The backend is required to use CyberMind. See [Backend Setup](#backend-setup).

---

## Backend Setup

CyberMind CLI connects to a backend API. You can either:

**Option A — Use the hosted API** *(default)*
```bash
# CLI connects to the live API automatically
cybermind
```

**Option B — Self-host locally**
```bash
# Set your local backend URL
export CYBERMIND_API=http://localhost:3000/chat
cybermind
```

> The backend source is maintained privately. Contact [github.com/thecnical](https://github.com/thecnical) for self-hosting access.

---

## Usage

```bash
# Launch interactive chat
cybermind

# Scan a target
cybermind scan <target> [type]

# Recon
cybermind recon <target> [type]

# Exploitation guide
cybermind exploit <cve-or-service> [target]

# Payload generation guide
cybermind payload <os> [arch]

# Tool help
cybermind tool <toolname> [task]

# History & utils
cybermind history
cybermind clear
cybermind help
cybermind --version
```

---

## Commands

### Scan Types

| Type | What it does |
|------|-------------|
| `quick` | Fast top-port scan |
| `full` | All ports, scripts, OS detection |
| `stealth` | Low-noise, slow timing |
| `web` | Web app scanning pipeline |
| `vuln` | Vulnerability detection |
| `subdomain` | Subdomain enumeration |
| `network` | Subnet discovery |
| `ad` | Active Directory enumeration |

### Recon Types

| Type | What it does |
|------|-------------|
| `passive` | No direct contact — OSINT only |
| `active` | Direct scanning pipeline |
| `subdomain` | Full subdomain enum pipeline |
| `osint` | Emails, employees, infrastructure |
| `web` | Tech stack, endpoints, JS analysis |
| `network` | Topology and service mapping |

---

## Examples

```bash
# Full port scan
cybermind scan 192.168.1.1 full

# Subdomain enumeration
cybermind scan example.com subdomain

# OSINT investigation
cybermind recon target.com osint

# Log4Shell exploitation guide
cybermind exploit CVE-2021-44228 10.0.0.1

# Windows x64 payload guide
cybermind payload windows x64

# SQLMap help for a specific task
cybermind tool sqlmap "find SQLi in login form"

# Direct question
cybermind "how to crack WPA2 with aircrack-ng"
```

---

## Chat History

All conversations are saved locally at:

```
~/.cybermind/history.json     # Linux / macOS
C:\Users\<you>\.cybermind\history.json   # Windows
```

```bash
cybermind history    # view all sessions
cybermind clear      # wipe history
```

---

## Build from Source

```bash
# Current OS
make build

# Kali Linux / Linux amd64
make build-linux

# Windows
make build-windows

# All platforms
make build-all

# Install globally on Linux
make install
```

---

## Project Structure

```
cybermind/
├── cli/
│   ├── main.go          # Commands, banner, entry point
│   ├── go.mod
│   ├── api/
│   │   └── client.go    # Backend HTTP client
│   ├── ui/
│   │   ├── model.go     # Bubble Tea state machine
│   │   ├── view.go      # Terminal UI renderer
│   │   └── styles.go    # Lipgloss styles
│   └── storage/
│       ├── history.go   # Chat history logic
│       └── file.go      # File I/O
├── install.sh           # Kali Linux installer
├── Makefile             # Build commands
├── LICENSE
└── README.md
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) — PRs welcome.

## License

MIT — see [LICENSE](LICENSE)

## Disclaimer

> CyberMind is intended for **authorized security research, penetration testing, and education only**.
> Never use against systems you do not own or have explicit written permission to test.
> The author is not responsible for misuse.

---

<div align="center">

Made with ⚡ by [Chandan Pandey](https://github.com/thecnical)

*Star ⭐ the repo if CyberMind helped you*

</div>
