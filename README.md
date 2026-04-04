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

[![Version](https://img.shields.io/badge/version-2.2.0-00FFFF?style=for-the-badge)](https://github.com/thecnical/cybermind)
[![License](https://img.shields.io/badge/license-MIT-8A2BE2?style=for-the-badge)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev)
[![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)](#-windows-installation)
[![Linux](https://img.shields.io/badge/Kali%20Linux-268BEE?style=for-the-badge&logo=kalilinux&logoColor=white)](#-kali-linux--ubuntu-installation)
[![Privacy](https://img.shields.io/badge/chat-anonymous-00FF00?style=for-the-badge&logo=tor&logoColor=black)](#privacy--anonymity)
[![Stars](https://img.shields.io/github/stars/thecnical/cybermind?style=for-the-badge&color=yellow)](https://github.com/thecnical/cybermind/stargazers)

[![Buy Me A Coffee](https://img.shields.io/badge/☕%20Buy%20Me%20A%20Coffee-chandanpandit-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/chandanpandit)

*Created by [Chandan Pandey](https://github.com/thecnical)*

**CyberMind is an open-source AI cybersecurity assistant CLI built for Kali Linux and Windows — for penetration testers, ethical hackers, red teamers, and bug bounty hunters.**

<br/>

</div>

---

## What is CyberMind?

CyberMind is an open-source, AI-powered cybersecurity CLI tool that connects to a powerful multi-provider AI backend and delivers real, working, copy-paste-ready cybersecurity commands and techniques directly in your terminal. No browser, no GUI, no distractions — just pure command-line power.

Built in Go as a single binary, CyberMind works on Kali Linux, Ubuntu, Parrot OS, BlackArch, Windows, and macOS. The interactive terminal UI is powered by Bubble Tea and Lipgloss, giving you a clean hacker-style interface with typing animations, full conversation memory, and scrollable chat history.

CyberMind detects your OS on startup and greets you accordingly — Kali Linux users get access to the full Auto Recon Mode which runs real tools like nmap, subfinder, nuclei, gobuster, and more, then sends all output to AI for deep attack vector analysis. Windows users get the full AI chat experience. The AI adapts to your skill level — beginner, intermediate, advanced, or expert — and responds in your preferred language including Hindi and Urdu.

---

## What's New in v2.2.0

**OS Detection + Personalized Greeting** — CyberMind detects your OS on startup and shows `🐧 Kali Linux` or `🪟 Windows` in the banner along with your local IP address.

**Auto Recon Mode (Linux Only)** — The most powerful new feature. Run `cybermind /recon <target>` and CyberMind automatically executes whois, dig, nmap, subfinder, amass, httpx, whatweb, gobuster, and nuclei against your target. All output is collected and sent to AI which analyzes it and returns ranked attack vectors with exact exploitation commands.

**Zero-Filter AI** — All restrictions removed from the AI. Every cybersecurity question gets a complete technical answer — offensive, defensive, red team, black hat techniques explained as security research. No refusals, no disclaimers.

**Adaptive Learning** — The AI detects your skill level from your messages and adapts. Beginners get explanations. Experts get raw commands. The AI also detects your language — write in Hindi or Urdu and it responds in kind.

**Bug Fixes** — Context memory leak fixed (proper circular buffer), history loading race condition fixed, version mismatch fixed, payload command now uses your detected local IP, direct prompt mode now saves to history, input focus restored properly after errors.

**Ctrl+L** — Clear the chat screen without exiting.

---

## ![Windows](https://img.shields.io/badge/Windows-0078D6?style=flat-square&logo=windows&logoColor=white) Windows Installation

### Step 1 — Install Go

Download from [go.dev/dl](https://go.dev/dl) — choose `go1.xx.windows-amd64.msi`. Install, then open a new PowerShell window and verify:

```powershell
go version
```

### Step 2 — Install Git

Download from [git-scm.com](https://git-scm.com/download/win) and install with default settings.

### Step 3 — Clone and build

```powershell
git clone https://github.com/thecnical/cybermind.git
cd cybermind\cli
go build -ldflags="-X main.Version=2.2.0" -o cybermind.exe .
```

### Step 4 — Install globally (run from anywhere)

Open PowerShell as Administrator:

```powershell
Move-Item cybermind.exe C:\Windows\System32\cybermind.exe
```

### Step 5 — Launch

```powershell
cybermind
```

---

## ![Kali Linux](https://img.shields.io/badge/Kali%20Linux-268BEE?style=flat-square&logo=kalilinux&logoColor=white) Kali Linux / Ubuntu Installation

### Step 1 — Install Go

```bash
sudo apt update && sudo apt install golang-go -y
go version
```

If version is older than 1.21, install latest:

```bash
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go version
```

### Step 2 — Clone and build

```bash
git clone https://github.com/thecnical/cybermind.git
cd cybermind/cli
go build -ldflags="-X main.Version=2.2.0" -o cybermind .
```

### Step 3 — Install globally

```bash
sudo mv cybermind /usr/local/bin/cybermind
sudo chmod +x /usr/local/bin/cybermind
```

### Step 4 — Launch

```bash
cybermind
```

### One-Command Install

```bash
git clone https://github.com/thecnical/cybermind.git && cd cybermind && chmod +x install.sh && sudo ./install.sh
```

---

## Auto Recon Mode 🐧 Linux Only

The most powerful feature of CyberMind. Just give it a target and it does everything automatically.

```bash
cybermind /recon 192.168.1.1
cybermind /recon example.com
cybermind /recon 10.0.0.0/24
```

CyberMind will automatically run all available tools in sequence — whois for registration info, dig for DNS records, nmap for port scanning and service detection, subfinder and amass for subdomain enumeration, httpx for live host probing, whatweb for technology fingerprinting, gobuster for directory bruteforce, and nuclei for vulnerability scanning. All output is collected and sent to AI which returns a complete analysis including identified vulnerabilities, CVEs, ranked attack vectors, and exact exploitation commands.

If a tool is not installed, it is skipped and the AI provides guidance based on what was collected. If no tools are installed at all, the AI falls back to providing a complete manual recon guide.

```bash
# Check which tools are installed
cybermind /tools

# Install missing tools
sudo apt install nmap whois dnsutils gobuster nuclei
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/owasp-amass/amass/v4/...@master
```

---

## Features

```
⚡ Interactive AI Chat        Fully responsive terminal UI with conversation memory
🔍 Auto Recon Mode           Real tools: nmap, subfinder, nuclei, gobuster + AI analysis
🧠 Adaptive Learning         AI adapts to beginner/intermediate/advanced/expert level
🌍 Language Detection        Responds in Hindi, Urdu, or English automatically
🚫 Zero Restrictions         All cybersecurity questions answered, no refusals
🔍 Scan Mode                 AI-guided network & web scanning with exact commands
🕵️  Recon Mode                OSINT, subdomain enum, passive/active recon
💥 Exploit Mode              CVE guides, Metasploit modules, manual exploits
🎯 Payload Mode              msfvenom with your detected local IP
🛠️  Tool Mode                 Deep-dive for any Kali Linux tool (CLI + GUI)
🔗 Research Feature          Real GitHub links, CVEs, exploit-db, resources
� Local Chat History        Saved only on your machine, never uploaded
� Zero Data Collection      No logs, no accounts, no tracking
� 9 AI Providers            Parallel execution, 40+ models, never fails
🪟 Windows Support           Full AI chat on Windows
� Linux/Kali Support        Full recon + AI on Linux
⌨️  Ctrl+L                    Clear chat screen instantly
```

---

## Usage

### Interactive Chat

```bash
cybermind
```

Controls: `Enter` send · `PgUp/PgDn` scroll · `Ctrl+L` clear screen · `Ctrl+C` exit

### Auto Recon (Linux only)

```bash
cybermind /recon <target>     # full auto recon + AI analysis
cybermind /tools              # check installed tools
```

### AI-Guided Commands

```bash
cybermind scan 192.168.1.1 full
cybermind scan example.com subdomain
cybermind recon target.com osint
cybermind exploit CVE-2021-44228 10.0.0.1
cybermind payload windows x64
cybermind payload linux x86
cybermind tool sqlmap "find SQLi in login form"
cybermind tool nmap "scan for SMB vulnerabilities"
cybermind tool bloodhound "find paths to domain admin"
```

### Research

```bash
cybermind "give me github links for pentesting tools"
cybermind "CVE-2021-44228 exploit links and PoC"
cybermind "best wordlists for password cracking"
```

### Direct Prompt

```bash
cybermind "how to crack WPA2 with aircrack-ng"
cybermind "kerberoasting step by step"
cybermind "bypass UAC on Windows 10"
```

### History

```bash
cybermind history      # view saved conversations
cybermind clear        # wipe local history
cybermind help         # show all commands
cybermind --version    # show version
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

## Privacy & Anonymity

Your conversations are completely private. No conversation logs are stored on the server. No user accounts. No tracking. No analytics. Your chat history is saved only on your machine at `~/.cybermind/history.json` (Linux) or `C:\Users\<you>\.cybermind\history.json` (Windows). Every request is stateless — the server processes it and immediately forgets it.

```bash
# Maximum anonymity through Tor
torsocks cybermind "your question"
proxychains cybermind scan target.com full
```

---

## Build Options

```bash
make build          # current OS
make build-linux    # Kali Linux amd64
make build-windows  # Windows amd64
make build-all      # all platforms
make install        # install to /usr/local/bin
make clean          # remove artifacts
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Support

[![Buy Me A Coffee](https://img.shields.io/badge/☕%20Buy%20Me%20A%20Coffee-chandanpandit-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/chandanpandit)

---

## License

MIT — see [LICENSE](LICENSE).

---

## Disclaimer

CyberMind is for authorized security research, penetration testing with written permission, CTF competitions, and cybersecurity education. Never use against systems you do not own or have explicit written authorization to test.

---

<div align="center">

Made with ⚡ by [Chandan Pandey](https://github.com/thecnical)

[GitHub](https://github.com/thecnical/cybermind) · [Buy Me A Coffee](https://buymeacoffee.com/chandanpandit)

---

*CyberMind — AI cybersecurity CLI | Kali Linux AI assistant | Windows hacking tool | Auto recon | Ethical hacking AI | Penetration testing CLI | Open source hacking tool | AI pentest assistant | Bug bounty AI | Red team tool*

</div>
