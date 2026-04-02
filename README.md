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

**CyberMind is an open-source AI cybersecurity assistant CLI tool built for Kali Linux and Windows, designed for penetration testers, ethical hackers, and bug bounty hunters.**

<br/>

</div>

---

## What is CyberMind?

CyberMind is an open-source, AI-powered cybersecurity CLI tool that connects to a powerful multi-provider AI backend and delivers real, working, copy-paste-ready cybersecurity commands and techniques directly in your terminal. No browser, no GUI, no distractions — just pure command-line power.

Built in Go as a single binary, CyberMind works on Kali Linux, Ubuntu, Parrot OS, BlackArch, Windows, and macOS. The interactive terminal UI is powered by Bubble Tea and Lipgloss, giving you a clean hacker-style interface with typing animations, conversation memory, and scrollable chat history.

CyberMind knows over 100 Kali Linux tools deeply — nmap, metasploit, sqlmap, hashcat, bloodhound, impacket, aircrack-ng, burpsuite, nuclei, subfinder, and many more. It remembers your conversation context, never refuses cybersecurity questions, and provides real GitHub links and resources on demand.

---

## ![Windows](https://img.shields.io/badge/Windows-0078D6?style=flat-square&logo=windows&logoColor=white) Windows Installation

### Step 1 — Install Go

Download and install Go from [go.dev/dl](https://go.dev/dl) — choose `go1.xx.windows-amd64.msi`.

Run the installer, then open a new PowerShell window and verify:

```powershell
go version
```

You should see something like `go version go1.21.0 windows/amd64`.

### Step 2 — Install Git (if not installed)

Download from [git-scm.com](https://git-scm.com/download/win) and install with default settings.

### Step 3 — Clone the repository

```powershell
git clone https://github.com/thecnical/cybermind.git
cd cybermind\cli
```

### Step 4 — Build the binary

```powershell
go build -ldflags="-X main.Version=2.2.0" -o cybermind.exe .
```

This creates `cybermind.exe` in the current folder.

### Step 5 — Install globally (run from anywhere)

Open PowerShell as Administrator, then:

```powershell
Move-Item cybermind.exe C:\Windows\System32\cybermind.exe
```

Now you can run `cybermind` from any folder in PowerShell or Command Prompt.

### Step 6 — Launch

```powershell
cybermind
```

Or ask a direct question:

```powershell
cybermind "how to find subdomains"
cybermind scan 192.168.1.1 full
```

---

## ![Kali Linux](https://img.shields.io/badge/Kali%20Linux-268BEE?style=flat-square&logo=kalilinux&logoColor=white) Kali Linux / Ubuntu Installation

### Step 1 — Install Go

```bash
sudo apt update && sudo apt install golang-go -y
go version
```

If the version is older than 1.21, install the latest from [go.dev/dl](https://go.dev/dl):

```bash
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go version
```

### Step 2 — Install Git (if not installed)

```bash
sudo apt install git -y
```

### Step 3 — Clone the repository

```bash
git clone https://github.com/thecnical/cybermind.git
cd cybermind/cli
```

### Step 4 — Build the binary

```bash
go build -ldflags="-X main.Version=2.2.0" -o cybermind .
```

### Step 5 — Install globally

```bash
sudo mv cybermind /usr/local/bin/cybermind
sudo chmod +x /usr/local/bin/cybermind
```

### Step 6 — Launch

```bash
cybermind
```

Or use the one-command installer which handles everything automatically:

```bash
git clone https://github.com/thecnical/cybermind.git
cd cybermind
chmod +x install.sh && sudo ./install.sh
```

---

## One-Command Install (Linux/Kali)

```bash
git clone https://github.com/thecnical/cybermind.git && cd cybermind && chmod +x install.sh && sudo ./install.sh
```

---

## Privacy & Anonymity

**Your conversations are completely private. No one can read your chats — not us, not anyone.**

Your queries are sent to the AI backend over HTTPS. The backend processes your prompt and sends back a response. No conversation logs are stored on the server. No user accounts. No tracking. No analytics. No IP logging tied to your queries.

Your chat history is saved only on your own machine — at `~/.cybermind/history.json` on Linux/macOS and `C:\Users\<you>\.cybermind\history.json` on Windows. This file never leaves your device. You can wipe it anytime with `cybermind clear`.

For maximum anonymity, route through Tor or a VPN:

```bash
# Linux — through Tor
torsocks cybermind "your question"

# Linux — through proxychains
proxychains cybermind scan target.com full
```

---

## Features

```
⚡ Interactive AI Chat        Fully responsive terminal UI with conversation memory
🔍 Scan Mode                 AI-guided network & web scanning
🕵️  Recon Mode                OSINT, subdomain enum, passive/active recon
💥 Exploit Mode              CVE guides, Metasploit modules, manual exploits
🎯 Payload Mode              msfvenom payload generation guides
🛠️  Tool Mode                 Deep-dive help for any Kali Linux tool
🔗 Research Feature          Real GitHub links, CVEs, exploit-db, resources
🧠 Conversation Memory       AI remembers context across the full session
🚫 Zero Refusals             Answers all cybersecurity questions
📜 Local Chat History        Saved only on your machine, never uploaded
🔒 Zero Data Collection      No logs, no accounts, no tracking
🔄 9 AI Providers            Parallel execution, auto-fallback, never fails
🌐 Tor/VPN Support           Full anonymity compatible
🪟 Windows Support           Works natively on Windows
🐧 Linux/Kali Support        Built for Kali Linux professionals
```

---

## Usage

### Interactive Chat Mode

```bash
cybermind
```

### Scan Mode

```bash
cybermind scan 192.168.1.1 full
cybermind scan example.com subdomain
cybermind scan 10.0.0.0/24 network
cybermind scan target.com ad
```

Scan types: `quick` `full` `stealth` `web` `vuln` `subdomain` `network` `ad`

### Recon Mode

```bash
cybermind recon target.com osint
cybermind recon example.com subdomain
cybermind recon 192.168.1.0/24 passive
```

Recon types: `passive` `active` `subdomain` `osint` `web` `network`

### Exploit Mode

```bash
cybermind exploit CVE-2021-44228 10.0.0.1
cybermind exploit CVE-2017-0144 192.168.1.100
cybermind exploit "apache struts"
```

### Payload Mode

```bash
cybermind payload windows x64
cybermind payload linux x86
cybermind payload android
```

### Tool Mode

```bash
cybermind tool sqlmap "find SQLi in login form"
cybermind tool nmap "scan for SMB vulnerabilities"
cybermind tool hashcat "crack NTLM hashes"
cybermind tool bloodhound "find paths to domain admin"
```

### Research — Get Links and Resources

```bash
cybermind "give me github links for pentesting tools"
cybermind "CVE-2021-44228 exploit links"
cybermind "best wordlists for password cracking"
```

### Direct Prompt

```bash
cybermind "how to crack WPA2 with aircrack-ng"
cybermind "kerberoasting step by step"
cybermind "bypass UAC on Windows 10"
```

### History and Utilities

```bash
cybermind history      # view saved conversations
cybermind clear        # wipe local history
cybermind help         # show all commands
cybermind --version    # show version
```

---

## Build Options

```bash
make build          # build for current OS
make build-linux    # build for Kali Linux amd64
make build-windows  # build for Windows amd64
make build-all      # all platforms
make install        # install to /usr/local/bin (Linux)
make clean          # remove build artifacts
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Support

If CyberMind helped you, consider buying me a coffee.

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

*CyberMind — AI cybersecurity CLI | Kali Linux AI assistant | Windows hacking tool | Ethical hacking AI | Penetration testing CLI | Open source hacking tool | AI pentest assistant | Bug bounty AI*

</div>
