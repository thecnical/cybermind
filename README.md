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

### ⚡ CyberMind — AI-Powered Cybersecurity CLI Tool for Kali Linux

[![Version](https://img.shields.io/badge/version-2.1.0-00FFFF?style=for-the-badge)](https://github.com/thecnical/cybermind)
[![License](https://img.shields.io/badge/license-MIT-8A2BE2?style=for-the-badge)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-Ready-268BEE?style=for-the-badge&logo=kalilinux&logoColor=white)](https://kali.org)
[![Privacy](https://img.shields.io/badge/chat-anonymous-00FF00?style=for-the-badge&logo=tor&logoColor=black)](#privacy--anonymity)
[![Stars](https://img.shields.io/github/stars/thecnical/cybermind?style=for-the-badge&color=yellow)](https://github.com/thecnical/cybermind/stargazers)

[![Buy Me A Coffee](https://img.shields.io/badge/☕%20Buy%20Me%20A%20Coffee-chandanpandit-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/chandanpandit)

*Created by [Chandan Pandey](https://github.com/thecnical)*

**CyberMind is an open-source AI cybersecurity assistant CLI tool built for Kali Linux, penetration testers, ethical hackers, and bug bounty hunters.**

<br/>

</div>

---

## What is CyberMind?

CyberMind is an open-source, AI-powered cybersecurity CLI tool built for Kali Linux professionals, ethical hackers, penetration testers, and bug bounty hunters. It connects to a powerful multi-provider AI backend and delivers real, working, copy-paste-ready cybersecurity commands and techniques directly in your terminal — no browser, no GUI, no distractions.

Built in Go as a single binary, CyberMind works on Kali Linux, Ubuntu, Parrot OS, BlackArch, and any Linux distribution. It also runs on Windows and macOS. The interactive terminal UI is powered by Bubble Tea and Lipgloss, giving you a clean hacker-style interface with typing animations, a loading spinner, and scrollable chat history.

CyberMind knows over 100 Kali Linux tools deeply — nmap, metasploit, sqlmap, hashcat, bloodhound, impacket, aircrack-ng, burpsuite, nuclei, subfinder, and many more. Ask it how to enumerate Active Directory, crack WPA2, find SQL injection, perform OSINT, or exploit a CVE — it gives you exact commands, flags, and step-by-step workflows every time.

> **Keywords:** cybermind, cybermind cli, ai cybersecurity tool, kali linux ai assistant, ethical hacking ai, penetration testing cli, ai hacking tool, cybersecurity ai cli, open source hacking tool, ai pentest assistant

---

## Privacy & Anonymity

**Your conversations are completely private. No one can read your chats — not us, not anyone.**

When you use CyberMind, your queries are sent to the AI backend over HTTPS — the same encryption standard used by banks and governments. The backend processes your prompt, gets a response from the AI, and sends it back. That's it. No conversation logs are stored on the server. No user accounts. No tracking. No analytics. No IP logging tied to your queries. The server has no idea who you are.

Your chat history is saved **only on your own machine** at `~/.cybermind/history.json`. This file never leaves your device. It is never uploaded, synced, or shared anywhere. You have full control over it — you can read it, delete it, or wipe it with `cybermind clear` at any time.

CyberMind has no login system, no cookies, no sessions, and no user database. There is nothing to breach because there is nothing stored. Every request is stateless — the server processes it and immediately forgets it. This is by design. Security researchers need a tool they can trust, and trust starts with not collecting data in the first place.

If you want maximum anonymity, run CyberMind over a VPN or through Tor. The CLI works over any network connection, so routing it through `proxychains` or `torsocks` is fully supported.

```bash
# Run through Tor for maximum anonymity
torsocks cybermind "your question"

# Or through proxychains
proxychains cybermind scan target.com full
```

---

## Features

```
⚡ Interactive AI Chat      Ask anything, get real commands
🔍 Scan Mode               AI-guided network & web scanning
🕵️  Recon Mode              OSINT, subdomain enum, passive/active recon
💥 Exploit Mode            CVE guides, service exploitation
🎯 Payload Mode            Payload generation guidance
🛠️  Tool Mode               Deep-dive help for any security tool
📜 Local Chat History      Saved only on your machine, never uploaded
🔒 Zero Data Collection    No logs, no accounts, no tracking
🔄 Auto-Fallback           Never fails — multiple AI providers
🌐 Works over Tor/VPN      Full anonymity support
```

---

## Installation

### Kali Linux / Ubuntu — One Command

The fastest way to get started on Kali Linux is the install script. It checks for Go and Node.js, installs missing dependencies, builds the CLI binary, and places it in `/usr/local/bin` so you can run `cybermind` from anywhere.

```bash
git clone https://github.com/thecnical/cybermind.git
cd cybermind
chmod +x install.sh && sudo ./install.sh
```

After installation, just run `cybermind` from any directory.

### Manual Build

If you prefer to build manually or want to customize the binary:

```bash
cd cli
go mod tidy
go build -ldflags="-X main.Version=2.0.0" -o cybermind .
sudo mv cybermind /usr/local/bin/
```

### Windows

```powershell
cd cli
go build -ldflags="-X main.Version=2.0.0" -o cybermind.exe .
.\cybermind.exe
```

### Requirements

You need Go 1.21 or higher installed. Download it from [go.dev/dl](https://go.dev/dl) if you don't have it. On Kali Linux you can also install it with `apt install golang-go`. No other runtime dependencies are needed for the CLI — it is a single compiled binary.

---

## Usage

### Interactive Chat Mode

Running `cybermind` with no arguments launches the full interactive terminal UI. You get a styled interface with a text input, a loading spinner while the AI thinks, and a typing animation as the response appears character by character. Press `Enter` to send your message and `Ctrl+C` to exit. Every conversation is automatically saved to your local history file on your machine only.

```bash
cybermind
```

### Scan Mode

The scan command generates a complete, step-by-step scanning guide for any target. You specify the target and optionally a scan type. The AI returns exact commands with all flags explained, what to look for in the output, and what to do next. Available scan types are `quick` for a fast top-port scan, `full` for a comprehensive all-port scan with scripts and OS detection, `stealth` for low-noise SYN scanning with slow timing to avoid detection, `web` for web application scanning, `vuln` for vulnerability detection, `subdomain` for a full subdomain enumeration pipeline, `network` for subnet discovery, and `ad` for Active Directory enumeration.

```bash
cybermind scan 192.168.1.1 full
cybermind scan example.com subdomain
cybermind scan 10.0.0.0/24 network
```

### Recon Mode

The recon command builds a complete reconnaissance guide tailored to your target and chosen methodology. Types include `passive` for zero-contact OSINT, `active` for direct scanning pipelines, `subdomain` for multi-tool subdomain enumeration, `osint` for a full open-source intelligence investigation, `web` for technology fingerprinting and endpoint discovery, and `network` for topology mapping.

```bash
cybermind recon target.com osint
cybermind recon example.com subdomain
cybermind recon 192.168.1.0/24 network
```

### Exploit Mode

The exploit command generates a complete exploitation guide for a specific CVE or service. Give it a CVE number and optionally a target IP, and it returns the vulnerability details, affected versions, the Metasploit module path, manual exploit commands, and post-exploitation steps.

```bash
cybermind exploit CVE-2021-44228 10.0.0.1
cybermind exploit CVE-2017-0144 192.168.1.100
cybermind exploit "apache struts"
```

### Payload Mode

The payload command generates a complete msfvenom payload creation guide including the exact command with all flags, how to set up the listener in Metasploit, delivery methods, and basic AV evasion tips.

```bash
cybermind payload windows x64
cybermind payload linux x86
cybermind payload android
```

### Tool Mode

The tool command gives you a deep-dive guide for any Kali Linux tool. Pass the tool name and optionally a specific task, and the AI returns the most useful commands, flags, and real-world usage examples for that exact scenario.

```bash
cybermind tool sqlmap "find SQLi in login form"
cybermind tool nmap "scan for SMB vulnerabilities"
cybermind tool hashcat "crack NTLM hashes wordlist attack"
cybermind tool bloodhound "find paths to domain admin"
```

### Direct Prompt Shortcut

Any unrecognized argument is treated as a direct question to the AI. This is the fastest way to get a quick answer without entering interactive mode.

```bash
cybermind "how to crack WPA2 with aircrack-ng"
cybermind "what is kerberoasting and how to do it"
cybermind "enumerate SMB shares on a Windows host"
```

### History and Utilities

```bash
cybermind history      # view all saved conversations (local only)
cybermind clear        # wipe local history
cybermind help         # show all commands
cybermind --version    # show version
```

---

## Chat History & Local Storage

Every conversation you have in interactive mode is automatically saved to a local JSON file on your machine. Nothing is sent to any external storage — your queries and responses stay on your device permanently. The history file lives at `~/.cybermind/history.json` on Linux and macOS. The directory is created automatically on first run. You can view your history with `cybermind history` and wipe it completely with `cybermind clear`. The file is plain JSON so you can also read, edit, or delete it manually at any time.

---

## Build Options

```bash
make build          # build for current OS
make build-linux    # build for Kali Linux / Linux amd64
make build-windows  # build for Windows amd64
make build-all      # build all platforms
make install        # build and install to /usr/local/bin (Linux)
make clean          # remove build artifacts
```

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get started, coding standards, and how to submit a pull request.

---

## Support the Project

If CyberMind has been useful in your work, research, or learning, consider buying me a coffee. It helps keep the project alive and motivates continued development.

[![Buy Me A Coffee](https://img.shields.io/badge/☕%20Buy%20Me%20A%20Coffee-chandanpandit-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/chandanpandit)

---

## License

MIT — see [LICENSE](LICENSE). Free to use, modify, and distribute.

---

## Disclaimer

CyberMind is built for authorized security research, penetration testing with written permission, CTF competitions, and cybersecurity education. Using this tool against systems you do not own or have explicit written authorization to test is illegal. The author takes no responsibility for misuse.

---

<div align="center">

Made with ⚡ by [Chandan Pandey](https://github.com/thecnical)

[GitHub](https://github.com/thecnical/cybermind) · [Buy Me A Coffee](https://buymeacoffee.com/chandanpandit)

---

*CyberMind — AI cybersecurity CLI tool | Kali Linux AI assistant | Ethical hacking AI | Penetration testing CLI | Open source hacking tool | AI pentest assistant | Bug bounty AI tool | Cybersecurity terminal tool*

</div>
