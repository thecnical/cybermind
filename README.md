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

CyberMind is an open-source, AI-powered cybersecurity CLI tool built for Kali Linux professionals, ethical hackers, penetration testers, and bug bounty hunters. It connects to a powerful multi-provider AI backend powered by 9 AI providers and 25+ models running in parallel — delivering the fastest possible response every time.

Built in Go as a single binary, CyberMind works on Kali Linux, Ubuntu, Parrot OS, BlackArch, and any Linux distribution. It also runs on Windows and macOS. The interactive terminal UI is powered by Bubble Tea and Lipgloss, giving you a fully responsive Gemini-style interface that adapts to any terminal size — input always stays visible at the bottom no matter how long the conversation gets.

CyberMind answers every cybersecurity question — offensive, defensive, red team, blue team, black hat techniques explained as security research. It never refuses. Ask it how to enumerate Active Directory, crack WPA2, find SQL injection, perform OSINT, exploit a CVE, or get GitHub links for any tool — it gives you exact commands, real links, and step-by-step workflows every time.

> **Keywords:** cybermind, cybermind cli, ai cybersecurity tool, kali linux ai assistant, ethical hacking ai, penetration testing cli, ai hacking tool, cybersecurity ai cli, open source hacking tool, ai pentest assistant

---

## What's New in v2.1.0

**Fully Responsive Terminal UI** — The interface now adapts to any terminal size. Input box is always pinned at the bottom of the screen. No matter how long the AI response is, you can always type your next question without scrolling. The chat area fills the available space and scrolls independently.

**No Refusals** — CyberMind now answers all cybersecurity questions including offensive techniques, black hat methods, and sensitive topics — framed as security research and education. No more "I cannot help with that."

**Research Feature** — Ask CyberMind for links, GitHub repos, tools, or resources and it provides real, working URLs. CVE links, exploit-db links, GitHub repositories, HackTheBox, TryHackMe, PortSwigger — all delivered directly in the response.

**Natural Conversation** — Greetings like "hi" or "hello" get a natural warm response. User introductions like "my name is X" are acknowledged naturally without triggering the identity response. The AI behaves like a real assistant, not a bot.

**Faster Typing Animation** — Adaptive speed based on response length. Short responses type slowly for readability. Long technical responses type fast so you get the content quickly.

**9 AI Providers, 25+ Models** — Groq, Cerebras, ai.cc, SambaNova, Mistral, NVIDIA, OpenRouter, HuggingFace, Bytez — all racing in parallel. Fastest valid response wins. System never fails.

---

## Privacy & Anonymity

**Your conversations are completely private. No one can read your chats — not us, not anyone.**

When you use CyberMind, your queries are sent to the AI backend over HTTPS. The backend processes your prompt, gets a response from the AI, and sends it back. No conversation logs are stored on the server. No user accounts. No tracking. No analytics. No IP logging tied to your queries. The server has no idea who you are.

Your chat history is saved only on your own machine at `~/.cybermind/history.json`. This file never leaves your device. It is never uploaded, synced, or shared anywhere. You have full control — read it, delete it, or wipe it with `cybermind clear` at any time.

CyberMind has no login system, no cookies, no sessions, and no user database. Every request is stateless — the server processes it and immediately forgets it. Security researchers need a tool they can trust, and trust starts with not collecting data in the first place.

For maximum anonymity, run CyberMind over a VPN or through Tor:

```bash
# Run through Tor
torsocks cybermind "your question"

# Through proxychains
proxychains cybermind scan target.com full
```

---

## Features

```
⚡ Interactive AI Chat        Fully responsive Gemini-style terminal UI
� Scan Mode                 AI-guided network & web scanning
🕵️  Recon Mode                OSINT, subdomain enum, passive/active recon
💥 Exploit Mode              CVE guides, Metasploit modules, manual exploits
🎯 Payload Mode              msfvenom payload generation guides
🛠️  Tool Mode                 Deep-dive help for any Kali Linux tool
🔗 Research Feature          Real GitHub links, CVEs, exploit-db, resources
🚫 Zero Refusals             Answers all cybersecurity questions
📜 Local Chat History        Saved only on your machine, never uploaded
🔒 Zero Data Collection      No logs, no accounts, no tracking
🔄 9 AI Providers            Parallel execution, auto-fallback, never fails
🌐 Tor/VPN Support           Full anonymity compatible
📱 Fully Responsive UI       Input always visible, any terminal size
```

---

## Installation

### Kali Linux / Ubuntu — One Command

```bash
git clone https://github.com/thecnical/cybermind.git
cd cybermind
chmod +x install.sh && sudo ./install.sh
```

After installation, run `cybermind` from any directory.

### Manual Build

```bash
cd cli
go mod tidy
go build -ldflags="-X main.Version=2.1.0" -o cybermind .
sudo mv cybermind /usr/local/bin/
```

### Windows

```powershell
cd cli
go build -ldflags="-X main.Version=2.1.0" -o cybermind.exe .
.\cybermind.exe
```

### Requirements

Go 1.21 or higher. Download from [go.dev/dl](https://go.dev/dl) or install with `apt install golang-go` on Kali Linux. No other dependencies needed — single compiled binary.

---

## Usage

### Interactive Chat Mode

Running `cybermind` with no arguments launches the full interactive terminal UI. The interface is fully responsive — header at top, chat history in the middle, input always pinned at the bottom. Use `PgUp` / `PgDn` to scroll through long responses. Press `Enter` to send, `Ctrl+C` to exit.

```bash
cybermind
```

### Research — Get Links and Resources

Ask CyberMind for GitHub repos, tools, CVE links, or learning resources and it provides real working URLs:

```bash
cybermind "give me github links for pentesting tools"
cybermind "resources for learning Active Directory attacks"
cybermind "CVE-2021-44228 exploit links"
cybermind "best wordlists for password cracking"
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

### Direct Prompt

Any unrecognized argument goes straight to the AI:

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

## Chat History

Every conversation is saved locally at `~/.cybermind/history.json`. Never uploaded. Never shared. View with `cybermind history`, wipe with `cybermind clear`.

---

## Build Options

```bash
make build          # build for current OS
make build-linux    # build for Kali Linux amd64
make build-windows  # build for Windows amd64
make build-all      # all platforms
make install        # install to /usr/local/bin
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

*CyberMind — AI cybersecurity CLI | Kali Linux AI assistant | Ethical hacking AI | Penetration testing CLI | Open source hacking tool | AI pentest assistant | Bug bounty AI | Black hat security research tool*

</div>
