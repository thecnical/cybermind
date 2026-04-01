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

### ⚡ AI-Powered Cybersecurity CLI — Built for Kali Linux

[![Version](https://img.shields.io/badge/version-2.0.0-00FFFF?style=for-the-badge)](https://github.com/thecnical/cybermind)
[![License](https://img.shields.io/badge/license-MIT-8A2BE2?style=for-the-badge)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-Ready-268BEE?style=for-the-badge&logo=kalilinux&logoColor=white)](https://kali.org)

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/chandanpandit)

*Created by [Chandan Pandey](https://github.com/thecnical)*

<br/>

</div>

---

## What is CyberMind?

CyberMind is a terminal-based AI assistant built specifically for cybersecurity professionals, penetration testers, CTF players, and security researchers. It brings the power of multiple large language models directly into your Kali Linux terminal — no browser, no GUI, no distractions. You type a question or a command, and CyberMind responds with real, working, copy-paste-ready cybersecurity commands and techniques.

The tool is built in Go, which means it compiles to a single binary with zero runtime dependencies. You drop it on any Linux machine and it just works. The interactive mode gives you a full terminal UI with a typing animation, spinner, and chat history. The command mode lets you run targeted operations like scan guides, recon pipelines, exploitation walkthroughs, and payload generation — all from a single command in your terminal.

CyberMind is not a toy. It knows nmap, metasploit, sqlmap, hashcat, bloodhound, impacket, aircrack-ng, and over a hundred other Kali tools deeply. When you ask it how to enumerate Active Directory, it gives you the exact BloodHound and Impacket commands. When you ask about a CVE, it gives you the Metasploit module, the manual exploit path, and the post-exploitation steps. This is the tool you open when you're on an engagement and need a fast, accurate answer without leaving your terminal.

---

## Why CyberMind?

Most AI tools require you to open a browser, log in, and deal with a web interface that wasn't designed for security work. CyberMind lives in your terminal where you already are. It understands the context of Kali Linux, knows the tools you're using, and gives you answers formatted for immediate use — not generic explanations padded with disclaimers.

The backend runs multiple AI providers in parallel and returns the fastest valid response. This means even if one provider is slow or down, you still get an answer in seconds. The system is designed to never fail silently — it tries every available model before giving up, and it tells you exactly what happened if something goes wrong.

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

# Install globally on Linux
sudo mv cybermind /usr/local/bin/
```

### Windows

```powershell
cd cli
go build -ldflags="-X main.Version=2.0.0" -o cybermind.exe .
.\cybermind.exe
```

### Requirements

You need Go 1.21 or higher installed. Download it from [go.dev/dl](https://go.dev/dl) if you don't have it. On Kali Linux you can also install it with `apt install golang`. No other runtime dependencies are needed for the CLI — it's a single compiled binary.

---

## Backend Connection

CyberMind CLI connects to a hosted backend API that handles all AI routing. By default, the CLI points to the live hosted backend, so it works out of the box without any configuration. You just build the binary and run it.

If you want to run the backend locally for development or self-hosting, set the `CYBERMIND_API` environment variable to your local server address:

```bash
export CYBERMIND_API=http://localhost:3000
cybermind
```

For permanent local setup, add that export to your `~/.bashrc` or `~/.zshrc`. Without that variable set, the CLI automatically uses the hosted production backend.

---

## Usage

### Interactive Chat Mode

Running `cybermind` with no arguments launches the full interactive terminal UI. You get a styled interface with a text input, a loading spinner while the AI thinks, and a typing animation as the response appears character by character. Press `Enter` to send your message and `Ctrl+C` to exit. Every conversation is automatically saved to your local history file.

```bash
cybermind
```

### Scan Mode

The scan command generates a complete, step-by-step scanning guide for any target. You specify the target (IP, domain, or subnet) and optionally a scan type. The AI returns exact commands with all flags explained, what to look for in the output, and what to do next. Available scan types are `quick` for a fast top-port scan, `full` for a comprehensive all-port scan with scripts and OS detection, `stealth` for low-noise SYN scanning with slow timing to avoid detection, `web` for web application scanning with nikto and directory bruteforce, `vuln` for vulnerability detection using nmap scripts and nuclei, `subdomain` for a full subdomain enumeration pipeline, `network` for subnet discovery and host mapping, and `ad` for Active Directory enumeration.

```bash
cybermind scan 192.168.1.1 full
cybermind scan example.com subdomain
cybermind scan 10.0.0.0/24 network
```

### Recon Mode

The recon command builds a complete reconnaissance guide tailored to your target and chosen methodology. Recon types include `passive` for zero-contact OSINT using Shodan, Google dorks, whois, and certificate transparency logs, `active` for direct scanning pipelines, `subdomain` for a multi-tool subdomain enumeration workflow, `osint` for a full open-source intelligence investigation covering emails, employees, leaked credentials, and infrastructure, `web` for technology fingerprinting and endpoint discovery, and `network` for topology mapping and service banner grabbing.

```bash
cybermind recon target.com osint
cybermind recon example.com subdomain
cybermind recon 192.168.1.0/24 network
```

### Exploit Mode

The exploit command generates a complete exploitation guide for a specific CVE or service. Give it a CVE number and optionally a target IP, and it returns the vulnerability details, affected versions, the Metasploit module path, manual exploit commands, and post-exploitation steps. You can also pass a service name instead of a CVE for a broader exploitation overview.

```bash
cybermind exploit CVE-2021-44228 10.0.0.1
cybermind exploit CVE-2017-0144 192.168.1.100
cybermind exploit "apache struts"
```

### Payload Mode

The payload command generates a complete msfvenom payload creation guide including the exact command with all flags, how to set up the listener in Metasploit, delivery methods, and basic AV evasion tips. Specify the target OS and optionally the architecture.

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
cybermind history      # view all saved conversations
cybermind clear        # wipe local history
cybermind help         # show all commands
cybermind --version    # show version
```

---

## Chat History

Every conversation you have in interactive mode is automatically saved to a local JSON file on your machine. Nothing is sent to any external storage — your queries and responses stay on your device. The history file lives at `~/.cybermind/history.json` on Linux and macOS, and at `C:\Users\<you>\.cybermind\history.json` on Windows. The directory is created automatically on first run. You can view your history with `cybermind history` and wipe it with `cybermind clear`.

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

## Project Structure

```
cybermind/
├── cli/
│   ├── main.go          # Entry point, all commands, banner
│   ├── go.mod           # Go module definition
│   ├── api/
│   │   └── client.go    # HTTP client connecting to backend
│   ├── ui/
│   │   ├── model.go     # Bubble Tea state machine and logic
│   │   ├── view.go      # Terminal UI renderer
│   │   └── styles.go    # Lipgloss color and style definitions
│   └── storage/
│       ├── history.go   # Chat history read/write/display
│       └── file.go      # Cross-platform file path handling
├── install.sh           # One-command Kali Linux installer
├── Makefile             # Build and install commands
├── VERSION              # Current version number
├── LICENSE              # MIT License
├── CONTRIBUTING.md      # How to contribute
├── CHANGELOG.md         # Version history
└── README.md
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

</div>
