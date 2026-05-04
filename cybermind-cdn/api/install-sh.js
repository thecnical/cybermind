// Serves install.sh — EMBEDDED directly (no GitHub proxy = no cache issues)
// Version: 5.4.6
// Last updated: 2026-05-05
// IMPORTANT: This file IS the install script served at cybermindcli1.vercel.app/install.sh
// Update this file whenever install.sh changes in the root repo.

module.exports = (req, res) => {
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("X-CyberMind-Version", "5.4.6");

  const script = `#!/bin/bash
# CyberMind CLI Installer v5.4.6 — Kali Linux / Ubuntu / Debian / macOS
# Usage: curl -sL https://cybermindcli1.vercel.app/install.sh | bash
# Usage: CYBERMIND_KEY=cp_live_xxx curl -sL https://cybermindcli1.vercel.app/install.sh | bash

set -e

export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
export GIT_TERMINAL_PROMPT=0
export GIT_ASKPASS=echo

CYAN='\\033[0;36m'
GREEN='\\033[0;32m'
RED='\\033[0;31m'
YELLOW='\\033[1;33m'
DIM='\\033[0;90m'
BOLD='\\033[1m'
NC='\\033[0m'

GITHUB_RAW="https://raw.githubusercontent.com/thecnical/cybermind/main/cli"
INSTALL_PATH="/usr/local/bin/cybermind"
CBM_PATH="/usr/local/bin/cbm"
VERSION="5.4.6"

echo -e "\\${CYAN}"
cat << 'BANNER'
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ███╗██╗███╗   ██╗██████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗ ████║██║████╗  ██║██╔══██╗
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔████╔██║██║██╔██╗ ██║██║  ██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╔╝██║██║██║╚██╗██║██║  ██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚═╝ ██║██║██║ ╚████║██████╔╝
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝
BANNER
echo -e "\\${NC}"
echo -e "\\${BOLD}\\${GREEN}⚡ CyberMind CLI Installer v\\${VERSION}\\${NC}"
echo -e "\\${DIM}   AI-Powered Bug Bounty & Recon Platform\\${NC}"
echo ""

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# ── Detect binary name ────────────────────────────────────────────────────────
case "\\$OS-\\$ARCH" in
    linux-x86_64)   BINARY="cybermind-linux-amd64" ;;
    linux-aarch64)  BINARY="cybermind-linux-arm64" ;;
    linux-arm64)    BINARY="cybermind-linux-arm64" ;;
    darwin-x86_64)  BINARY="cybermind-darwin-amd64" ;;
    darwin-arm64)   BINARY="cybermind-darwin-arm64" ;;
    *)
        echo -e "\\${YELLOW}[!] Unsupported: \\$OS/\\$ARCH — building from source\\${NC}"
        BINARY=""
        ;;
esac

if [ "\\$OS" != "linux" ]; then
    echo -e "\\${YELLOW}[!] \\$OS detected. Recon/hunt tools are Linux-only.\\${NC}"
    echo -e "\\${DIM}    AI chat + /scan /osint /cve /payload work on all platforms.\\${NC}"
fi

# ── Step 1: Download pre-built binary ────────────────────────────────────────
if [ -n "\\$BINARY" ]; then
    echo -e "\\${YELLOW}[*] Downloading CyberMind CLI v\\${VERSION} (\\${BINARY})...\\${NC}"
    BINARY_URL="\\${GITHUB_RAW}/\\${BINARY}"
    TMP_BIN="/tmp/cybermind-install-\\$\\$"

    if command -v curl &>/dev/null; then
        HTTP_CODE=\\$(curl -fsSL -w "%{http_code}" -o "\\$TMP_BIN" "\\$BINARY_URL" 2>/dev/null)
    elif command -v wget &>/dev/null; then
        wget -q -O "\\$TMP_BIN" "\\$BINARY_URL" 2>/dev/null && HTTP_CODE="200" || HTTP_CODE="404"
    else
        echo -e "\\${RED}[!] curl or wget required\\${NC}"; exit 1
    fi

    FILE_SIZE=\\$(stat -c%s "\\$TMP_BIN" 2>/dev/null || stat -f%z "\\$TMP_BIN" 2>/dev/null || echo 0)
    if [ "\\$HTTP_CODE" = "200" ] && [ -f "\\$TMP_BIN" ] && [ "\\$FILE_SIZE" -gt 1048576 ]; then
        chmod +x "\\$TMP_BIN"
        if [ "\\$OS" = "darwin" ]; then
            cp "\\$TMP_BIN" "\\$INSTALL_PATH" 2>/dev/null || sudo cp "\\$TMP_BIN" "\\$INSTALL_PATH"
            cp "\\$INSTALL_PATH" "\\$CBM_PATH" 2>/dev/null || sudo cp "\\$INSTALL_PATH" "\\$CBM_PATH"
        else
            sudo cp "\\$TMP_BIN" "\\$INSTALL_PATH"
            sudo chmod +x "\\$INSTALL_PATH"
            sudo cp "\\$INSTALL_PATH" "\\$CBM_PATH"
            sudo chmod +x "\\$CBM_PATH"
        fi
        rm -f "\\$TMP_BIN"
        echo -e "\\${GREEN}[✓] Binary installed: \\$INSTALL_PATH\\${NC}"
        echo -e "\\${GREEN}[✓] Alias installed:  \\$CBM_PATH\\${NC}"
    else
        rm -f "\\$TMP_BIN"
        echo -e "\\${YELLOW}[!] Binary download failed (HTTP \\$HTTP_CODE, size \\${FILE_SIZE}B). Building from source...\\${NC}"
        BINARY=""
    fi
fi

# ── Step 2: Build from source (fallback) ─────────────────────────────────────
if [ -z "\\$BINARY" ] || ! command -v cybermind &>/dev/null; then
    echo -e "\\${YELLOW}[*] Building from source (requires Go)...\\${NC}"
    if ! command -v go &>/dev/null; then
        echo -e "\\${YELLOW}[!] Installing Go 1.22...\\${NC}"
        wget -q "https://go.dev/dl/go1.22.0.linux-amd64.tar.gz" -O "/tmp/go.tar.gz"
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf "/tmp/go.tar.gz"
        rm "/tmp/go.tar.gz"
        export PATH=\\$PATH:/usr/local/go/bin
    fi
    REPO_DIR="/tmp/cybermind-src-\\$\\$"
    GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=echo git clone --depth=1 https://github.com/thecnical/cybermind.git "\\$REPO_DIR" 2>/dev/null
    cd "\\$REPO_DIR/cli"
    go mod tidy -q
    CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=\\${VERSION}" -o /tmp/cybermind-built .
    chmod +x /tmp/cybermind-built
    sudo cp /tmp/cybermind-built "\\$INSTALL_PATH"
    sudo cp /tmp/cybermind-built "\\$CBM_PATH"
    rm -rf "\\$REPO_DIR" /tmp/cybermind-built
    echo -e "\\${GREEN}[✓] Built and installed from source\\${NC}"
fi

# ── Step 3: Save API key ──────────────────────────────────────────────────────
if [ -n "\\$CYBERMIND_KEY" ]; then
    mkdir -p "\\$HOME/.cybermind"
    chmod 700 "\\$HOME/.cybermind"
    printf '{"key":"%s"}' "\\$CYBERMIND_KEY" > "\\$HOME/.cybermind/config.json"
    chmod 600 "\\$HOME/.cybermind/config.json"
    echo -e "\\${GREEN}[✓] API key saved to ~/.cybermind/config.json\\${NC}"
fi

# ── Step 4: PATH ──────────────────────────────────────────────────────────────
export PATH=\\$PATH:/usr/local/bin:\\$HOME/go/bin:/usr/local/go/bin
for profile in ~/.bashrc ~/.zshrc ~/.profile /root/.bashrc /root/.zshrc; do
    [ -f "\\$profile" ] && ! grep -q "go/bin" "\\$profile" && \\
        echo 'export PATH=\\$PATH:\\$HOME/go/bin:/usr/local/go/bin' >> "\\$profile" || true
done

# ── Step 5: Install tools (Linux only) ───────────────────────────────────────
if [ "\\$OS" = "linux" ]; then
    echo ""
    echo -e "\\${BOLD}\\${YELLOW}[*] Installing recon + hunt tools (v\\${VERSION})...\\${NC}"
    echo -e "\\${DIM}    Full install: sudo cybermind /doctor\\${NC}"
    echo ""

    sudo apt-get update -qq 2>/dev/null || true
    sudo apt-get install -y nmap masscan zmap ffuf feroxbuster gobuster nikto sqlmap commix \\
        wpscan libpcap-dev python3-pip python3-venv pipx git curl wget whois dnsutils \\
        build-essential amass apktool -qq 2>/dev/null || true

    symlink_go_tool() {
        local bin="\\$1"
        for gobin in "\\$HOME/go/bin" "/root/go/bin"; do
            [ -f "\\$gobin/\\$bin" ] && sudo ln -sf "\\$gobin/\\$bin" "/usr/local/bin/\\$bin" 2>/dev/null && return
        done
    }

    GO_TOOLS=(
        "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
        "httpx:github.com/projectdiscovery/httpx/cmd/httpx"
        "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
        "dnsx:github.com/projectdiscovery/dnsx/cmd/dnsx"
        "naabu:github.com/projectdiscovery/naabu/v2/cmd/naabu"
        "katana:github.com/projectdiscovery/katana/cmd/katana"
        "tlsx:github.com/projectdiscovery/tlsx/cmd/tlsx"
        "urlfinder:github.com/projectdiscovery/urlfinder/cmd/urlfinder"
        "gau:github.com/lc/gau/v2/cmd/gau"
        "waybackurls:github.com/tomnomnom/waybackurls"
        "hakrawler:github.com/hakluke/hakrawler"
        "dalfox:github.com/hahwul/dalfox/v2"
        "kxss:github.com/Emoe/kxss"
        "gospider:github.com/jaeles-project/gospider"
        "subjs:github.com/lc/subjs"
        "httprobe:github.com/tomnomnom/httprobe"
        "gf:github.com/tomnomnom/gf"
        "interactsh-client:github.com/projectdiscovery/interactsh/cmd/interactsh-client"
        "puredns:github.com/d3mondev/puredns/v2"
        "cariddi:github.com/edoardottt/cariddi/cmd/cariddi"
        "bxss:github.com/ethicalhackingplayground/bxss/v2/cmd/bxss"
        "mapcidr:github.com/projectdiscovery/mapcidr/cmd/mapcidr"
        "cdncheck:github.com/projectdiscovery/cdncheck/cmd/cdncheck"
        "asnmap:github.com/projectdiscovery/asnmap/cmd/asnmap"
        "uncover:github.com/projectdiscovery/uncover/cmd/uncover"
        "notify:github.com/projectdiscovery/notify/cmd/notify"
        "alterx:github.com/projectdiscovery/alterx/cmd/alterx"
        "shuffledns:github.com/projectdiscovery/shuffledns/cmd/shuffledns"
        "gowitness:github.com/sensepost/gowitness"
        "jsluice:github.com/BishopFox/jsluice/cmd/jsluice"
        "sourcemapper:github.com/denandz/sourcemapper"
        "github-subdomains:github.com/gwen001/github-subdomains"
        "webanalyze:github.com/rverton/webanalyze/cmd/webanalyze"
        "favirecon:github.com/edoardottt/favirecon/cmd/favirecon"
        "smap:github.com/s0md3v/smap/cmd/smap"
        "dnstake:github.com/pwnesia/dnstake/cmd/dnstake"
        "second-order:github.com/mhmdiaa/second-order"
        "misconfig-mapper:github.com/intigriti/misconfig-mapper/cmd/misconfig-mapper"
    )
    for entry in "\\${GO_TOOLS[@]}"; do
        bin="\\${entry%%:*}"; module="\\${entry##*:}"
        command -v "\\$bin" &>/dev/null || (go install "\\${module}@latest" 2>/dev/null && symlink_go_tool "\\$bin") || true
    done

    export PIPX_BIN_DIR=/usr/local/bin
    export PIPX_HOME=/opt/pipx
    pip3 install setuptools --break-system-packages -q 2>/dev/null || true
    for tool in shodan h8mail arjun wafw00f waymore ghauri semgrep pip-audit uro swaggerspy; do
        command -v "\\$tool" &>/dev/null || pipx install "\\$tool" 2>/dev/null || \\
            pip3 install "\\$tool" --break-system-packages -q 2>/dev/null || true
    done

    install_python_git_tool() {
        local name="\\$1" repo="\\$2" dir="\\$3" script="\\$4"
        command -v "\\$name" &>/dev/null && return 0
        GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=echo git clone --depth=1 "\\$repo" "\\$dir" 2>/dev/null || return 1
        python3 -m venv "\\$dir/.venv" 2>/dev/null
        "\\$dir/.venv/bin/pip" install --upgrade pip -q 2>/dev/null
        [ -f "\\$dir/requirements.txt" ] && "\\$dir/.venv/bin/pip" install -r "\\$dir/requirements.txt" -q 2>/dev/null || true
        printf '#!/bin/bash\\nexec "%s/.venv/bin/python3" "%s/%s" "\\$@"\\n' "\\$dir" "\\$dir" "\\$script" | sudo tee "/usr/local/bin/\\$name" > /dev/null
        sudo chmod +x "/usr/local/bin/\\$name"
    }

    install_python_git_tool "paramspider" "https://github.com/devanshbatham/ParamSpider" "/opt/ParamSpider" "paramspider.py" 2>/dev/null || true
    install_python_git_tool "xsstrike"    "https://github.com/s0md3v/XSStrike"           "/opt/XSStrike"    "xsstrike.py"    2>/dev/null || true
    install_python_git_tool "ssrfmap"     "https://github.com/swisskyrepo/SSRFmap"        "/opt/ssrfmap"     "ssrfmap.py"     2>/dev/null || true
    install_python_git_tool "corsy"       "https://github.com/s0md3v/Corsy"               "/opt/corsy"       "corsy.py"       2>/dev/null || true
    install_python_git_tool "smuggler"    "https://github.com/defparam/smuggler"           "/opt/smuggler"    "smuggler.py"    2>/dev/null || true
    install_python_git_tool "jwt_tool"    "https://github.com/ticarpi/jwt_tool"            "/opt/jwt_tool"    "jwt_tool.py"    2>/dev/null || true
    install_python_git_tool "liffy"       "https://github.com/mzfr/liffy"                  "/opt/liffy"       "liffy.py"       2>/dev/null || true
    install_python_git_tool "gopherus"    "https://github.com/tarunkant/Gopherus"          "/opt/gopherus"    "gopherus.py"    2>/dev/null || true
    install_python_git_tool "secretfinder" "https://github.com/m4ll0k/SecretFinder"       "/opt/secretfinder" "SecretFinder.py" 2>/dev/null || true
    install_python_git_tool "linkfinder"  "https://github.com/GerbenJavado/LinkFinder"    "/opt/linkfinder"  "linkfinder.py"  2>/dev/null || true
    install_python_git_tool "cmseek"      "https://github.com/Tuhinshubhra/CMSeeK"        "/opt/cmseek"      "cmseek.py"      2>/dev/null || true

    command -v trufflehog &>/dev/null || \\
        curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \\
        | sh -s -- -b /usr/local/bin 2>/dev/null || true

    command -v gf &>/dev/null && [ ! -d "\\$HOME/.gf" ] && \\
        GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=echo git clone --depth=1 https://github.com/1ndianl33t/Gf-Patterns "\\$HOME/.gf" 2>/dev/null || true

    command -v nuclei &>/dev/null && nuclei -update-templates 2>/dev/null || true

    command -v retire &>/dev/null || npm install -g retire 2>/dev/null || true
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "\\${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\${NC}"
echo -e "\\${BOLD}\\${GREEN}⚡ CyberMind CLI v\\${VERSION} installed!\\${NC}"
echo ""
echo -e "  \\${CYAN}Verify:     \\${NC} cybermind --version"
echo -e "  \\${CYAN}AI Chat:    \\${NC} cybermind"
echo -e "  \\${CYAN}Doctor:     \\${NC} sudo cybermind /doctor"
if [ "\\$OS" = "linux" ]; then
echo -e "  \\${CYAN}OMEGA Plan: \\${NC} sudo cybermind /plan example.com"
echo -e "  \\${CYAN}Recon:      \\${NC} sudo cybermind /recon example.com"
echo -e "  \\${CYAN}Hunt:       \\${NC} sudo cybermind /hunt example.com"
fi
echo -e "  \\${CYAN}Scan:       \\${NC} cybermind /scan example.com"
echo -e "  \\${CYAN}CVE:        \\${NC} cybermind /cve CVE-2024-1234"
echo -e "  \\${CYAN}Feedback:   \\${NC} cybermind /feedback"
echo ""
echo -e "  \\${BOLD}\\${YELLOW}NEW in v5.4.6:\\${NC}"
echo -e "  \\${DIM}  • /scan: parallel TCP dial — 8s not 30s+ on Windows\\${NC}"
echo -e "  \\${DIM}  • /report: anti-hallucination — only real session findings\\${NC}"
echo -e "  \\${DIM}  • /payload: correct OS-specific code (no Linux paths in Windows payloads)\\${NC}"
echo -e "  \\${DIM}  • AI chat: Windows-native tools (Burp/ZAP/PowerShell) not 'use WSL'\\${NC}"
echo -e "  \\${DIM}  • /feedback: report bad AI responses directly from CLI\\${NC}"
echo -e "  \\${DIM}  • Markdown rendering: no more **bold** markers in terminal\\${NC}"
echo ""
if [ -n "\\$CYBERMIND_KEY" ]; then
    echo -e "  \\${GREEN}✓ API key saved — run: cybermind whoami\\${NC}"
    echo ""
fi
echo -e "\\${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\${NC}"
echo ""
`;

  res.send(script);
};
