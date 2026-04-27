// Serves install.sh — EMBEDDED directly (no GitHub proxy = no cache issues)
// Version: 4.5.0
// Last updated: 2026-04-27
// IMPORTANT: This file IS the install script served at cybermindcli1.vercel.app/install.sh
// Update this file whenever install.sh changes in the root repo.

module.exports = (req, res) => {
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("X-CyberMind-Version", "4.5.0");

  const script = `#!/bin/bash
# CyberMind CLI Installer v4.5.0 — Kali Linux / Ubuntu / Debian
# Usage: curl -sL https://cybermindcli1.vercel.app/install.sh | bash
# Usage: CYBERMIND_KEY=cp_live_xxx curl -sL https://cybermindcli1.vercel.app/install.sh | bash

set -e

CYAN='\\033[0;36m'
GREEN='\\033[0;32m'
RED='\\033[0;31m'
YELLOW='\\033[1;33m'
PURPLE='\\033[0;35m'
DIM='\\033[0;90m'
BOLD='\\033[1m'
NC='\\033[0m'

GITHUB_RAW="https://raw.githubusercontent.com/thecnical/cybermind/main/cli"
INSTALL_PATH="/usr/local/bin/cybermind"
CBM_PATH="/usr/local/bin/cbm"
VERSION="4.5.0"

echo -e "\${CYAN}"
cat << 'BANNER'
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ███╗██╗███╗   ██╗██████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗ ████║██║████╗  ██║██╔══██╗
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔████╔██║██║██╔██╗ ██║██║  ██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╔╝██║██║██║╚██╗██║██║  ██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚═╝ ██║██║██║ ╚████║██████╔╝
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝
BANNER
echo -e "\${NC}"
echo -e "\${BOLD}\${GREEN}⚡ CyberMind CLI Installer v\${VERSION}\${NC}"
echo -e "\${DIM}   AI-Powered Bug Bounty & Recon Platform — Agentic Edition\${NC}"
echo ""

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "\$ARCH" in
    x86_64)  BINARY="cybermind-linux-amd64" ;;
    aarch64|arm64) BINARY="cybermind-linux-arm64" ;;
    *) echo -e "\${YELLOW}[!] Unsupported arch: \$ARCH — building from source\${NC}"; BINARY="" ;;
esac

if [ "\$OS" != "linux" ]; then
    echo -e "\${YELLOW}[!] Non-Linux OS (\$OS). Recon/hunt tools are Linux-only.\${NC}"
fi

# ── Step 1: Download binary from GitHub ──────────────────────────────────────
if [ -n "\$BINARY" ]; then
    echo -e "\${YELLOW}[*] Downloading CyberMind CLI v\${VERSION} (\${BINARY})...\${NC}"
    BINARY_URL="\${GITHUB_RAW}/\${BINARY}"
    TMP_BIN="/tmp/cybermind-install-\$\$"

    if command -v curl &>/dev/null; then
        HTTP_CODE=$(curl -fsSL -w "%{http_code}" -o "\$TMP_BIN" "\$BINARY_URL" 2>/dev/null)
    elif command -v wget &>/dev/null; then
        wget -q -O "\$TMP_BIN" "\$BINARY_URL" 2>/dev/null && HTTP_CODE="200" || HTTP_CODE="404"
    else
        echo -e "\${RED}[!] curl or wget required\${NC}"; exit 1
    fi

    FILE_SIZE=\$(stat -c%s "\$TMP_BIN" 2>/dev/null || stat -f%z "\$TMP_BIN" 2>/dev/null || echo 0)
    if [ "\$HTTP_CODE" = "200" ] && [ -f "\$TMP_BIN" ] && [ "\$FILE_SIZE" -gt 1048576 ]; then
        chmod +x "\$TMP_BIN"
        sudo cp "\$TMP_BIN" "\$INSTALL_PATH"
        sudo chmod +x "\$INSTALL_PATH"
        sudo cp "\$INSTALL_PATH" "\$CBM_PATH"
        sudo chmod +x "\$CBM_PATH"
        rm -f "\$TMP_BIN"
        echo -e "\${GREEN}[✓] Binary installed: \$INSTALL_PATH\${NC}"
        echo -e "\${GREEN}[✓] Alias installed:  \$CBM_PATH\${NC}"
    else
        rm -f "\$TMP_BIN"
        echo -e "\${YELLOW}[!] Binary download failed (HTTP \$HTTP_CODE, size \${FILE_SIZE}B). Building from source...\${NC}"
        BINARY=""
    fi
fi

# ── Step 2: Build from source (fallback) ─────────────────────────────────────
if [ -z "\$BINARY" ] || ! command -v cybermind &>/dev/null; then
    echo -e "\${YELLOW}[*] Building from source...\${NC}"
    if ! command -v go &>/dev/null; then
        echo -e "\${YELLOW}[!] Installing Go 1.22...\${NC}"
        wget -q "https://go.dev/dl/go1.22.0.linux-amd64.tar.gz" -O "/tmp/go.tar.gz"
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf "/tmp/go.tar.gz"
        rm "/tmp/go.tar.gz"
        export PATH=\$PATH:/usr/local/go/bin
    fi
    REPO_DIR="/tmp/cybermind-src-\$\$"
    git clone --depth=1 https://github.com/thecnical/cybermind.git "\$REPO_DIR" 2>/dev/null
    cd "\$REPO_DIR/cli"
    go mod tidy -q
    go build -ldflags="-s -w" -o /tmp/cybermind-built .
    chmod +x /tmp/cybermind-built
    sudo cp /tmp/cybermind-built "\$INSTALL_PATH"
    sudo cp /tmp/cybermind-built "\$CBM_PATH"
    rm -rf "\$REPO_DIR" /tmp/cybermind-built
    echo -e "\${GREEN}[✓] Built and installed from source\${NC}"
fi

# ── Step 3: Save API key ──────────────────────────────────────────────────────
if [ -n "\$CYBERMIND_KEY" ]; then
    mkdir -p "\$HOME/.cybermind"
    chmod 700 "\$HOME/.cybermind"
    printf '{"key":"%s"}' "\$CYBERMIND_KEY" > "\$HOME/.cybermind/config.json"
    chmod 600 "\$HOME/.cybermind/config.json"
    echo -e "\${GREEN}[✓] API key saved\${NC}"
fi

# ── Step 4: PATH ──────────────────────────────────────────────────────────────
export PATH=\$PATH:/usr/local/bin:\$HOME/go/bin:/usr/local/go/bin
for profile in ~/.bashrc ~/.zshrc ~/.profile /root/.bashrc /root/.zshrc; do
    [ -f "\$profile" ] && ! grep -q "go/bin" "\$profile" && \\
        echo 'export PATH=\$PATH:\$HOME/go/bin:/usr/local/go/bin' >> "\$profile" || true
done

# ── Step 5: System dependencies ──────────────────────────────────────────────
echo ""
echo -e "\${BOLD}\${YELLOW}[*] Installing tools (v4.5.0)...\${NC}"
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq 2>/dev/null || true
sudo apt-get install -y nmap masscan zmap ffuf feroxbuster gobuster nikto sqlmap commix wpscan \\
    libpcap-dev python3-pip python3-venv pipx git curl wget whois dnsutils \\
    build-essential amass apktool -qq 2>/dev/null || true

symlink_go_tool() {
    local bin="\$1"
    for gobin in "\$HOME/go/bin" "/root/go/bin"; do
        [ -f "\$gobin/\$bin" ] && sudo ln -sf "\$gobin/\$bin" "/usr/local/bin/\$bin" 2>/dev/null && return
    done
}

# ── Go tools (v4.5.0 — 30 tools) ─────────────────────────────────────────────
echo -e "\${DIM}  Installing Go tools...\${NC}"
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
    "chisel:github.com/jpillora/chisel"
    "interactsh-client:github.com/projectdiscovery/interactsh/cmd/interactsh-client"
    "puredns:github.com/d3mondev/puredns/v2"
    "cariddi:github.com/edoardottt/cariddi/cmd/cariddi"
    "bxss:github.com/ethicalhackingplayground/bxss"
    "mantra:github.com/MrEmpy/mantra"
    "mapcidr:github.com/projectdiscovery/mapcidr/cmd/mapcidr"
    "cdncheck:github.com/projectdiscovery/cdncheck/cmd/cdncheck"
    "asnmap:github.com/projectdiscovery/asnmap/cmd/asnmap"
    "uncover:github.com/projectdiscovery/uncover/cmd/uncover"
    "notify:github.com/projectdiscovery/notify/cmd/notify"
    "alterx:github.com/projectdiscovery/alterx/cmd/alterx"
    "shuffledns:github.com/projectdiscovery/shuffledns/cmd/shuffledns"
    "ligolo-ng:github.com/nicocha30/ligolo-ng/cmd/proxy"
)
for entry in "\${GO_TOOLS[@]}"; do
    bin="\${entry%%:*}"; module="\${entry##*:}"
    command -v "\$bin" &>/dev/null || (go install "\${module}@latest" 2>/dev/null && symlink_go_tool "\$bin") || true
done

# ── Python tools via pipx (isolated) ─────────────────────────────────────────
echo -e "\${DIM}  Installing Python tools via pipx...\${NC}"
export PIPX_BIN_DIR=/usr/local/bin
export PIPX_HOME=/opt/pipx
for tool in shodan h8mail arjun wafw00f graphw00f waymore ghauri semgrep pip-audit; do
    command -v "\$tool" &>/dev/null || pipx install "\$tool" 2>/dev/null || \\
        pip3 install "\$tool" --break-system-packages -q 2>/dev/null || true
done

# ── install_python_git_tool: isolated venv per tool ──────────────────────────
install_python_git_tool() {
    local name="\$1" repo="\$2" dir="\$3" script="\$4"
    command -v "\$name" &>/dev/null && return 0
    sudo rm -rf "\$dir" 2>/dev/null || true
    git clone --depth=1 "\$repo" "\$dir" 2>/dev/null || return 1
    python3 -m venv "\$dir/.venv" 2>/dev/null || { sudo apt-get install -y python3-venv -qq 2>/dev/null; python3 -m venv "\$dir/.venv"; }
    "\$dir/.venv/bin/pip" install --upgrade pip -q 2>/dev/null
    [ -f "\$dir/requirements.txt" ] && "\$dir/.venv/bin/pip" install -r "\$dir/requirements.txt" -q 2>/dev/null || true
    [ -f "\$dir/setup.py" ] || [ -f "\$dir/pyproject.toml" ] && "\$dir/.venv/bin/pip" install -e "\$dir" -q 2>/dev/null || true
    printf '#!/bin/bash\\nexec "%s/.venv/bin/python3" "%s/%s" "\$@"\\n' "\$dir" "\$dir" "\$script" | sudo tee "/usr/local/bin/\$name" > /dev/null
    sudo chmod +x "/usr/local/bin/\$name"
}

echo -e "\${DIM}  Installing git-based Python tools (isolated venvs)...\${NC}"
install_python_git_tool "paramspider" "https://github.com/devanshbatham/ParamSpider" "/opt/ParamSpider" "paramspider.py" 2>/dev/null || true
install_python_git_tool "xsstrike"    "https://github.com/s0md3v/XSStrike"           "/opt/XSStrike"    "xsstrike.py"    2>/dev/null || true
install_python_git_tool "ssrfmap"     "https://github.com/swisskyrepo/SSRFmap"        "/opt/ssrfmap"     "ssrfmap.py"     2>/dev/null || true
install_python_git_tool "tplmap"      "https://github.com/epinna/tplmap"              "/opt/tplmap"      "tplmap.py"      2>/dev/null || true
install_python_git_tool "corsy"       "https://github.com/s0md3v/Corsy"               "/opt/corsy"       "corsy.py"       2>/dev/null || true
install_python_git_tool "smuggler"    "https://github.com/defparam/smuggler"           "/opt/smuggler"    "smuggler.py"    2>/dev/null || true
install_python_git_tool "jwt_tool"    "https://github.com/ticarpi/jwt_tool"            "/opt/jwt_tool"    "jwt_tool.py"    2>/dev/null || true
install_python_git_tool "liffy"       "https://github.com/mzfr/liffy"                  "/opt/liffy"       "liffy.py"       2>/dev/null || true
install_python_git_tool "gopherus"    "https://github.com/tarunkant/Gopherus"          "/opt/gopherus"    "gopherus.py"    2>/dev/null || true

# ── TruffleHog ────────────────────────────────────────────────────────────────
command -v trufflehog &>/dev/null || \\
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \\
    | sh -s -- -b /usr/local/bin 2>/dev/null || true

# ── GF patterns ───────────────────────────────────────────────────────────────
command -v gf &>/dev/null && [ ! -d "\$HOME/.gf" ] && \\
    git clone --depth=1 https://github.com/1ndianl33t/Gf-Patterns "\$HOME/.gf" 2>/dev/null || true

# ── Nuclei templates ──────────────────────────────────────────────────────────
command -v nuclei &>/dev/null && nuclei -update-templates 2>/dev/null || true

# ── puredns resolvers ─────────────────────────────────────────────────────────
command -v puredns &>/dev/null && [ ! -f /tmp/cybermind_resolvers.txt ] && \\
    curl -sL "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \\
    -o /tmp/cybermind_resolvers.txt 2>/dev/null || true

# ── Playwright (headless browser for SPA scanning) ───────────────────────────
if command -v node &>/dev/null && ! node -e "require('playwright')" 2>/dev/null; then
    echo -e "\${DIM}  Installing Playwright (headless SPA scanning)...\${NC}"
    sudo npm install -g playwright 2>/dev/null || true
    sudo npx playwright install chromium --with-deps 2>/dev/null || true
fi

# ── Reconftw (Mega Mode) ──────────────────────────────────────────────────────
if ! command -v reconftw &>/dev/null && [ ! -f /opt/reconftw/reconftw.sh ]; then
    echo -e "\${DIM}  Installing reconftw (Mega Mode — 5-10 min)...\${NC}"
    git clone --depth=1 https://github.com/six2dez/reconftw.git /opt/reconftw 2>/dev/null && \\
    chmod +x /opt/reconftw/reconftw.sh /opt/reconftw/install.sh && \\
    (cd /opt/reconftw && bash install.sh 2>/dev/null || true) && \\
    printf '#!/bin/bash\\nexec bash /opt/reconftw/reconftw.sh "\$@"\\n' | sudo tee /usr/local/bin/reconftw > /dev/null && \\
    sudo chmod +x /usr/local/bin/reconftw 2>/dev/null || true
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "\${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\${NC}"
echo -e "\${BOLD}\${GREEN}⚡ CyberMind CLI v\${VERSION} installed!\${NC}"
echo ""
echo -e "  \${CYAN}Verify:${NC}          cybermind --version"
echo -e "  \${CYAN}Doctor:${NC}          sudo cybermind /doctor"
echo -e "  \${CYAN}OMEGA Plan:${NC}      sudo cybermind /plan example.com"
echo -e "  \${CYAN}Auto-Target:${NC}     sudo cybermind /plan --auto-target --skill intermediate"
echo -e "  \${CYAN}Mega Mode:${NC}       sudo cybermind /plan --auto-target --mode overnight --continuous"
echo -e "  \${CYAN}Recon:${NC}           sudo cybermind /recon example.com"
echo -e "  \${CYAN}Hunt:${NC}            sudo cybermind /hunt example.com"
echo -e "  \${CYAN}Abhimanyu:${NC}       sudo cybermind /abhimanyu example.com"
echo -e "  \${CYAN}DevSec:${NC}          cybermind /devsec <github-url|path>"
echo -e "  \${CYAN}Vibe-Hack:${NC}       sudo cybermind /vibe-hack example.com"
echo -e "  \${CYAN}Chain:${NC}           sudo cybermind /chain example.com"
echo -e "  \${CYAN}Red Team:${NC}        sudo cybermind /red-team company.com"
echo -e "  \${CYAN}Python Tools:${NC}    sudo cybermind /install-python-tools"
echo ""
echo -e "  \${BOLD}\${YELLOW}NEW in v4.5.0:\${NC}"
echo -e "  \${DIM}  • 13 new tools: puredns, alterx, shuffledns, uncover, cdncheck, asnmap, ghauri\${NC}"
echo -e "  \${DIM}  • Nuclei AI template generator (target-specific YAML templates)\${NC}"
echo -e "  \${DIM}  • Headless browser SPA scanning (katana headless + Playwright)\${NC}"
echo -e "  \${DIM}  • SPA framework detection (React/Next.js/Vue/Angular)\${NC}"
echo -e "  \${DIM}  • Chat AI strict no-greeting (edge-level enforcement)\${NC}"
echo -e "  \${DIM}  • OMEGA brain upgraded with 2025/2026 attack patterns\${NC}"
echo ""
if [ -n "\$CYBERMIND_KEY" ]; then
    echo -e "  \${GREEN}✓ API key saved — run: cybermind whoami\${NC}"
    echo ""
fi
echo -e "\${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\${NC}"
echo ""
`;

  res.send(script);
};
