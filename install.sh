#!/bin/bash
# CyberMind CLI Installer — Kali Linux / Ubuntu / Debian
# Downloads pre-built binary from GitHub (fast, no Go needed)
# Usage: curl -sL https://cybermindcli1.vercel.app/install.sh | bash
# Usage: CYBERMIND_KEY=cp_live_xxx curl -sL https://cybermindcli1.vercel.app/install.sh | bash

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
DIM='\033[0;90m'
BOLD='\033[1m'
NC='\033[0m'

GITHUB_RAW="https://raw.githubusercontent.com/thecnical/cybermind/main/cli"
INSTALL_PATH="/usr/local/bin/cybermind"
CBM_PATH="/usr/local/bin/cbm"
VERSION="4.7.0"

echo -e "${CYAN}"
cat << 'BANNER'
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ███╗██╗███╗   ██╗██████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗ ████║██║████╗  ██║██╔══██╗
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔████╔██║██║██╔██╗ ██║██║  ██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╔╝██║██║██║╚██╗██║██║  ██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚═╝ ██║██║██║ ╚████║██████╔╝
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝
BANNER
echo -e "${NC}"
echo -e "${BOLD}${GREEN}⚡ CyberMind CLI Installer v${VERSION}${NC}"
echo -e "${DIM}   AI-Powered Bug Bounty & Recon Platform${NC}"
echo ""

# ── Detect OS + arch ──────────────────────────────────────────────────────────
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64)  BINARY="cybermind-linux-amd64" ;;
    aarch64) BINARY="cybermind-linux-arm64" ;;
    arm64)   BINARY="cybermind-linux-arm64" ;;
    *)
        echo -e "${YELLOW}[!] Unsupported architecture: $ARCH — building from source...${NC}"
        BINARY=""
        ;;
esac

if [ "$OS" != "linux" ]; then
    echo -e "${YELLOW}[!] Non-Linux OS detected ($OS). Recon/hunt tools are Linux-only.${NC}"
    echo -e "${DIM}    AI chat + CBM Code work on all platforms.${NC}"
fi

# ── Step 1: Download pre-built binary from GitHub ─────────────────────────────
if [ -n "$BINARY" ]; then
    echo -e "${YELLOW}[*] Downloading CyberMind CLI binary (${BINARY})...${NC}"
    BINARY_URL="${GITHUB_RAW}/${BINARY}"
    TMP_BIN="/tmp/cybermind-install-$$"

    if command -v curl &>/dev/null; then
        HTTP_CODE=$(curl -fsSL -w "%{http_code}" -o "$TMP_BIN" "$BINARY_URL" 2>/dev/null)
    elif command -v wget &>/dev/null; then
        wget -q -O "$TMP_BIN" "$BINARY_URL" 2>/dev/null && HTTP_CODE="200" || HTTP_CODE="404"
    else
        echo -e "${RED}[!] curl or wget required${NC}"
        exit 1
    fi

    FILE_SIZE=$(stat -c%s "$TMP_BIN" 2>/dev/null || stat -f%z "$TMP_BIN" 2>/dev/null || echo 0)
    if [ "$HTTP_CODE" = "200" ] && [ -f "$TMP_BIN" ] && [ "$FILE_SIZE" -gt 1048576 ]; then
        chmod +x "$TMP_BIN"
        sudo cp "$TMP_BIN" "$INSTALL_PATH"
        sudo chmod +x "$INSTALL_PATH"
        sudo cp "$INSTALL_PATH" "$CBM_PATH"
        sudo chmod +x "$CBM_PATH"
        rm -f "$TMP_BIN"
        echo -e "${GREEN}[✓] Binary installed: $INSTALL_PATH${NC}"
        echo -e "${GREEN}[✓] Alias installed:  $CBM_PATH${NC}"
    else
        rm -f "$TMP_BIN"
        echo -e "${YELLOW}[!] Binary download failed (HTTP $HTTP_CODE, size ${FILE_SIZE}B). Building from source...${NC}"
        BINARY=""
    fi
fi

# ── Step 2: Build from source (fallback) ─────────────────────────────────────
if [ -z "$BINARY" ] || ! command -v cybermind &>/dev/null; then
    echo -e "${YELLOW}[*] Building from source (requires Go)...${NC}"

    if ! command -v go &>/dev/null; then
        echo -e "${YELLOW}[!] Go not found. Installing Go 1.22...${NC}"
        GO_VERSION="1.22.0"
        GO_TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"
        GO_URL="https://go.dev/dl/${GO_TARBALL}"
        wget -q "$GO_URL" -O "/tmp/${GO_TARBALL}"
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf "/tmp/${GO_TARBALL}"
        rm "/tmp/${GO_TARBALL}"
        export PATH=$PATH:/usr/local/go/bin
        for profile in /root/.bashrc /root/.zshrc /home/*/.bashrc /home/*/.zshrc; do
            [ -f "$profile" ] && grep -q "/usr/local/go/bin" "$profile" || \
                echo 'export PATH=$PATH:/usr/local/go/bin' >> "$profile" 2>/dev/null || true
        done
    fi
    echo -e "${GREEN}[✓] Go $(go version | awk '{print $3}')${NC}"

    REPO_DIR="/tmp/cybermind-src-$$"
    echo -e "${YELLOW}[*] Cloning CyberMind repo...${NC}"
    git clone --depth=1 https://github.com/thecnical/cybermind.git "$REPO_DIR" 2>/dev/null
    cd "$REPO_DIR/cli"
    go mod tidy -q
    go build -ldflags="-s -w" -o /tmp/cybermind-built .
    chmod +x /tmp/cybermind-built
    sudo cp /tmp/cybermind-built "$INSTALL_PATH"
    sudo cp /tmp/cybermind-built "$CBM_PATH"
    rm -rf "$REPO_DIR" /tmp/cybermind-built
    echo -e "${GREEN}[✓] Built and installed from source${NC}"
fi

# ── Step 3: Save API key if provided ─────────────────────────────────────────
if [ -n "$CYBERMIND_KEY" ]; then
    echo ""
    echo -e "${YELLOW}[*] Saving API key...${NC}"
    mkdir -p "$HOME/.cybermind"
    chmod 700 "$HOME/.cybermind"
    printf '{"key":"%s"}' "$CYBERMIND_KEY" > "$HOME/.cybermind/config.json"
    chmod 600 "$HOME/.cybermind/config.json"
    echo -e "${GREEN}[✓] API key saved to ~/.cybermind/config.json${NC}"
fi

# ── Step 4: Configure PATH ────────────────────────────────────────────────────
export PATH=$PATH:/usr/local/bin:$HOME/go/bin:/usr/local/go/bin
for profile in ~/.bashrc ~/.zshrc ~/.profile /root/.bashrc /root/.zshrc; do
    if [ -f "$profile" ] && ! grep -q "go/bin" "$profile"; then
        echo 'export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin' >> "$profile"
    fi
done

# ── Step 5: Install essential recon + hunt tools ──────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}[*] Installing essential recon + hunt tools...${NC}"
echo -e "${DIM}    Full install: sudo cybermind /doctor${NC}"
echo ""

# Non-interactive apt
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq 2>/dev/null || true

# ── APT essentials ────────────────────────────────────────────────────────────
APT_TOOLS=(
    nmap masscan zmap whois dnsutils theharvester whatweb
    ffuf feroxbuster gobuster nikto amass sqlmap commix
    wpscan libpcap-dev python3-pip pipx git curl wget
    libimage-exiftool-perl wafw00f
)
echo -e "${DIM}  Installing apt packages...${NC}"
sudo apt-get install -y "${APT_TOOLS[@]}" -qq 2>/dev/null || true

# ── Go tools ─────────────────────────────────────────────────────────────────
symlink_go_tool() {
    local bin="$1"
    for gobin in "$HOME/go/bin" "/root/go/bin"; do
        [ -f "$gobin/$bin" ] && sudo ln -sf "$gobin/$bin" "/usr/local/bin/$bin" 2>/dev/null && return
    done
}

echo -e "${DIM}  Installing Go tools...${NC}"
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
for entry in "${GO_TOOLS[@]}"; do
    bin="${entry%%:*}"; module="${entry##*:}"
    if ! command -v "$bin" &>/dev/null; then
        go install "${module}@latest" 2>/dev/null && symlink_go_tool "$bin" || true
    fi
done

# ── Python tools via pipx ─────────────────────────────────────────────────────
echo -e "${DIM}  Installing Python tools via pipx (isolated, no system pollution)...${NC}"
# Ensure pipx is available
if ! command -v pipx &>/dev/null; then
    sudo apt-get install -y pipx python3-venv -qq 2>/dev/null || pip3 install pipx -q 2>/dev/null || true
fi
export PIPX_BIN_DIR=/usr/local/bin
export PIPX_HOME=/opt/pipx
# Fix shodan pkg_resources error
pip3 install setuptools --break-system-packages -q 2>/dev/null || true
PIPX_TOOLS=(shodan h8mail wafw00f arjun graphw00f waymore ghauri semgrep pip-audit)
for tool in "${PIPX_TOOLS[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
        pipx install "$tool" 2>/dev/null || \
        pip3 install "$tool" --break-system-packages -q 2>/dev/null || \
        pip3 install "$tool" -q 2>/dev/null || true
    fi
done

# ── TruffleHog ────────────────────────────────────────────────────────────────
if ! command -v trufflehog &>/dev/null; then
    echo -e "${DIM}  Installing trufflehog...${NC}"
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sh -s -- -b /usr/local/bin 2>/dev/null || true
fi

# ── GF patterns ───────────────────────────────────────────────────────────────
if command -v gf &>/dev/null && [ ! -d "$HOME/.gf" ]; then
    git clone --depth=1 https://github.com/1ndianl33t/Gf-Patterns "$HOME/.gf" 2>/dev/null || true
fi

# ── Nuclei templates ──────────────────────────────────────────────────────────
if command -v nuclei &>/dev/null; then
    nuclei -update-templates 2>/dev/null || true
fi

# ── Interactsh (real SSRF/OOB verification) ───────────────────────────────────
if ! command -v interactsh-client &>/dev/null; then
    echo -e "${DIM}  Installing interactsh-client (OOB verification)...${NC}"
    go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest 2>/dev/null && \
        symlink_go_tool "interactsh-client" || true
fi

# ── Playwright (browser automation for XSS/OAuth/race conditions) ─────────────
if ! command -v node &>/dev/null; then
    echo -e "${DIM}  Installing Node.js for Playwright...${NC}"
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - 2>/dev/null || true
    sudo apt-get install -y nodejs -qq 2>/dev/null || true
fi
if command -v node &>/dev/null && ! node -e "require('playwright')" 2>/dev/null; then
    echo -e "${DIM}  Installing Playwright (browser automation)...${NC}"
    sudo npm install -g playwright 2>/dev/null || true
    sudo npx playwright install chromium --with-deps 2>/dev/null || true
fi

# ── install_python_git_tool: installs a Python git tool in isolated venv ──────
# Usage: install_python_git_tool <name> <repo_url> <install_dir> <main_script>
install_python_git_tool() {
    local name="$1" repo="$2" dir="$3" script="$4"
    command -v "$name" &>/dev/null && return 0
    git clone --depth=1 "$repo" "$dir" 2>/dev/null || return 1
    python3 -m venv "$dir/.venv" 2>/dev/null || { sudo apt-get install -y python3-venv -qq 2>/dev/null; python3 -m venv "$dir/.venv"; }
    "$dir/.venv/bin/pip" install --upgrade pip -q 2>/dev/null
    [ -f "$dir/requirements.txt" ] && "$dir/.venv/bin/pip" install -r "$dir/requirements.txt" -q 2>/dev/null || true
    [ -f "$dir/setup.py" ] || [ -f "$dir/pyproject.toml" ] && "$dir/.venv/bin/pip" install -e "$dir" -q 2>/dev/null || true
    printf '#!/bin/bash\nexec "%s/.venv/bin/python3" "%s/%s" "$@"\n' "$dir" "$dir" "$script" | sudo tee "/usr/local/bin/$name" > /dev/null
    sudo chmod +x "/usr/local/bin/$name"
}

# ── Additional exploit + intelligence tools ───────────────────────────────────
echo -e "${DIM}  Installing additional tools...${NC}"
# Slither (smart contract analysis) — isolated venv
if ! command -v slither &>/dev/null; then
    python3 -m venv /opt/slither-venv 2>/dev/null
    /opt/slither-venv/bin/pip install slither-analyzer -q 2>/dev/null && \
    sudo ln -sf /opt/slither-venv/bin/slither /usr/local/bin/slither 2>/dev/null || true
fi
# APK tools (mobile)
command -v apktool &>/dev/null || sudo apt-get install -y apktool -qq 2>/dev/null || true
# HTTP smuggling — isolated venv
install_python_git_tool "smuggler" "https://github.com/defparam/smuggler" "/opt/smuggler" "smuggler.py" 2>/dev/null || true
# JWT Tool (OAuth/JWT attack engine) — isolated venv
install_python_git_tool "jwt_tool" "https://github.com/ticarpi/jwt_tool" "/opt/jwt_tool" "jwt_tool.py" 2>/dev/null || true
# GraphQL attack tool — proper git install
# graphw00f — GraphQL fingerprinting (git install, not pip)
if ! command -v graphw00f &>/dev/null; then
    git clone --depth=1 https://github.com/dolevf/graphw00f.git /opt/graphw00f 2>/dev/null && \
    pip3 install -r /opt/graphw00f/requirements.txt --break-system-packages -q 2>/dev/null && \
    sudo ln -sf /opt/graphw00f/main.py /usr/local/bin/graphw00f && \
    sudo chmod +x /usr/local/bin/graphw00f 2>/dev/null || true
fi
# SSRF map — isolated venv
install_python_git_tool "ssrfmap" "https://github.com/swisskyrepo/SSRFmap" "/opt/ssrfmap" "ssrfmap.py" 2>/dev/null || true
# SSTI exploitation (tplmap) — isolated venv
install_python_git_tool "tplmap" "https://github.com/epinna/tplmap" "/opt/tplmap" "tplmap.py" 2>/dev/null || true
# CORS scanner — isolated venv
install_python_git_tool "corsy" "https://github.com/s0md3v/Corsy" "/opt/corsy" "corsy.py" 2>/dev/null || true
# ParamSpider — pipx (has proper package)
command -v paramspider &>/dev/null || pipx install paramspider 2>/dev/null || \
    install_python_git_tool "paramspider" "https://github.com/devanshbatham/ParamSpider" "/opt/ParamSpider" "paramspider.py" 2>/dev/null || true
# XSStrike — isolated venv
install_python_git_tool "xsstrike" "https://github.com/s0md3v/XSStrike" "/opt/XSStrike" "xsstrike.py" 2>/dev/null || true
# Mantra (JS secret finder), Cariddi (deep crawler), BXss (blind XSS)
go install github.com/MrEmpy/mantra@latest 2>/dev/null && symlink_go_tool "mantra" || true
go install github.com/edoardottt/cariddi/cmd/cariddi@latest 2>/dev/null && symlink_go_tool "cariddi" || true
go install github.com/ethicalhackingplayground/bxss@latest 2>/dev/null && symlink_go_tool "bxss" || true
# ── 2025 NEW: ghauri — advanced SQLi (better than sqlmap for modern apps) ─────
command -v ghauri &>/dev/null || pipx install ghauri 2>/dev/null || \
    pip3 install ghauri --break-system-packages -q 2>/dev/null || true
# ── 2025 NEW: puredns — fast DNS brute-force with wildcard filtering ──────────
command -v puredns &>/dev/null || \
    (go install github.com/d3mondev/puredns/v2@latest 2>/dev/null && symlink_go_tool "puredns") || true
# ── 2025 NEW: alterx — subdomain permutation engine ──────────────────────────
command -v alterx &>/dev/null || \
    (go install github.com/projectdiscovery/alterx/cmd/alterx@latest 2>/dev/null && symlink_go_tool "alterx") || true
# ── 2025 NEW: shuffledns — mass DNS resolver ─────────────────────────────────
command -v shuffledns &>/dev/null || \
    (go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest 2>/dev/null && symlink_go_tool "shuffledns") || true
# ── 2025 NEW: uncover — expose internet-facing assets (Shodan/Fofa/Censys) ───
command -v uncover &>/dev/null || \
    (go install github.com/projectdiscovery/uncover/cmd/uncover@latest 2>/dev/null && symlink_go_tool "uncover") || true
# ── 2025 NEW: cdncheck — CDN/WAF detection ───────────────────────────────────
command -v cdncheck &>/dev/null || \
    (go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest 2>/dev/null && symlink_go_tool "cdncheck") || true
# ── 2025 NEW: asnmap — ASN to IP range mapping ───────────────────────────────
command -v asnmap &>/dev/null || \
    (go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest 2>/dev/null && symlink_go_tool "asnmap") || true
# ── 2025 NEW: notify — bug found notifications (Telegram/Slack/Discord) ──────
command -v notify &>/dev/null || \
    (go install github.com/projectdiscovery/notify/cmd/notify@latest 2>/dev/null && symlink_go_tool "notify") || true
# ── 2025 NEW: ligolo-ng — advanced tunneling for lateral movement ─────────────
command -v ligolo-ng &>/dev/null || \
    (go install github.com/nicocha30/ligolo-ng/cmd/proxy@latest 2>/dev/null && symlink_go_tool "ligolo-ng") || true
# ligolo-ng symlink fix (binary is named 'proxy' not 'ligolo-ng')
if [ -f "$HOME/go/bin/proxy" ] && ! command -v ligolo-ng &>/dev/null; then
    sudo ln -sf "$HOME/go/bin/proxy" /usr/local/bin/ligolo-ng 2>/dev/null || true
fi
# ── 2025 NEW: semgrep — SAST code analysis ───────────────────────────────────
command -v semgrep &>/dev/null || pipx install semgrep 2>/dev/null || \
    pip3 install semgrep --break-system-packages -q 2>/dev/null || true
# ── 2025 NEW: liffy — LFI exploitation framework ─────────────────────────────
install_python_git_tool "liffy" "https://github.com/mzfr/liffy" "/opt/liffy" "liffy.py" 2>/dev/null || true
# ── 2025 NEW: gopherus — SSRF payload generator ──────────────────────────────
install_python_git_tool "gopherus" "https://github.com/tarunkant/Gopherus" "/opt/gopherus" "gopherus.py" 2>/dev/null || true
# ── puredns resolvers list (also used by reconftw internally) ────────────────
if [ ! -f /tmp/cybermind_resolvers.txt ] || [ $(wc -l < /tmp/cybermind_resolvers.txt 2>/dev/null || echo 0) -lt 100 ]; then
    curl -sL "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
        -o /tmp/cybermind_resolvers.txt 2>/dev/null || true
fi
# ── reconftw — Full reconFTW power (Mega Mode) ───────────────────────────────
# reconftw is the backbone of CyberMind's recon mode — 50+ tools in one
# Modes: -s (subdomain, 15min), -r (full recon, 2-4h), -a --deep (all, 6-12h)
if ! command -v reconftw &>/dev/null || [ ! -f /opt/reconftw/reconftw.sh ]; then
    echo -e "${DIM}  Installing reconftw (Mega Mode — 5-10 min)...${NC}"
    # Remove stale install if exists
    [ -d /opt/reconftw ] && sudo rm -rf /opt/reconftw 2>/dev/null || true
    git clone --depth=1 https://github.com/six2dez/reconftw.git /opt/reconftw 2>/dev/null && \
    chmod +x /opt/reconftw/reconftw.sh /opt/reconftw/install.sh && \
    (cd /opt/reconftw && timeout 600 bash install.sh 2>/dev/null || true) && \
    printf '#!/bin/bash\nexec bash /opt/reconftw/reconftw.sh "$@"\n' | sudo tee /usr/local/bin/reconftw > /dev/null && \
    sudo chmod +x /usr/local/bin/reconftw && \
    echo -e "${GREEN}[✓] reconftw installed${NC}" || \
    echo -e "${YELLOW}[!] reconftw install failed — run: sudo cybermind /doctor${NC}"
elif [ -f /opt/reconftw/reconftw.sh ]; then
    # Update existing reconftw to latest
    echo -e "${DIM}  Updating reconftw to latest...${NC}"
    (cd /opt/reconftw && git pull --ff-only 2>/dev/null || true)
    # Ensure wrapper is up to date
    printf '#!/bin/bash\nexec bash /opt/reconftw/reconftw.sh "$@"\n' | sudo tee /usr/local/bin/reconftw > /dev/null
    sudo chmod +x /usr/local/bin/reconftw
fi

# ── reconftw resolvers (required for puredns/shuffledns inside reconftw) ──────
if [ ! -f /tmp/cybermind_resolvers.txt ] || [ $(wc -l < /tmp/cybermind_resolvers.txt 2>/dev/null || echo 0) -lt 100 ]; then
    echo -e "${DIM}  Downloading DNS resolvers list...${NC}"
    curl -sL "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
        -o /tmp/cybermind_resolvers.txt 2>/dev/null || \
    curl -sL "https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt" \
        -o /tmp/cybermind_resolvers.txt 2>/dev/null || true
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}${GREEN}⚡ CyberMind CLI v${VERSION} installed!${NC}"
echo ""
echo -e "  ${CYAN}Verify:${NC}          cybermind --version"
echo -e "  ${CYAN}AI Chat:${NC}         cybermind"
echo -e "  ${CYAN}Doctor:${NC}          sudo cybermind /doctor"
echo -e "  ${CYAN}OMEGA Plan:${NC}      sudo cybermind /plan example.com"
echo -e "  ${CYAN}Auto-Target:${NC}     sudo cybermind /plan --auto-target --skill intermediate"
echo -e "  ${CYAN}Mega Mode:${NC}       sudo cybermind /plan --auto-target --mode overnight --continuous"
echo -e "  ${CYAN}Recon:${NC}           sudo cybermind /recon example.com"
echo -e "  ${CYAN}Hunt:${NC}            sudo cybermind /hunt example.com"
echo -e "  ${CYAN}Abhimanyu:${NC}       sudo cybermind /abhimanyu example.com"
echo -e "  ${CYAN}DevSec:${NC}          cybermind /devsec <github-url|path>"
echo -e "  ${CYAN}Vibe-Hack:${NC}       sudo cybermind /vibe-hack example.com"
echo -e "  ${CYAN}Chain:${NC}           sudo cybermind /chain example.com"
echo -e "  ${CYAN}Red Team:${NC}        sudo cybermind /red-team company.com"
echo -e "  ${CYAN}BizLogic:${NC}        sudo cybermind /bizlogic example.com"
echo -e "  ${CYAN}OSINT Deep:${NC}      sudo cybermind /osint-deep example.com"
echo -e "  ${CYAN}Novel Attacks:${NC}   sudo cybermind /novel example.com"
echo -e "  ${CYAN}Python Tools:${NC}    sudo cybermind /install-python-tools"
echo -e "  ${CYAN}Vibe Coder:${NC}      cybermind /vibe"
echo ""
echo -e "  ${BOLD}${YELLOW}NEW in v4.7.0:${NC}"
echo -e "  ${DIM}  • reconFTW fully integrated — mode-aware: quick(-s) / deep(-r) / overnight(-a --deep)${NC}"
echo -e "  ${DIM}  • reconFTW output parsing: subdomains, URLs, vulns, secrets, emails, takeover, buckets${NC}"
echo -e "  ${DIM}  • reconFTW tech stack + WAF detection fed into agentic brain${NC}"
echo -e "  ${DIM}  • Brain memory records reconFTW findings for smarter future scans${NC}"
echo -e "  ${DIM}  • reconFTW auto-updates on re-install (git pull)${NC}"
echo -e "  ${DIM}  • 14 subdomain file types parsed (passive, brute, permut, crt, noerror, vhosts)${NC}"
echo -e "  ${DIM}  • 18 vuln file types parsed (XSS, SQLi, SSRF, LFI, SSTI, CRLF, smuggling, cache)${NC}"
echo -e "  ${DIM}  • Cloud bucket exposure detection (S3Scanner + cloud_enum)${NC}"
echo -e "  ${DIM}  • JS file secrets extraction (mantra, JSA, subjs)${NC}"
echo -e "  ${DIM}  • Subdomain takeover candidates auto-flagged${NC}"
echo ""
echo -e "  ${DIM}Full tool install: sudo cybermind /doctor${NC}"
echo -e "  ${DIM}OOB verification:  interactsh-client auto-installed above${NC}"
echo ""
if [ -n "$CYBERMIND_KEY" ]; then
    echo -e "  ${GREEN}✓ API key saved — run: cybermind whoami${NC}"
    echo ""
fi
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
