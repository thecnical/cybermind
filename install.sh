#!/bin/bash
# CyberMind CLI Installer — Kali Linux / Ubuntu / Debian
# Downloads pre-built binary from GitHub (fast, no Go needed)
# Usage: curl -sL https://cybermindcli1.vercel.app/install.sh | bash
# Usage: CYBERMIND_KEY=cp_live_xxx curl -sL https://cybermindcli1.vercel.app/install.sh | bash

set -e

# ── Disable ALL interactive prompts ──────────────────────────────────────────
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true
export GIT_TERMINAL_PROMPT=0          # CRITICAL: Never ask for GitHub credentials
export GIT_ASKPASS=echo               # Return empty string for any git credential prompt
export GCM_INTERACTIVE=never          # Disable Git Credential Manager interactive mode
export HOMEBREW_NO_AUTO_UPDATE=1      # No brew auto-update
export PIP_NO_INPUT=1                 # No pip interactive prompts
export NPM_CONFIG_YES=true            # No npm prompts

# ── Trap errors — don't exit on tool install failures ────────────────────────
# Individual tool installs use '|| true' so they never cause script exit
# Only critical steps (binary download) will exit on failure

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
VERSION="5.4.5"

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
    GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=echo git clone --depth=1 https://github.com/thecnical/cybermind.git "$REPO_DIR" 2>/dev/null
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
    "bxss:github.com/ethicalhackingplayground/bxss/v2/cmd/bxss"
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
PIPX_TOOLS=(shodan h8mail wafw00f arjun waymore ghauri semgrep pip-audit)
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
    GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=echo git clone --depth=1 https://github.com/1ndianl33t/Gf-Patterns "$HOME/.gf" 2>/dev/null || true
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
# NOTE: Playwright is optional — only needed for headless browser scanning of SPA apps
# Skipped in initial install to avoid long download + Ubuntu 24.04 compatibility issues
# Install manually if needed: sudo npm install -g playwright && sudo npx playwright install chromium --with-deps
if ! command -v node &>/dev/null; then
    echo -e "${DIM}  Installing Node.js (lightweight, no Playwright)...${NC}"
    sudo apt-get install -y nodejs npm -qq 2>/dev/null || true
fi
# Playwright install is SKIPPED here — run manually if you need headless browser scanning:
# sudo npm install -g playwright && sudo npx playwright install chromium --with-deps

# ── install_python_git_tool: installs a Python git tool in isolated venv ──────
# Usage: install_python_git_tool <name> <repo_url> <install_dir> <main_script>
install_python_git_tool() {
    local name="$1" repo="$2" dir="$3" script="$4"
    command -v "$name" &>/dev/null && return 0
    GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=echo git clone --depth=1 "$repo" "$dir" 2>/dev/null || return 1
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
# graphw00f — GraphQL fingerprinting (git clone + requests only, NOT requirements.txt which includes wsgiref/Python2)
if ! command -v graphw00f &>/dev/null; then
    GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=echo git clone --depth=1 https://github.com/dolevf/graphw00f.git /opt/graphw00f 2>/dev/null && \
    pip3 install requests --break-system-packages -q 2>/dev/null && \
    sudo ln -sf /opt/graphw00f/main.py /usr/local/bin/graphw00f && \
    sudo chmod +x /opt/graphw00f/main.py 2>/dev/null || true
fi
# SSRF map — isolated venv
install_python_git_tool "ssrfmap" "https://github.com/swisskyrepo/SSRFmap" "/opt/ssrfmap" "ssrfmap.py" 2>/dev/null || true
# tplmap requires Python 2 — skip, install tinja as Python 3 replacement
# install_python_git_tool "tplmap" "https://github.com/epinna/tplmap" "/opt/tplmap" "tplmap.py"  # Python 2 only
command -v tinja &>/dev/null || pip3 install tinja --break-system-packages -q 2>/dev/null || true
# CORS scanner — isolated venv
install_python_git_tool "corsy" "https://github.com/s0md3v/Corsy" "/opt/corsy" "corsy.py" 2>/dev/null || true
# ParamSpider — pipx (has proper package)
command -v paramspider &>/dev/null || pipx install paramspider 2>/dev/null || \
    install_python_git_tool "paramspider" "https://github.com/devanshbatham/ParamSpider" "/opt/ParamSpider" "paramspider.py" 2>/dev/null || true
# XSStrike — isolated venv
install_python_git_tool "xsstrike" "https://github.com/s0md3v/XSStrike" "/opt/XSStrike" "xsstrike.py" 2>/dev/null || true
# Mantra (JS secret finder) — use git clone + build to avoid module path conflict
if ! command -v mantra &>/dev/null; then
    echo -e "${DIM}  Installing mantra (git clone + build)...${NC}"
    rm -rf /tmp/mantra_build 2>/dev/null || true
    GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=echo git clone --depth=1 https://github.com/MrEmpy/mantra /tmp/mantra_build 2>/dev/null && \
    (cd /tmp/mantra_build && go build -o /tmp/mantra_bin . 2>/dev/null) && \
    sudo cp /tmp/mantra_bin /usr/local/bin/mantra && \
    sudo chmod +x /usr/local/bin/mantra && \
    rm -rf /tmp/mantra_build /tmp/mantra_bin && \
    echo -e "${GREEN}[✓] mantra installed${NC}" || \
    echo -e "${YELLOW}[!] mantra install failed — skipping${NC}"
fi
go install github.com/edoardottt/cariddi/cmd/cariddi@latest 2>/dev/null && symlink_go_tool "cariddi" || true
go install github.com/ethicalhackingplayground/bxss/v2/cmd/bxss@latest 2>/dev/null && symlink_go_tool "bxss" || true
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
# ── 2026 NEW: github-subdomains — find subdomains in GitHub code ──────────────
command -v github-subdomains &>/dev/null || \
    (go install github.com/gwen001/github-subdomains@latest 2>/dev/null && symlink_go_tool "github-subdomains") || true
# ── 2026 NEW: asnmap — ASN to IP range mapping ───────────────────────────────
command -v asnmap &>/dev/null || \
    (go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest 2>/dev/null && symlink_go_tool "asnmap") || true
# ── 2026 NEW: webanalyze — Go-based Wappalyzer ───────────────────────────────
command -v webanalyze &>/dev/null || \
    (go install github.com/rverton/webanalyze/cmd/webanalyze@latest 2>/dev/null && symlink_go_tool "webanalyze") || true
# ── 2026 NEW: favirecon — favicon hash tech detection ────────────────────────
command -v favirecon &>/dev/null || \
    (go install github.com/edoardottt/favirecon/cmd/favirecon@latest 2>/dev/null && symlink_go_tool "favirecon") || true
# ── 2026 NEW: jsluice — extract endpoints from minified JS ───────────────────
command -v jsluice &>/dev/null || \
    (go install github.com/BishopFox/jsluice/cmd/jsluice@latest 2>/dev/null && symlink_go_tool "jsluice") || true
# ── 2026 NEW: sourcemapper — extract source maps from JS ─────────────────────
command -v sourcemapper &>/dev/null || \
    (go install github.com/denandz/sourcemapper@latest 2>/dev/null && symlink_go_tool "sourcemapper") || true
# ── 2026 NEW: getjswords — REMOVED: private/broken repo (github.com/m4ll0k/getjswords)
# Use jsluice or cariddi for JS word extraction instead
# ── 2026 NEW: swaggerspy — Swagger/OpenAPI endpoint discovery ────────────────
command -v swaggerspy &>/dev/null || pip3 install swaggerspy --break-system-packages -q 2>/dev/null || true
# ── v5.4.0 NEW: gowitness — screenshot capture for visual recon ──────────────
command -v gowitness &>/dev/null || \
    (go install github.com/sensepost/gowitness@latest 2>/dev/null && symlink_go_tool "gowitness") || true
# ── v5.4.0 NEW: nuclei takeover templates (ensure latest) ────────────────────
command -v nuclei &>/dev/null && nuclei -update-templates 2>/dev/null || true
# ── 2025 NEW: semgrep — SAST code analysis ───────────────────────────────────
command -v semgrep &>/dev/null || pipx install semgrep 2>/dev/null || \
    pip3 install semgrep --break-system-packages -q 2>/dev/null || true
# ── 2025 NEW: liffy — LFI exploitation framework ─────────────────────────────
install_python_git_tool "liffy" "https://github.com/mzfr/liffy" "/opt/liffy" "liffy.py" 2>/dev/null || true
# ── 2025 NEW: gopherus — SSRF payload generator ──────────────────────────────
install_python_git_tool "gopherus" "https://github.com/tarunkant/Gopherus" "/opt/gopherus" "gopherus.py" 2>/dev/null || true
# ── 2026 NEW: cloud-enum — S3/Azure/GCP bucket enumeration ───────────────────
command -v cloud_enum &>/dev/null || pipx install cloud-enum 2>/dev/null || \
    pip3 install cloud-enum --break-system-packages -q 2>/dev/null || true

# ── 2026 NEW: JS Deep Analysis Tools ─────────────────────────────────────────
# SecretFinder — extract API keys/secrets from JS files
if ! command -v secretfinder &>/dev/null; then
    echo -e "${DIM}  Installing SecretFinder...${NC}"
    GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=echo git clone --depth=1 https://github.com/m4ll0k/SecretFinder /opt/secretfinder 2>/dev/null && \
    pip3 install -r /opt/secretfinder/requirements.txt --break-system-packages -q 2>/dev/null && \
    printf '#!/bin/bash\npython3 /opt/secretfinder/SecretFinder.py "$@"\n' | sudo tee /usr/local/bin/secretfinder > /dev/null && \
    sudo chmod +x /usr/local/bin/secretfinder 2>/dev/null || true
fi
# LinkFinder — extract endpoints from JS source code
if ! command -v linkfinder &>/dev/null; then
    echo -e "${DIM}  Installing LinkFinder...${NC}"
    GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=echo git clone --depth=1 https://github.com/GerbenJavado/LinkFinder /opt/linkfinder 2>/dev/null && \
    pip3 install -r /opt/linkfinder/requirements.txt --break-system-packages -q 2>/dev/null && \
    printf '#!/bin/bash\npython3 /opt/linkfinder/linkfinder.py "$@"\n' | sudo tee /usr/local/bin/linkfinder > /dev/null && \
    sudo chmod +x /usr/local/bin/linkfinder 2>/dev/null || true
fi
# CMSeeK — CMS detection (WordPress, Drupal, Joomla, 180+ CMSes)
if ! command -v cmseek &>/dev/null; then
    echo -e "${DIM}  Installing CMSeeK...${NC}"
    GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=echo git clone --depth=1 https://github.com/Tuhinshubhra/CMSeeK /opt/cmseek 2>/dev/null && \
    pip3 install -r /opt/cmseek/requirements.txt --break-system-packages -q 2>/dev/null && \
    printf '#!/bin/bash\npython3 /opt/cmseek/cmseek.py "$@"\n' | sudo tee /usr/local/bin/cmseek > /dev/null && \
    sudo chmod +x /usr/local/bin/cmseek 2>/dev/null || true
fi
# retire.js — detect vulnerable JavaScript libraries
if ! command -v retire &>/dev/null; then
    echo -e "${DIM}  Installing retire.js...${NC}"
    npm install -g retire 2>/dev/null || true
fi
# ── puredns resolvers list (also used by reconftw internally) ────────────────
if [ ! -f /tmp/cybermind_resolvers.txt ] || [ $(wc -l < /tmp/cybermind_resolvers.txt 2>/dev/null || echo 0) -lt 100 ]; then
    curl -sL "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
        -o /tmp/cybermind_resolvers.txt 2>/dev/null || true
fi

# ── v5.0.0 NEW: Tier 1 Recon Tools ───────────────────────────────────────────
echo -e "${DIM}  Installing Tier 1 recon tools (wafw00f, dnsrecon, uncover, shuffledns, cdncheck, smap, rustscan, dnstake)...${NC}"
# wafw00f — WAF detection
command -v wafw00f &>/dev/null || pipx install wafw00f 2>/dev/null || pip3 install wafw00f --break-system-packages -q 2>/dev/null || true
# emailfinder — email discovery
command -v emailfinder &>/dev/null || pipx install emailfinder 2>/dev/null || pip3 install emailfinder --break-system-packages -q 2>/dev/null || true
# dnsrecon — DNS enumeration
command -v dnsrecon &>/dev/null || sudo apt-get install -y dnsrecon -qq 2>/dev/null || pip3 install dnsrecon --break-system-packages -q 2>/dev/null || true
# spoofcheck — email spoofing check
if ! command -v spoofcheck &>/dev/null; then
    GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=echo git clone --depth=1 https://github.com/BishopFox/spoofcheck /opt/spoofcheck 2>/dev/null && \
    pip3 install -r /opt/spoofcheck/requirements.txt --break-system-packages -q 2>/dev/null && \
    printf '#!/bin/bash\npython3 /opt/spoofcheck/spoofcheck.py "$@"\n' | sudo tee /usr/local/bin/spoofcheck > /dev/null && \
    sudo chmod +x /usr/local/bin/spoofcheck 2>/dev/null || true
fi
# uncover — Shodan+Fofa+Censys+Hunter aggregator
command -v uncover &>/dev/null || (go install github.com/projectdiscovery/uncover/cmd/uncover@latest 2>/dev/null && symlink_go_tool "uncover") || true
# shuffledns — mass DNS resolver
command -v shuffledns &>/dev/null || (go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest 2>/dev/null && symlink_go_tool "shuffledns") || true
# cdncheck — CDN/WAF detection
command -v cdncheck &>/dev/null || (go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest 2>/dev/null && symlink_go_tool "cdncheck") || true
# smap — passive port scan via Shodan
command -v smap &>/dev/null || (go install github.com/s0md3v/smap/cmd/smap@latest 2>/dev/null && symlink_go_tool "smap") || true
# rustscan — ultra-fast port scanner
if ! command -v rustscan &>/dev/null; then
    sudo apt-get install -y rustscan -qq 2>/dev/null || \
    (command -v cargo &>/dev/null && cargo install rustscan 2>/dev/null) || true
fi
# dnstake — subdomain takeover detection
command -v dnstake &>/dev/null || (go install github.com/pwnesia/dnstake/cmd/dnstake@latest 2>/dev/null && symlink_go_tool "dnstake") || true

# ── v5.0.0 NEW: Tier 2 Recon Tools ───────────────────────────────────────────
echo -e "${DIM}  Installing Tier 2 recon tools (ctfr, mapcidr, sslscan, uro, misconfig-mapper, second-order)...${NC}"
# ctfr — Certificate Transparency subdomain finder
command -v ctfr &>/dev/null || pip3 install ctfr --break-system-packages -q 2>/dev/null || true
# mapcidr — CIDR manipulation
command -v mapcidr &>/dev/null || (go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest 2>/dev/null && symlink_go_tool "mapcidr") || true
# sslscan — SSL/TLS analysis
command -v sslscan &>/dev/null || sudo apt-get install -y sslscan -qq 2>/dev/null || true
# uro — URL deduplication
command -v uro &>/dev/null || pip3 install uro --break-system-packages -q 2>/dev/null || true
# misconfig-mapper — third-party misconfigs
command -v misconfig-mapper &>/dev/null || (go install github.com/intigriti/misconfig-mapper/cmd/misconfig-mapper@latest 2>/dev/null && symlink_go_tool "misconfig-mapper") || true
# second-order — broken link hijacking
command -v second-order &>/dev/null || (go install github.com/mhmdiaa/second-order@latest 2>/dev/null && symlink_go_tool "second-order") || true
# testssl — comprehensive TLS testing
if ! command -v testssl &>/dev/null && ! command -v testssl.sh &>/dev/null; then
    sudo apt-get install -y testssl.sh -qq 2>/dev/null || \
    (git clone --depth=1 https://github.com/drwetter/testssl.sh /opt/testssl 2>/dev/null && \
    sudo ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl 2>/dev/null) || true
fi

# ── v5.4.0 NEW: cloud_enum — git clone (PyPI package name is wrong) ──────────
if ! command -v cloud_enum &>/dev/null; then
    echo -e "${DIM}  Installing cloud_enum (git clone)...${NC}"
    sudo rm -rf /opt/cloud_enum 2>/dev/null || true
    GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=echo git clone --depth=1 https://github.com/initstring/cloud_enum /opt/cloud_enum 2>/dev/null && \
    python3 -m venv /opt/cloud_enum/.venv 2>/dev/null && \
    /opt/cloud_enum/.venv/bin/pip install -r /opt/cloud_enum/requirements.txt -q 2>/dev/null || true && \
    printf '#!/bin/bash\nexec /opt/cloud_enum/.venv/bin/python3 /opt/cloud_enum/cloud_enum.py "$@"\n' | sudo tee /usr/local/bin/cloud_enum > /dev/null && \
    sudo chmod +x /usr/local/bin/cloud_enum && \
    echo -e "${GREEN}[✓] cloud_enum installed${NC}" || \
    echo -e "${YELLOW}[!] cloud_enum install failed${NC}"
fi
# ── v5.4.0 NEW: ctfr — git clone (pipx fails due to numpy deps) ──────────────
if ! command -v ctfr &>/dev/null; then
    echo -e "${DIM}  Installing ctfr (git clone)...${NC}"
    sudo rm -rf /opt/ctfr 2>/dev/null || true
    GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=echo git clone --depth=1 https://github.com/UnaPibaGeek/ctfr /opt/ctfr 2>/dev/null && \
    python3 -m venv /opt/ctfr/.venv 2>/dev/null && \
    /opt/ctfr/.venv/bin/pip install requests -q 2>/dev/null || true && \
    printf '#!/bin/bash\nexec /opt/ctfr/.venv/bin/python3 /opt/ctfr/ctfr.py "$@"\n' | sudo tee /usr/local/bin/ctfr > /dev/null && \
    sudo chmod +x /usr/local/bin/ctfr && \
    echo -e "${GREEN}[✓] ctfr installed${NC}" || \
    echo -e "${YELLOW}[!] ctfr install failed${NC}"
fi
# ── v5.4.0 NEW: spoofcheck — git clone (not on PyPI) ─────────────────────────
if ! command -v spoofcheck &>/dev/null; then
    echo -e "${DIM}  Installing spoofcheck (git clone)...${NC}"
    sudo rm -rf /opt/spoofcheck 2>/dev/null || true
    GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=echo git clone --depth=1 https://github.com/BishopFox/spoofcheck /opt/spoofcheck 2>/dev/null && \
    python3 -m venv /opt/spoofcheck/.venv 2>/dev/null && \
    (/opt/spoofcheck/.venv/bin/pip install -r /opt/spoofcheck/requirements.txt -q 2>/dev/null || \
     /opt/spoofcheck/.venv/bin/pip install dnspython pyspf -q 2>/dev/null || true) && \
    printf '#!/bin/bash\nexec /opt/spoofcheck/.venv/bin/python3 /opt/spoofcheck/spoofcheck.py "$@"\n' | sudo tee /usr/local/bin/spoofcheck > /dev/null && \
    sudo chmod +x /usr/local/bin/spoofcheck && \
    echo -e "${GREEN}[✓] spoofcheck installed${NC}" || \
    echo -e "${YELLOW}[!] spoofcheck install failed${NC}"
fi
# ── v5.4.0 NEW: rustscan — apt (Kali has it), fallback cargo ─────────────────
if ! command -v rustscan &>/dev/null; then
    sudo apt-get install -y rustscan -qq 2>/dev/null || \
    (command -v cargo &>/dev/null && cargo install rustscan 2>/dev/null && \
     for d in "$HOME/.cargo/bin" "/root/.cargo/bin"; do [ -f "$d/rustscan" ] && sudo ln -sf "$d/rustscan" /usr/local/bin/rustscan && break; done) || true
fi
# ── v5.4.0 NEW: enum4linux-ng — apt ──────────────────────────────────────────
command -v enum4linux-ng &>/dev/null || sudo apt-get install -y enum4linux-ng -qq 2>/dev/null || true
echo -e "${DIM}  Installing Tier 3 recon tools (crosslinked, enum4linux-ng, dorks_hunter, analyticsrelationships, gitleaks)...${NC}"
# crosslinked — LinkedIn employee enum
command -v crosslinked &>/dev/null || pip3 install crosslinked --break-system-packages -q 2>/dev/null || true
# enum4linux-ng — SMB/LDAP enumeration
command -v enum4linux-ng &>/dev/null || pip3 install enum4linux-ng --break-system-packages -q 2>/dev/null || sudo apt-get install -y enum4linux -qq 2>/dev/null || true
# snmpwalk — SNMP enumeration
command -v snmpwalk &>/dev/null || sudo apt-get install -y snmp -qq 2>/dev/null || true
# dorks_hunter — Google dorking
if ! command -v dorks_hunter &>/dev/null; then
    pip3 install dorks-hunter --break-system-packages -q 2>/dev/null || \
    (git clone --depth=1 https://github.com/six2dez/dorks_hunter /opt/dorks_hunter 2>/dev/null && \
    pip3 install -r /opt/dorks_hunter/requirements.txt --break-system-packages -q 2>/dev/null && \
    printf '#!/bin/bash\npython3 /opt/dorks_hunter/dorks_hunter.py "$@"\n' | sudo tee /usr/local/bin/dorks_hunter > /dev/null && \
    sudo chmod +x /usr/local/bin/dorks_hunter 2>/dev/null) || true
fi
# analyticsrelationships — Google Analytics subdomain discovery
command -v analyticsrelationships &>/dev/null || (go install github.com/Josue87/analyticsrelationships@latest 2>/dev/null && symlink_go_tool "analyticsrelationships") || true
# gitleaks — git secret detection (use binary release, not go install — module path conflict)
if ! command -v gitleaks &>/dev/null; then
    echo -e "${DIM}  Installing gitleaks (binary release)...${NC}"
    GITLEAKS_VER=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep '"tag_name"' | cut -d'"' -f4 | tr -d 'v' 2>/dev/null || echo "8.21.2")
    GITLEAKS_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER}_linux_x64.tar.gz"
    curl -fsSL "$GITLEAKS_URL" -o /tmp/gitleaks.tar.gz 2>/dev/null && \
    mkdir -p /tmp/gitleaks_extract && \
    tar -xzf /tmp/gitleaks.tar.gz -C /tmp/gitleaks_extract 2>/dev/null && \
    sudo cp /tmp/gitleaks_extract/gitleaks /usr/local/bin/gitleaks && \
    sudo chmod +x /usr/local/bin/gitleaks && \
    rm -rf /tmp/gitleaks.tar.gz /tmp/gitleaks_extract && \
    echo -e "${GREEN}[✓] gitleaks installed${NC}" || \
    echo -e "${YELLOW}[!] gitleaks install failed${NC}"
fi

# ── reconftw — Full reconFTW power (Mega Mode) ───────────────────────────────
# reconftw is the backbone of CyberMind's recon mode — 50+ tools in one
# Modes: -s (subdomain, 15min), -r (full recon, 2-4h), -a --deep (all, 6-12h)
if ! command -v reconftw &>/dev/null || [ ! -f /opt/reconftw/reconftw.sh ]; then
    echo -e "${DIM}  Installing reconftw (Mega Mode — 5-10 min)...${NC}"
    # Remove stale install if exists
    [ -d /opt/reconftw ] && sudo rm -rf /opt/reconftw 2>/dev/null || true
    # Clone with credential prompt disabled — public repo, no auth needed
    GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=echo \
    GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=echo git clone --depth=1 https://github.com/six2dez/reconftw.git /opt/reconftw 2>/dev/null && \
    chmod +x /opt/reconftw/reconftw.sh /opt/reconftw/install.sh && \
    (cd /opt/reconftw && GIT_TERMINAL_PROMPT=0 timeout 600 bash install.sh 2>/dev/null || true) && \
    printf '#!/bin/bash\nexec bash /opt/reconftw/reconftw.sh "$@"\n' | sudo tee /usr/local/bin/reconftw > /dev/null && \
    sudo chmod +x /usr/local/bin/reconftw && \
    echo -e "${GREEN}[✓] reconftw installed${NC}" || \
    echo -e "${YELLOW}[!] reconftw install failed — run: sudo cybermind /doctor${NC}"
elif [ -f /opt/reconftw/reconftw.sh ]; then
    # Update existing reconftw to latest
    echo -e "${DIM}  Updating reconftw to latest...${NC}"
    (cd /opt/reconftw && GIT_TERMINAL_PROMPT=0 git pull --ff-only 2>/dev/null || true)
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
echo -e "  ${BOLD}${YELLOW}NEW in v5.0.0:${NC}"
echo -e "  ${DIM}  • Tier 1: wafw00f, dnsrecon, uncover, shuffledns, cdncheck, smap, rustscan, dnstake${NC}"
echo -e "  ${DIM}  • Tier 2: ctfr, mapcidr, sslscan, uro, misconfig-mapper, second-order, testssl${NC}"
echo -e "  ${DIM}  • Tier 3: crosslinked, enum4linux-ng, dorks_hunter, analyticsrelationships, gitleaks${NC}"
echo -e "  ${DIM}  • nuclei takeover + token templates in recon phase${NC}"
echo -e "  ${DIM}  • Recon Brain: attack surface analysis, priority scoring, hunt focus generation${NC}"
echo -e "  ${DIM}  • OMEGA: full recon intelligence fed into agentic loop${NC}"
echo -e "  ${DIM}  • 50+ total recon tools across 6 phases${NC}"
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
