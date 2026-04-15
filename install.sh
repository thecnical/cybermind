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
VERSION="4.0.0"

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
)
for entry in "${GO_TOOLS[@]}"; do
    bin="${entry%%:*}"; module="${entry##*:}"
    if ! command -v "$bin" &>/dev/null; then
        go install "${module}@latest" 2>/dev/null && symlink_go_tool "$bin" || true
    fi
done

# ── Python tools via pipx ─────────────────────────────────────────────────────
echo -e "${DIM}  Installing Python tools...${NC}"
PIPX_TOOLS=(shodan h8mail wafw00f arjun graphw00f waymore)
for tool in "${PIPX_TOOLS[@]}"; do
    command -v "$tool" &>/dev/null || pipx install "$tool" 2>/dev/null || pip3 install "$tool" --break-system-packages -q 2>/dev/null || true
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

# ── Additional exploit tools ──────────────────────────────────────────────────
echo -e "${DIM}  Installing additional tools...${NC}"
# Slither (smart contract analysis)
command -v slither &>/dev/null || pip3 install slither-analyzer --break-system-packages -q 2>/dev/null || true
# APK tools (mobile)
command -v apktool &>/dev/null || sudo apt-get install -y apktool -qq 2>/dev/null || true
# HTTP smuggling
command -v smuggler &>/dev/null || (git clone --depth=1 https://github.com/defparam/smuggler /opt/smuggler 2>/dev/null && \
    pip3 install -r /opt/smuggler/requirements.txt --break-system-packages -q 2>/dev/null && \
    printf '#!/bin/bash\npython3 /opt/smuggler/smuggler.py "$@"\n' | sudo tee /usr/local/bin/smuggler > /dev/null && \
    sudo chmod +x /usr/local/bin/smuggler) 2>/dev/null || true

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}${GREEN}⚡ CyberMind CLI v${VERSION} installed!${NC}"
echo ""
echo -e "  ${CYAN}Verify:${NC}        cybermind --version"
echo -e "  ${CYAN}AI Chat:${NC}       cybermind"
echo -e "  ${CYAN}Doctor:${NC}        sudo cybermind /doctor"
echo -e "  ${CYAN}Recon:${NC}         sudo cybermind /recon example.com"
echo -e "  ${CYAN}Hunt:${NC}          sudo cybermind /hunt example.com"
echo -e "  ${CYAN}OMEGA Plan:${NC}    sudo cybermind /plan --auto-target"
echo -e "  ${CYAN}Auto-Target:${NC}   sudo cybermind /plan --auto-target --skill intermediate --focus idor,xss"
echo -e "  ${CYAN}Overnight:${NC}     sudo cybermind /plan --auto-target --mode overnight --continuous"
echo -e "  ${CYAN}BizLogic:${NC}      sudo cybermind /bizlogic example.com"
echo -e "  ${CYAN}Manual Guide:${NC}  sudo cybermind /guide example.com"
echo -e "  ${CYAN}Vibe Coder:${NC}    cybermind /vibe"
echo ""
echo -e "  ${DIM}Full tool install: sudo cybermind /doctor${NC}"
echo -e "  ${DIM}Browser tests:     Playwright auto-installed above${NC}"
echo -e "  ${DIM}OOB verification:  interactsh-client auto-installed above${NC}"
echo ""
if [ -n "$CYBERMIND_KEY" ]; then
    echo -e "  ${GREEN}✓ API key saved — run: cybermind whoami${NC}"
    echo ""
fi
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
