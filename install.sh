#!/bin/bash
# CyberMind CLI Installer — Kali Linux / Ubuntu / Debian
# Downloads pre-built binary from GitHub (fast, no Go needed)
# Usage: curl -sL https://raw.githubusercontent.com/thecnical/cybermind/main/install.sh | bash
# Usage: CYBERMIND_KEY=cp_live_xxx curl -sL https://raw.githubusercontent.com/thecnical/cybermind/main/install.sh | bash

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
DIM='\033[0;90m'
NC='\033[0m'

GITHUB_RAW="https://raw.githubusercontent.com/thecnical/cybermind/main/cli"
INSTALL_PATH="/usr/local/bin/cybermind"
CBM_PATH="/usr/local/bin/cbm"

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
echo -e "${GREEN}⚡ CyberMind CLI Installer v2.5.2${NC}"
echo ""

# ── Detect arch ───────────────────────────────────────────────────────────────
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  BINARY="cybermind-linux-amd64" ;;
    aarch64) BINARY="cybermind-linux-arm64" ;;
    arm64)   BINARY="cybermind-linux-arm64" ;;
    *)
        echo -e "${RED}[!] Unsupported architecture: $ARCH${NC}"
        echo -e "${YELLOW}    Falling back to build from source...${NC}"
        BINARY=""
        ;;
esac

# ── Step 1: Download pre-built binary from GitHub ─────────────────────────────
if [ -n "$BINARY" ]; then
    echo -e "${YELLOW}[*] Downloading CyberMind CLI binary...${NC}"
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

    # Verify download succeeded and file is a valid binary (>1MB)
    if [ "$HTTP_CODE" = "200" ] && [ -f "$TMP_BIN" ] && [ "$(stat -c%s "$TMP_BIN" 2>/dev/null || stat -f%z "$TMP_BIN")" -gt 1048576 ]; then
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
        echo -e "${YELLOW}[!] Binary download failed (HTTP $HTTP_CODE). Building from source...${NC}"
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

    # Clone or update repo
    REPO_DIR="/tmp/cybermind-src-$$"
    echo -e "${YELLOW}[*] Cloning CyberMind repo...${NC}"
    git clone --depth=1 https://github.com/thecnical/cybermind.git "$REPO_DIR" 2>/dev/null
    cd "$REPO_DIR/cli"
    go mod tidy -q
    go build -ldflags="-X main.Version=2.5.2" -o /tmp/cybermind-built .
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

# ── Step 5: Install recon + hunt tools ───────────────────────────────────────
echo ""
echo -e "${YELLOW}[*] Installing recon + hunt tools (background)...${NC}"
echo -e "${DIM}    Run: sudo cybermind /doctor  to check + install all tools${NC}"

# Quick apt tools (non-blocking essentials)
sudo apt-get update -qq 2>/dev/null || true
for tool in nmap masscan whois dnsutils theharvester whatweb ffuf gobuster nikto amass libpcap-dev; do
    command -v "$tool" &>/dev/null || sudo apt-get install -y "$tool" -qq 2>/dev/null || true
done

# Go tools
symlink_go_tool() {
    local bin="$1"
    for gobin in "$HOME/go/bin" "/root/go/bin"; do
        [ -f "$gobin/$bin" ] && sudo ln -sf "$gobin/$bin" "/usr/local/bin/$bin" 2>/dev/null && return
    done
}
for entry in \
    "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder" \
    "httpx:github.com/projectdiscovery/httpx/cmd/httpx" \
    "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei" \
    "dnsx:github.com/projectdiscovery/dnsx/cmd/dnsx" \
    "katana:github.com/projectdiscovery/katana/cmd/katana" \
    "gau:github.com/lc/gau/v2/cmd/gau" \
    "waybackurls:github.com/tomnomnom/waybackurls" \
    "dalfox:github.com/hahwul/dalfox/v2"; do
    bin="${entry%%:*}"; module="${entry##*:}"
    command -v "$bin" &>/dev/null || (go install "${module}@latest" 2>/dev/null && symlink_go_tool "$bin") || true
done

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}⚡ CyberMind CLI v2.5.2 installed!${NC}"
echo ""
echo -e "  ${CYAN}Verify:${NC}      cybermind --version"
echo -e "  ${CYAN}AI Chat:${NC}     cybermind"
echo -e "  ${CYAN}Doctor:${NC}      sudo cybermind /doctor"
echo -e "  ${CYAN}Recon:${NC}       sudo cybermind /recon example.com"
echo -e "  ${CYAN}Hunt:${NC}        sudo cybermind /hunt example.com"
echo -e "  ${CYAN}OMEGA Plan:${NC}  sudo cybermind /plan --auto-target"
echo ""
if [ -n "$CYBERMIND_KEY" ]; then
    echo -e "  ${GREEN}✓ API key saved — run: cybermind whoami${NC}"
fi
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
