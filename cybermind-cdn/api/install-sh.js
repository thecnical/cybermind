// Serves install.sh — EMBEDDED directly (no GitHub proxy = no cache issues)
// Version: 4.1.0
// Last updated: 2026-04-16

module.exports = (req, res) => {
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("X-CyberMind-Version", "4.1.0");

  const script = `#!/bin/bash
# CyberMind CLI Installer v4.1.0 — Kali Linux / Ubuntu / Debian
# Usage: curl -sL https://cybermindcli1.vercel.app/install.sh | bash
# Usage: CYBERMIND_KEY=cp_live_xxx curl -sL https://cybermindcli1.vercel.app/install.sh | bash

set -e

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
VERSION="4.1.0"

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

# ── Step 1: Download binary ───────────────────────────────────────────────────
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
    [ -f "\$profile" ] && ! grep -q "go/bin" "\$profile" && \
        echo 'export PATH=\$PATH:\$HOME/go/bin:/usr/local/go/bin' >> "\$profile" || true
done

# ── Step 5: Essential tools ───────────────────────────────────────────────────
echo ""
echo -e "\${BOLD}\${YELLOW}[*] Installing essential tools...\${NC}"
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq 2>/dev/null || true
sudo apt-get install -y nmap ffuf feroxbuster gobuster nikto sqlmap commix wpscan \\
    libpcap-dev python3-pip pipx git curl wget whois dnsutils -qq 2>/dev/null || true

symlink_go_tool() {
    local bin="\$1"
    for gobin in "\$HOME/go/bin" "/root/go/bin"; do
        [ -f "\$gobin/\$bin" ] && sudo ln -sf "\$gobin/\$bin" "/usr/local/bin/\$bin" 2>/dev/null && return
    done
}

for entry in \\
    "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder" \\
    "httpx:github.com/projectdiscovery/httpx/cmd/httpx" \\
    "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei" \\
    "naabu:github.com/projectdiscovery/naabu/v2/cmd/naabu" \\
    "katana:github.com/projectdiscovery/katana/cmd/katana" \\
    "gau:github.com/lc/gau/v2/cmd/gau" \\
    "waybackurls:github.com/tomnomnom/waybackurls" \\
    "dalfox:github.com/hahwul/dalfox/v2" \\
    "dnsx:github.com/projectdiscovery/dnsx/cmd/dnsx" \\
    "gf:github.com/tomnomnom/gf" \\
    "interactsh-client:github.com/projectdiscovery/interactsh/cmd/interactsh-client"; do
    bin="\${entry%%:*}"; module="\${entry##*:}"
    command -v "\$bin" &>/dev/null || (go install "\${module}@latest" 2>/dev/null && symlink_go_tool "\$bin") || true
done

for tool in shodan h8mail arjun wafw00f; do
    command -v "\$tool" &>/dev/null || pipx install "\$tool" 2>/dev/null || \\
        pip3 install "\$tool" --break-system-packages -q 2>/dev/null || true
done

command -v trufflehog &>/dev/null || \\
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \\
    | sh -s -- -b /usr/local/bin 2>/dev/null || true

command -v gf &>/dev/null && [ ! -d "\$HOME/.gf" ] && \\
    git clone --depth=1 https://github.com/1ndianl33t/Gf-Patterns "\$HOME/.gf" 2>/dev/null || true

command -v nuclei &>/dev/null && nuclei -update-templates 2>/dev/null || true

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "\${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\${NC}"
echo -e "\${BOLD}\${GREEN}⚡ CyberMind CLI v\${VERSION} installed!\${NC}"
echo ""
echo -e "  \${CYAN}Verify:\${NC}        cybermind --version"
echo -e "  \${CYAN}Doctor:\${NC}        sudo cybermind /doctor"
echo -e "  \${CYAN}OMEGA Plan:\${NC}    sudo cybermind /plan --auto-target"
echo -e "  \${CYAN}Overnight:\${NC}     sudo cybermind /plan --auto-target --mode overnight --continuous"
echo -e "  \${CYAN}BizLogic:\${NC}      sudo cybermind /bizlogic example.com"
echo -e "  \${CYAN}Manual Guide:\${NC}  sudo cybermind /guide example.com"
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
