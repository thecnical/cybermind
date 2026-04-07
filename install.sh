#!/bin/bash
# CyberMind CLI Installer for Kali Linux / Ubuntu
# Backend is hosted on Render — no local backend setup needed.
# Usage: chmod +x install.sh && sudo ./install.sh

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

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
echo -e "${GREEN}⚡ CyberMind CLI Installer v2.5.0 — github.com/thecnical${NC}"
echo ""

# ── Step 1: Check Go ──────────────────────────────────────────────────────────
echo -e "${YELLOW}[*] Checking Go...${NC}"
if ! command -v go &> /dev/null; then
    echo -e "${YELLOW}[!] Go not found. Installing Go 1.22...${NC}"
    wget -q https://go.dev/dl/go1.22.0.linux-amd64.tar.gz -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    # Add to all shell profiles
    for profile in /root/.bashrc /root/.zshrc /home/*/.bashrc /home/*/.zshrc; do
        [ -f "$profile" ] && grep -q "/usr/local/go/bin" "$profile" || \
            echo 'export PATH=$PATH:/usr/local/go/bin' >> "$profile" 2>/dev/null || true
    done
fi
echo -e "${GREEN}[✓] Go $(go version | awk '{print $3}')${NC}"

# ── Step 2: Build CLI ─────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[*] Building CyberMind CLI...${NC}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI_DIR="$SCRIPT_DIR/cli"

if [ ! -d "$CLI_DIR" ]; then
    echo -e "${RED}[!] cli/ directory not found. Make sure you cloned the full repo.${NC}"
    echo -e "${RED}    git clone https://github.com/thecnical/cybermind.git${NC}"
    exit 1
fi

cd "$CLI_DIR"
go mod tidy
go build -o cybermind .
echo -e "${GREEN}[✓] CLI built successfully${NC}"

# ── Step 3: Install globally ──────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[*] Installing to /usr/local/bin/cybermind...${NC}"
sudo cp cybermind /usr/local/bin/cybermind
sudo chmod +x /usr/local/bin/cybermind
rm -f cybermind  # clean up local binary
cd "$SCRIPT_DIR"
echo -e "${GREEN}[✓] cybermind installed globally${NC}"

# ── Step 4: Configure Go PATH ─────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[*] Configuring Go PATH for tools...${NC}"
GOBIN_PATH="$HOME/go/bin"
ROOT_GOBIN="/root/go/bin"

# Add to shell profiles
for profile in ~/.bashrc ~/.zshrc ~/.profile /root/.bashrc /root/.zshrc; do
    if [ -f "$profile" ] && ! grep -q "go/bin" "$profile"; then
        echo 'export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin' >> "$profile"
    fi
done
export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin:/root/go/bin
echo -e "${GREEN}[✓] Go PATH configured${NC}"

# ── Step 5: Install recon + hunt tools ───────────────────────────────────────
echo ""
echo -e "${YELLOW}[*] Installing all recon + hunt tools...${NC}"
echo -e "${CYAN}    This may take 5-10 minutes...${NC}"
echo ""

# Symlink helper
symlink_go_tool() {
    local bin="$1"
    for gobin in "$HOME/go/bin" "/root/go/bin" "/usr/local/go/bin"; do
        if [ -f "$gobin/$bin" ]; then
            sudo ln -sf "$gobin/$bin" "/usr/local/bin/$bin" 2>/dev/null || true
            return
        fi
    done
}

# apt tools
echo -e "${CYAN}  [1/4] Installing apt tools...${NC}"
sudo apt-get update -qq 2>/dev/null || true
for tool in nmap masscan whois dnsutils theharvester whatweb ffuf feroxbuster gobuster nikto amass libpcap-dev build-essential cargo; do
    if command -v "$tool" &>/dev/null || dpkg -l "$tool" &>/dev/null 2>&1; then
        echo -e "${GREEN}  ✓ $tool (already installed)${NC}"
    else
        echo -e "${CYAN}  ⟳ $tool installing...${NC}"
        sudo apt-get install -y "$tool" -qq 2>/dev/null && \
            echo -e "${GREEN}  ✓ $tool${NC}" || \
            echo -e "${YELLOW}  ⚡ $tool failed (skip)${NC}"
    fi
done

# rustscan
echo -e "${CYAN}  [2/4] Installing rustscan...${NC}"
if command -v rustscan &>/dev/null; then
    echo -e "${GREEN}  ✓ rustscan (already installed)${NC}"
else
    RUSTSCAN_URL=$(curl -s https://api.github.com/repos/RustScan/RustScan/releases/latest \
        | grep browser_download_url | grep amd64.deb | cut -d'"' -f4 2>/dev/null)
    if [ -n "$RUSTSCAN_URL" ]; then
        curl -sL "$RUSTSCAN_URL" -o /tmp/rustscan.deb && \
            sudo dpkg -i /tmp/rustscan.deb && \
            echo -e "${GREEN}  ✓ rustscan${NC}" || \
            echo -e "${YELLOW}  ⚡ rustscan failed (skip)${NC}"
    fi
fi

# Go tools
echo -e "${CYAN}  [3/4] Installing Go tools...${NC}"
GO_TOOLS=(
    "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    "httpx:github.com/projectdiscovery/httpx/cmd/httpx"
    "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
    "naabu:github.com/projectdiscovery/naabu/v2/cmd/naabu"
    "dnsx:github.com/projectdiscovery/dnsx/cmd/dnsx"
    "tlsx:github.com/projectdiscovery/tlsx/cmd/tlsx"
    "katana:github.com/projectdiscovery/katana/cmd/katana"
    "gau:github.com/lc/gau/v2/cmd/gau"
    "waybackurls:github.com/tomnomnom/waybackurls"
    "dalfox:github.com/hahwul/dalfox/v2"
)
for entry in "${GO_TOOLS[@]}"; do
    bin="${entry%%:*}"
    module="${entry##*:}"
    if command -v "$bin" &>/dev/null; then
        echo -e "${GREEN}  ✓ $bin (already installed)${NC}"
    else
        echo -e "${CYAN}  ⟳ $bin installing...${NC}"
        go install "${module}@latest" 2>/dev/null && \
            symlink_go_tool "$bin" && \
            echo -e "${GREEN}  ✓ $bin${NC}" || \
            echo -e "${YELLOW}  ⚡ $bin failed (skip)${NC}"
    fi
done

# x8 via cargo
echo -e "${CYAN}  [4/4] Installing x8...${NC}"
if command -v x8 &>/dev/null; then
    echo -e "${GREEN}  ✓ x8 (already installed)${NC}"
elif command -v cargo &>/dev/null; then
    cargo install x8 2>/dev/null && \
        sudo ln -sf "$HOME/.cargo/bin/x8" /usr/local/bin/x8 2>/dev/null || true && \
        echo -e "${GREEN}  ✓ x8${NC}" || \
        echo -e "${YELLOW}  ⚡ x8 failed (skip)${NC}"
fi

# ── Step 6: Verify installation ───────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[*] Verifying installation...${NC}"
if command -v cybermind &>/dev/null; then
    echo -e "${GREEN}[✓] cybermind installed: $(cybermind --version 2>/dev/null || echo 'v2.5.0')${NC}"
else
    echo -e "${RED}[!] cybermind not found in PATH. Try: export PATH=\$PATH:/usr/local/bin${NC}"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}⚡ CyberMind CLI installed successfully!${NC}"
echo ""
echo -e "  ${CYAN}Verify:${NC}    cybermind --version"
echo -e "  ${CYAN}AI Chat:${NC}   cybermind"
echo -e "  ${CYAN}Recon:${NC}     cybermind /recon example.com"
echo -e "  ${CYAN}Hunt:${NC}      cybermind /hunt example.com"
echo -e "  ${CYAN}Doctor:${NC}    cybermind /doctor"
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
