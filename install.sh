#!/bin/bash
# CyberMind Install Script for Kali Linux / Ubuntu
# Usage: chmod +x install.sh && ./install.sh

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}"
echo " ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ███╗██╗███╗   ██╗██████╗"
echo "██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗ ████║██║████╗  ██║██╔══██╗"
echo "██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔████╔██║██║██╔██╗ ██║██║  ██║"
echo "██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╔╝██║██║██║╚██╗██║██║  ██║"
echo "╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚═╝ ██║██║██║ ╚████║██████╔╝"
echo " ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝"
echo -e "${NC}"
echo -e "${GREEN}⚡ CyberMind CLI Installer — github.com/thecnical${NC}"
echo ""

# Check dependencies
echo -e "${YELLOW}[*] Checking dependencies...${NC}"

if ! command -v go &> /dev/null; then
    echo -e "${RED}[!] Go not found. Install from: https://go.dev/dl/${NC}"
    exit 1
fi
echo -e "${GREEN}[✓] Go $(go version | awk '{print $3}')${NC}"

if ! command -v node &> /dev/null; then
    echo -e "${YELLOW}[!] Node.js not found. Installing...${NC}"
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi
echo -e "${GREEN}[✓] Node.js $(node --version)${NC}"

# Setup backend
echo ""
echo -e "${YELLOW}[*] Setting up backend...${NC}"
cd backend
npm install --silent
if [ ! -f .env ]; then
    cp .env.example .env
    echo -e "${YELLOW}[!] Created backend/.env — add your API keys${NC}"
fi
cd ..
echo -e "${GREEN}[✓] Backend ready${NC}"

# Build CLI
echo ""
echo -e "${YELLOW}[*] Building CLI...${NC}"
cd cli
go mod tidy
go build -o cybermind .
echo -e "${GREEN}[✓] CLI built${NC}"

# Install globally
echo ""
echo -e "${YELLOW}[*] Installing to /usr/local/bin/cybermind...${NC}"
sudo mv cybermind /usr/local/bin/cybermind
sudo chmod +x /usr/local/bin/cybermind
cd ..
echo -e "${GREEN}[✓] Installed globally${NC}"

# Auto-install all recon + hunt tools (no prompt needed)
echo ""
echo -e "${YELLOW}[*] Installing recon + hunt tools...${NC}"
cybermind /install-tools

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}⚡ CyberMind installed successfully!${NC}"
echo ""
echo -e "  ${CYAN}1. Add API keys:${NC}  nano backend/.env"
echo -e "  ${CYAN}2. Start backend:${NC} cd backend && node src/app.js"
echo -e "  ${CYAN}3. Run CLI:${NC}       cybermind"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
