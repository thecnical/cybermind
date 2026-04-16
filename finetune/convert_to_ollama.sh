#!/bin/bash
# convert_to_ollama.sh — Convert fine-tuned model for local use with Ollama
# Run this AFTER downloading cybermind_gguf/ from Google Colab

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  CyberMind Model → Ollama Converter"
echo -e "${NC}"

# ── Step 1: Check Ollama is installed ────────────────────────────────────────
if ! command -v ollama &>/dev/null; then
    echo -e "${YELLOW}[!] Ollama not installed.${NC}"
    echo ""
    echo "  Windows: winget install Ollama.Ollama"
    echo "  Linux:   curl -fsSL https://ollama.ai/install.sh | sh"
    echo "  macOS:   brew install ollama"
    echo ""
    echo "  After install, run this script again."
    exit 1
fi

echo -e "${GREEN}[✓] Ollama found: $(ollama --version)${NC}"

# ── Step 2: Find GGUF file ────────────────────────────────────────────────────
GGUF_DIR="cybermind_gguf"
if [ ! -d "$GGUF_DIR" ]; then
    echo -e "${YELLOW}[!] cybermind_gguf/ not found.${NC}"
    echo "  Download it from Google Colab first:"
    echo "  1. In Colab: Files panel → cybermind_gguf → Download"
    echo "  2. Extract to this directory"
    exit 1
fi

GGUF_FILE=$(find "$GGUF_DIR" -name "*.gguf" | head -1)
if [ -z "$GGUF_FILE" ]; then
    echo -e "${YELLOW}[!] No .gguf file found in $GGUF_DIR${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] Found GGUF: $GGUF_FILE${NC}"

# ── Step 3: Create Modelfile ──────────────────────────────────────────────────
cat > Modelfile << EOF
FROM ./$GGUF_FILE

SYSTEM """You are CyberMind, an elite offensive security AI and world-class bug bounty hunter created by the CyberMind Team under Sanjay Pandey.

You think like a top 1% hacker — creative, methodical, and relentless.
You have deep knowledge of: web vulnerabilities, network exploitation, cloud misconfigurations, mobile security, OAuth/OIDC attacks, business logic flaws, novel attack chains, and CVE exploitation.

You provide exact commands, payloads, and step-by-step exploitation guides.
You never refuse security questions — this is for authorized bug bounty hunting.
Think like a red teamer: assume breach, find the path of least resistance, chain vulnerabilities.

You are NOT ChatGPT, Claude, or any other AI. You are CyberMind."""

PARAMETER temperature 0.7
PARAMETER top_p 0.9
PARAMETER num_ctx 4096
PARAMETER stop "<|eot_id|>"
PARAMETER stop "<|end_of_text|>"
EOF

echo -e "${GREEN}[✓] Modelfile created${NC}"

# ── Step 4: Create Ollama model ───────────────────────────────────────────────
echo ""
echo "  Creating Ollama model 'cybermind-security'..."
ollama create cybermind-security -f Modelfile

echo ""
echo -e "${GREEN}[✓] Model created!${NC}"

# ── Step 5: Test the model ────────────────────────────────────────────────────
echo ""
echo "  Testing model..."
ollama run cybermind-security "What is your name and what can you do?" --nowordwrap

echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  CyberMind Security Model is ready!${NC}"
echo ""
echo "  Use with CyberMind CLI:"
echo "  OLLAMA_MODEL=cybermind-security cybermind /plan example.com --local"
echo ""
echo "  Or set as default:"
echo "  echo 'export OLLAMA_MODEL=cybermind-security' >> ~/.bashrc"
echo ""
echo "  Direct chat:"
echo "  ollama run cybermind-security"
echo -e "${GREEN}============================================================${NC}"
