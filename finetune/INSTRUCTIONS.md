# CyberMind AI Fine-Tuning — Complete Instructions

## Kya Milega

Ek fully uncensored, security-focused AI jo:
- Top 1% bug bounty hunter ki tarah sochta hai
- Har attack technique, CVE, aur bypass method jaanta hai
- Autonomous decisions leta hai agentic pipeline mein
- Exact commands, payloads, aur PoCs deta hai

---

## Step-by-Step (Bilkul Simple)

### Step 1: API Keys Lelo (Free)

**Kaggle API Key:**
1. [kaggle.com](https://kaggle.com) → Login/Signup (free)
2. Top right → Profile icon → Account
3. Scroll down → API section → **Create New Token**
4. `kaggle.json` download hoga — open karo
5. Copy karo: `username` aur `key`

**HuggingFace Token:**
1. [huggingface.co](https://huggingface.co) → Sign up (free)
2. Top right → Settings → Access Tokens
3. **New token** → Name: `cybermind` → Role: **Write** → Generate
4. Token copy karo (starts with `hf_`)

---

### Step 2: Colab Open Karo

1. [colab.research.google.com](https://colab.research.google.com) → New notebook
2. **Runtime** → Change runtime type → **T4 GPU** → Save
3. File → Upload notebook → Select `CyberMind_FineTune_Auto.ipynb`

---

### Step 3: Credentials Dalo

Notebook mein **Cell 2** aur **Cell 3** edit karo:

**Cell 2:**
```python
KAGGLE_USERNAME = "your_username"  # ← Yahan dalo
KAGGLE_KEY = "your_key"            # ← Yahan dalo
```

**Cell 3:**
```python
HF_TOKEN = "hf_your_token"  # ← Yahan dalo
```

---

### Step 4: Run All

**Runtime** → **Run All** (ya Ctrl+F9)

Bas. Ab 2-3 hours wait karo. Sab automatic ho jayega:
- Dependencies install (10 min)
- Model download (10 min)
- Datasets download (15 min)
- Training (90-120 min)
- Model save (5 min)
- HuggingFace upload (10 min)

---

### Step 5: Backend Mein Enable Karo

Training complete hone ke baad:

1. Edit file: `cybermind-backend/src/routes/free.js`
2. Line 22 pe yeh uncomment karo:
   ```javascript
   { id: "thecnical/cybermind-security", name: "CyberMind Security" },
   ```
3. Push karo:
   ```bash
   cd cybermind-backend
   git add -A
   git commit -m "enable cybermind-security model"
   git push
   ```

Render automatically deploy kar dega (2 minutes).

---

## Ab Sabke Liye Free Hai

Koi bhi user bina API key ke use kar sakta hai:

```bash
cybermind "how do I find XSS?"
cybermind "explain Log4Shell"
cybermind "what is SSRF?"
```

Backend automatically tumhara fine-tuned model use karega — free for everyone.

---

## Agar Colab Disconnect Ho Jaye

T4 GPU sirf 4 hours milti hai free mein. Agar disconnect ho jaye:

**Resume training:**
```python
# Last cell mein yeh add karo
trainer.train(resume_from_checkpoint=True)
```

**Ya phir:**
- Colab Pro lelo ($10/month) → 24 hours GPU
- Ya training ko 2-3 sessions mein complete karo

---

## Troubleshooting

**Error: "Kaggle credentials not found"**
→ Cell 2 mein username/key sahi se dala?

**Error: "HuggingFace login failed"**
→ Cell 3 mein token sahi hai? `hf_` se shuru hona chahiye

**Error: "CUDA out of memory"**
→ Runtime restart karo: Runtime → Restart runtime
→ Phir Run All dobara

**Error: "Model download failed"**
→ Internet slow hai. Retry karo.

---

## Files Download Karne Hain (Optional)

Training ke baad agar local use karna hai:

1. Colab Files panel (left sidebar) → `cybermind_lora/` folder
2. Right click → Download
3. Apne PC pe: `ollama create cybermind -f Modelfile`

But **zarurat nahi** — HuggingFace pe upload ho gaya toh backend automatically use karega.

---

## Questions?

Agar koi step mein problem aaye toh screenshot bhejo. Main fix kar dunga.
