# 🚀 Quick Start — 3 Steps Only

## Step 1: Download Notebook

Download: [CyberMind_FineTune.ipynb](https://github.com/thecnical/cybermind/blob/main/finetune/CyberMind_FineTune.ipynb)

## Step 2: Edit 2 Lines

Open notebook, edit **Cell 2** and **Cell 3**:

**Cell 2 (Kaggle — Already Done):**
```python
KAGGLE_USERNAME = "cybermindcli"
KAGGLE_KEY = "d946427f9e4d90b7e3438f061b80b485"
```
✅ Already set — no change needed!

**Cell 3 (HuggingFace — You need this):**
```python
HF_TOKEN = "hf_YOUR_TOKEN_HERE"  # ← Change this
```

Get HF token (free, 30 seconds):
1. [huggingface.co](https://huggingface.co) → Sign up
2. Settings → Access Tokens → New token
3. Name: `cybermind`, Role: **Write** → Generate
4. Copy token (starts with `hf_`)

## Step 3: Run All

1. Upload notebook to [colab.research.google.com](https://colab.research.google.com)
2. Runtime → Change runtime type → **T4 GPU** → Save
3. Runtime → **Run All**
4. Wait 2 hours ☕

Done! Model automatically uploads to HuggingFace and becomes free for everyone.

---

## What Happens Automatically

- ✅ GPU check
- ✅ Kaggle setup (already configured)
- ✅ HuggingFace login
- ✅ Install dependencies
- ✅ Download Llama 3.2 3B model
- ✅ Download Kaggle bug-hunter dataset
- ✅ Download Figshare CVE dataset
- ✅ Add synthetic security dataset
- ✅ Format for training
- ✅ Train for 3 epochs (~2 hours)
- ✅ Save model
- ✅ Upload to HuggingFace
- ✅ Test the model

---

## After Training

**Enable in backend (1 line):**

Edit `cybermind-backend/src/routes/free.js` line 22:
```javascript
// Uncomment this:
{ id: "thecnical/cybermind-security", name: "CyberMind Security" },
```

Push:
```bash
git add -A && git commit -m "enable cybermind-security" && git push
```

**Result:** Every user worldwide gets your fine-tuned AI for free — no API key needed.

---

## Troubleshooting

**"GPU not found"**
→ Runtime → Change runtime type → T4 GPU → Save

**"Kaggle credentials invalid"**
→ Already set correctly — should work

**"HuggingFace login failed"**
→ Token sahi hai? `hf_` se shuru hona chahiye

**"CUDA out of memory"**
→ Runtime → Restart runtime → Run All again

**"Training interrupted"**
→ Resume: `trainer.train(resume_from_checkpoint=True)`

---

## Agar Koi Problem Aaye

Screenshot bhejo. Main immediately fix kar dunga.
