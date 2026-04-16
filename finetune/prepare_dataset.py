"""
prepare_dataset.py — CyberMind Dataset Preparation
Downloads and prepares all 3 datasets for fine-tuning.

Usage:
    python prepare_dataset.py

Requirements:
    pip install kagglehub pandas requests tqdm
"""

import json
import os
import re
import requests
import pandas as pd
from pathlib import Path
from tqdm import tqdm

OUTPUT_DIR = Path("datasets")
OUTPUT_DIR.mkdir(exist_ok=True)

FINAL_OUTPUT = OUTPUT_DIR / "cybermind_combined.jsonl"


# ── Step 1: Download Kaggle Bug Hunter Dataset ────────────────────────────────

def download_kaggle_dataset():
    """Download the bug-hunter dataset from Kaggle."""
    print("\n[1/3] Downloading Kaggle Bug Hunter dataset...")
    print("      Source: https://www.kaggle.com/datasets/vellyy/bug-hunter")

    try:
        import kagglehub
        path = kagglehub.dataset_download("vellyy/bug-hunter")
        print(f"      Downloaded to: {path}")
        return path
    except ImportError:
        print("      kagglehub not installed. Installing...")
        os.system("pip install kagglehub -q")
        import kagglehub
        path = kagglehub.dataset_download("vellyy/bug-hunter")
        return path
    except Exception as e:
        print(f"      Kaggle download failed: {e}")
        print("      Manual download: https://www.kaggle.com/datasets/vellyy/bug-hunter")
        print("      Place CSV files in datasets/kaggle/")
        return None


def process_kaggle_dataset(kaggle_path):
    """Convert Kaggle bug reports to instruction-output format."""
    print("\n      Processing Kaggle dataset...")
    entries = []

    if kaggle_path is None:
        # Try local fallback
        local_path = OUTPUT_DIR / "kaggle"
        if not local_path.exists():
            print("      No Kaggle data found. Skipping.")
            return entries

    try:
        # Find CSV files
        search_path = Path(kaggle_path) if kaggle_path else OUTPUT_DIR / "kaggle"
        csv_files = list(search_path.rglob("*.csv"))

        for csv_file in csv_files:
            print(f"      Processing: {csv_file.name}")
            df = pd.read_csv(csv_file, encoding="utf-8", errors="replace")

            # Common column names in bug bounty datasets
            title_cols = [c for c in df.columns if any(k in c.lower() for k in ["title", "name", "vuln"])]
            desc_cols = [c for c in df.columns if any(k in c.lower() for k in ["desc", "detail", "report", "body", "content"])]
            severity_cols = [c for c in df.columns if any(k in c.lower() for k in ["severity", "risk", "impact", "rating"])]

            if not title_cols or not desc_cols:
                print(f"      Skipping {csv_file.name} — no title/description columns found")
                continue

            title_col = title_cols[0]
            desc_col = desc_cols[0]
            sev_col = severity_cols[0] if severity_cols else None

            for _, row in df.iterrows():
                title = str(row.get(title_col, "")).strip()
                desc = str(row.get(desc_col, "")).strip()
                severity = str(row.get(sev_col, "medium")).strip() if sev_col else "medium"

                if not title or not desc or len(desc) < 50:
                    continue

                # Create instruction-output pair
                entry = {
                    "instruction": f"Analyze this bug bounty finding and explain the vulnerability, impact, and remediation:\n\nTitle: {title}\nSeverity: {severity}",
                    "input": "",
                    "output": f"## Vulnerability Analysis\n\n**Title:** {title}\n**Severity:** {severity}\n\n## Description\n{desc[:2000]}\n\n## Impact\nThis vulnerability could allow an attacker to [impact based on severity].\n\n## Remediation\nTo fix this vulnerability:\n1. [Specific remediation steps]\n2. Apply security patches\n3. Implement input validation",
                    "category": "real_bug_report",
                    "source": "kaggle_bug_hunter",
                }
                entries.append(entry)

        print(f"      Processed {len(entries)} entries from Kaggle dataset")
    except Exception as e:
        print(f"      Error processing Kaggle data: {e}")

    return entries


# ── Step 2: Download Figshare CVE Dataset ─────────────────────────────────────

def download_figshare_dataset():
    """Download CVE dataset from Figshare."""
    print("\n[2/3] Downloading Figshare CVE dataset...")
    print("      Source: https://doi.org/10.6084/m9.figshare.22056617")

    output_path = OUTPUT_DIR / "figshare_cve.json"

    if output_path.exists():
        print(f"      Already downloaded: {output_path}")
        return output_path

    # Figshare API to get download URL
    try:
        api_url = "https://api.figshare.com/v2/articles/22056617"
        resp = requests.get(api_url, timeout=30)
        resp.raise_for_status()
        article = resp.json()

        files = article.get("files", [])
        if not files:
            print("      No files found in Figshare article")
            return None

        # Download first file
        file_url = files[0]["download_url"]
        file_name = files[0]["name"]
        print(f"      Downloading: {file_name} ({files[0].get('size', 0) // 1024 // 1024}MB)")

        with requests.get(file_url, stream=True, timeout=120) as r:
            r.raise_for_status()
            total = int(r.headers.get("content-length", 0))
            with open(output_path, "wb") as f, tqdm(total=total, unit="B", unit_scale=True) as pbar:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
                    pbar.update(len(chunk))

        print(f"      Downloaded to: {output_path}")
        return output_path

    except Exception as e:
        print(f"      Figshare download failed: {e}")
        print("      Manual download: https://figshare.com/articles/dataset/22056617")
        return None


def process_figshare_dataset(figshare_path):
    """Convert CVE dataset to instruction-output format."""
    print("\n      Processing Figshare CVE dataset...")
    entries = []

    if figshare_path is None or not Path(figshare_path).exists():
        print("      No Figshare data found. Skipping.")
        return entries

    try:
        with open(figshare_path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)

        # Handle different JSON structures
        if isinstance(data, list):
            cve_list = data
        elif isinstance(data, dict):
            cve_list = data.get("cves", data.get("vulnerabilities", data.get("data", [])))
        else:
            cve_list = []

        print(f"      Found {len(cve_list)} CVE entries")

        for cve in tqdm(cve_list[:5000], desc="      Processing CVEs"):  # limit to 5000
            cve_id = cve.get("id", cve.get("cve_id", cve.get("CVE_ID", "")))
            description = cve.get("description", cve.get("desc", cve.get("summary", "")))
            cvss = cve.get("cvss", cve.get("cvss_score", cve.get("score", 0)))
            severity = cve.get("severity", cve.get("risk", "medium"))

            if not cve_id or not description or len(description) < 30:
                continue

            entry = {
                "instruction": f"Explain {cve_id} and how to detect and exploit it in a bug bounty context. Provide exact commands.",
                "input": "",
                "output": f"## {cve_id} — Security Advisory\n\n**Severity:** {severity} | **CVSS:** {cvss}\n\n## Description\n{description[:1000]}\n\n## Detection\n```bash\n# Check with nuclei\nnuclei -u https://TARGET -tags {cve_id.lower()} -silent\n\n# Manual check\ncurl -v https://TARGET/VULNERABLE_ENDPOINT\n```\n\n## Exploitation\n```bash\n# Automated\nnuclei -u https://TARGET -t cves/{cve_id.split('-')[1] if '-' in cve_id else '2024'}/{cve_id}.yaml\n\n# Manual PoC\ncurl -X POST https://TARGET/ENDPOINT -d 'PAYLOAD'\n```\n\n## Impact\nThis vulnerability allows an attacker to compromise the target system.\n\n## Remediation\nApply the vendor security patch immediately.",
                "category": "cve_knowledge",
                "source": "figshare_cve_dataset",
            }
            entries.append(entry)

        print(f"      Processed {len(entries)} CVE entries")
    except Exception as e:
        print(f"      Error processing Figshare data: {e}")

    return entries


# ── Step 3: Load CyberMind Synthetic Dataset ──────────────────────────────────

def load_synthetic_dataset():
    """Load the pre-generated CyberMind synthetic dataset."""
    print("\n[3/3] Loading CyberMind synthetic dataset...")

    synthetic_path = OUTPUT_DIR / "cybermind_synthetic.jsonl"
    entries = []

    if not synthetic_path.exists():
        print("      cybermind_synthetic.jsonl not found")
        print("      Generate it: curl -X POST https://YOUR_BACKEND/dataset/generate -H 'X-API-Key: KEY' -d '{\"count\":500}' -o datasets/cybermind_synthetic.jsonl")
        return entries

    with open(synthetic_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entry = json.loads(line)
                    entries.append(entry)
                except json.JSONDecodeError:
                    continue

    print(f"      Loaded {len(entries)} synthetic entries")
    return entries


# ── Step 4: Combine and Save ──────────────────────────────────────────────────

def combine_and_save(kaggle_entries, figshare_entries, synthetic_entries):
    """Combine all datasets and save as JSONL."""
    print("\n[4/4] Combining datasets...")

    all_entries = []
    all_entries.extend(kaggle_entries)
    all_entries.extend(figshare_entries)
    all_entries.extend(synthetic_entries)

    # Deduplicate by instruction
    seen = set()
    unique_entries = []
    for entry in all_entries:
        key = entry.get("instruction", "")[:100]
        if key not in seen:
            seen.add(key)
            unique_entries.append(entry)

    # Shuffle for better training
    import random
    random.shuffle(unique_entries)

    # Save as JSONL
    with open(FINAL_OUTPUT, "w", encoding="utf-8") as f:
        for entry in unique_entries:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    print(f"\n✓ Combined dataset saved: {FINAL_OUTPUT}")
    print(f"  Total entries: {len(unique_entries)}")
    print(f"  Kaggle: {len(kaggle_entries)}")
    print(f"  Figshare CVE: {len(figshare_entries)}")
    print(f"  CyberMind Synthetic: {len(synthetic_entries)}")

    # Save stats
    stats = {
        "total": len(unique_entries),
        "kaggle": len(kaggle_entries),
        "figshare": len(figshare_entries),
        "synthetic": len(synthetic_entries),
        "categories": list(set(e.get("category", "unknown") for e in unique_entries)),
    }
    with open(OUTPUT_DIR / "dataset_stats.json", "w") as f:
        json.dump(stats, f, indent=2)

    return unique_entries


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("CyberMind Dataset Preparation")
    print("=" * 60)

    # Step 1: Kaggle
    kaggle_path = download_kaggle_dataset()
    kaggle_entries = process_kaggle_dataset(kaggle_path)

    # Step 2: Figshare
    figshare_path = download_figshare_dataset()
    figshare_entries = process_figshare_dataset(figshare_path)

    # Step 3: Synthetic
    synthetic_entries = load_synthetic_dataset()

    # Step 4: Combine
    all_entries = combine_and_save(kaggle_entries, figshare_entries, synthetic_entries)

    print("\n" + "=" * 60)
    print("NEXT STEP: Open CyberMind_FineTune.ipynb in Google Colab")
    print("=" * 60)
