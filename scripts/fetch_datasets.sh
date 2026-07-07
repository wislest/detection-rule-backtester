#!/usr/bin/env bash
# Pull the real public datasets used by the examples into ./data (gitignored).
# Versions are pinned by URL so runs are reproducible. Re-run to refresh.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA="$ROOT/data"
mkdir -p "$DATA/security-datasets" "$DATA/garak"

# --- Track A: Security-Datasets (Mordor) Empire regsvr32 launcher capture ---
SD_URL="https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/defense_evasion/host/empire_launcher_sct_regsvr32.zip"
echo "[track A] fetching Security-Datasets Empire launcher capture ..."
curl -sSL -o "$DATA/security-datasets/empire_launcher_sct_regsvr32.zip" "$SD_URL"
( cd "$DATA/security-datasets" && unzip -o empire_launcher_sct_regsvr32.zip >/dev/null )
echo "[track A] done -> data/security-datasets/*.json"

# --- Track B: real garak jailbreak / prompt-injection payloads ---
GARAK_BASE="https://raw.githubusercontent.com/NVIDIA/garak/main/garak/data"
echo "[track B] fetching garak jailbreak payloads ..."
# 666 real in-the-wild jailbreak prompts.
curl -sSL -o "$DATA/garak/inthewild_jailbreak_llms.json" "$GARAK_BASE/inthewild_jailbreak_llms.json"
# A few named DAN/Developer-Mode jailbreaks.
for f in DAN_Jailbreak Dan_11_0 ChatGPT_Developer_Mode_v2; do
  curl -sSL -o "$DATA/garak/$f.json" "$GARAK_BASE/dan/$f.json"
done
echo "[track B] done -> data/garak/  (then: python scripts/build_garak_corpus.py)"

echo "All datasets pinned under data/ (gitignored)."
