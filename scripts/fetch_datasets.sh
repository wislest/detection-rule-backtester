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

# --- Track B (indirect): Microsoft BIPIA indirect prompt-injection benchmark (MIT) ---
# Real third-party content (emails, tables, code Q&A) plus attack instructions
# that get embedded *inside* that content. Pinned to the last upstream commit.
BIPIA_BASE="https://raw.githubusercontent.com/microsoft/BIPIA/a004b69ec0dd446e0afd461d98cb5e96e120a5d0"
mkdir -p "$DATA/bipia"
echo "[track B] fetching BIPIA indirect prompt-injection benchmark ..."
for f in email/test.jsonl table/test.jsonl code/test.jsonl text_attack_test.json code_attack_test.json; do
  curl -sSL -o "$DATA/bipia/$(echo "$f" | tr '/' '_')" "$BIPIA_BASE/benchmark/$f"
done
echo "[track B] done -> data/bipia/  (then: python scripts/build_bipia_corpus.py)"

echo "All datasets pinned under data/ (gitignored)."
