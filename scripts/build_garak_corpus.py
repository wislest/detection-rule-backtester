"""Build a garak-report-style JSONL corpus from real garak payload files.

Reads the raw jailbreak/prompt-injection payloads fetched under
``data/garak/*.json`` (each a JSON list of prompt strings, with garak's
``{generator.name}`` template placeholder) and emits ``data/garak/corpus.jsonl``
in the ``entry_type: attempt`` shape that :func:`drbt.loaders.load_garak_events`
consumes. Every payload is an attack; the source filename becomes the probe
class.

    python scripts/build_garak_corpus.py
"""

from __future__ import annotations

import glob
import json
import os
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(__file__)
GARAK_DIR = os.path.join(HERE, os.pardir, "data", "garak")


def main() -> int:
    payload_files = sorted(
        p for p in glob.glob(os.path.join(GARAK_DIR, "*.json"))
        if os.path.basename(p) != "corpus.jsonl"
    )
    if not payload_files:
        print("No garak payloads found. Run: bash scripts/fetch_datasets.sh")
        return 2

    out_path = os.path.join(GARAK_DIR, "corpus.jsonl")
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    n = 0
    with open(out_path, "w", encoding="utf-8") as out:
        out.write(json.dumps({"entry_type": "start_run setup", "source": "garak payloads"}) + "\n")
        for pf in payload_files:
            probe = os.path.splitext(os.path.basename(pf))[0]
            with open(pf, encoding="utf-8") as fh:
                payloads = json.load(fh)
            if not isinstance(payloads, list):
                payloads = [payloads]
            for prompt in payloads:
                # Resolve garak's template placeholder to a concrete assistant name.
                text = str(prompt).replace("{generator.name}", "the assistant")
                out.write(
                    json.dumps(
                        {
                            "entry_type": "attempt",
                            "uuid": f"garak-{n}",
                            "timestamp": (base + timedelta(seconds=n * 5)).isoformat(),
                            "probe_classname": f"dan.{probe}",
                            "prompt": text,
                        }
                    )
                    + "\n"
                )
                n += 1
    print(f"Wrote {n} attack prompts -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
