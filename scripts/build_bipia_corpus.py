"""Build a labelled indirect prompt-injection corpus from Microsoft BIPIA.

Indirect injection hides the attacker's instruction inside third-party content
(an email, a table, a Stack Overflow answer) that an LLM application retrieves
and pastes into its prompt. BIPIA ships the clean contexts and the attack
instructions separately; this script assembles them the way the benchmark
does — attack inserted at the start, middle or end of a real context.

Emits ``data/bipia/corpus.jsonl``, one record per context:

* every clean context once (``is_attack: false``) — real negatives, so precision
  and false-positive rate mean something;
* every attack inserted at each of the three positions, each time into a
  different context of the matching task (``is_attack: true``).

Text attacks go into email and table contexts; code attacks into code answers.
The assembled content sits in the ``prompt`` field: that is what a gateway
sees once retrieval has concatenated it into the request.

    python scripts/build_bipia_corpus.py
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(__file__)
BIPIA_DIR = os.path.join(HERE, os.pardir, "data", "bipia")
POSITIONS = ("start", "middle", "end")
TECHNIQUE = "atlas.aml.t0051.001"  # MITRE ATLAS: LLM Prompt Injection — Indirect


def _read_jsonl(name: str) -> list[dict]:
    with open(os.path.join(BIPIA_DIR, name), encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _context_text(rec: dict) -> str:
    ctx = rec["context"]
    return "\n".join(ctx) if isinstance(ctx, list) else str(ctx)


def _insert(context: str, attack: str, position: str) -> str:
    if position == "start":
        return f"{attack}\n{context}"
    if position == "end":
        return f"{context}\n{attack}"
    lines = context.split("\n")
    mid = len(lines) // 2
    return "\n".join(lines[:mid] + [attack] + lines[mid:])


def main() -> int:
    try:
        contexts = {
            "email": [_context_text(r) for r in _read_jsonl("email_test.jsonl")],
            "table": [_context_text(r) for r in _read_jsonl("table_test.jsonl")],
            "code": [_context_text(r) for r in _read_jsonl("code_test.jsonl")],
        }
        with open(os.path.join(BIPIA_DIR, "text_attack_test.json"), encoding="utf-8") as fh:
            text_attacks = json.load(fh)
        with open(os.path.join(BIPIA_DIR, "code_attack_test.json"), encoding="utf-8") as fh:
            code_attacks = json.load(fh)
    except FileNotFoundError:
        print("BIPIA files not found. Run: bash scripts/fetch_datasets.sh")
        return 2

    base = datetime(2026, 1, 3, tzinfo=timezone.utc)
    records: list[dict] = []

    def emit(task: str, text: str, is_attack: bool, category: str | None, position: str | None) -> None:
        n = len(records)
        records.append(
            {
                "id": f"bipia-{n}",
                "timestamp": (base + timedelta(seconds=n * 5)).isoformat(),
                "task": task,
                "prompt": text,
                "is_attack": is_attack,
                "attack_category": category,
                "position": position,
                "technique": TECHNIQUE if is_attack else None,
            }
        )

    for task, items in contexts.items():
        for text in items:
            emit(task, text, False, None, None)

    # Round-robin over contexts so each attack lands in three different documents.
    cursor = {"email": 0, "table": 0, "code": 0}
    plan = [(("email", "table"), text_attacks), (("code",), code_attacks)]
    for tasks, attacks in plan:
        t = 0
        for category, payloads in attacks.items():
            for attack in payloads:
                for position in POSITIONS:
                    task = tasks[t % len(tasks)]
                    t += 1
                    ctx = contexts[task][cursor[task] % len(contexts[task])]
                    cursor[task] += 1
                    emit(task, _insert(ctx, attack, position), True, category, position)

    out_path = os.path.join(BIPIA_DIR, "corpus.jsonl")
    with open(out_path, "w", encoding="utf-8") as out:
        for rec in records:
            out.write(json.dumps(rec) + "\n")
    n_att = sum(r["is_attack"] for r in records)
    print(f"Wrote {n_att} injected + {len(records) - n_att} clean contexts -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
