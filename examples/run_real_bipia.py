"""Backtest prompt-injection rules against real indirect injections (track B).

Prepare the corpus first:

    bash scripts/fetch_datasets.sh
    python scripts/build_bipia_corpus.py

The corpus is Microsoft BIPIA: real emails, tables and Stack Overflow answers,
clean or with an attacker instruction embedded at the start, middle or end.
Two rule sets are compared on the same events:

* the direct-jailbreak families from ``rules/`` and ``rules/llm/`` — do rules
  tuned on "you are now DAN" transfer to injected documents?
* the indirect families in ``rules/llm_indirect/``.

Clean contexts are real negatives, so the false-positive rate is measured on
the kind of content a retrieval pipeline actually carries.
"""

from __future__ import annotations

import os
import sys
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "src"))

from drbt import BacktestEngine, load_bipia_events, load_sigma_file, to_markdown  # noqa: E402


def _load_dir(path: str) -> list:
    return [
        load_sigma_file(os.path.join(path, f))
        for f in sorted(os.listdir(path))
        if f.endswith((".yml", ".yaml"))
    ]


def _ensemble(result, events, label: str) -> set:
    attacks = [e for e in events if e.is_attack]
    clean = len(events) - len(attacks)
    caught = {f["event_id"] for f in result.firings if f["is_attack"]}
    false_alarms = {f["event_id"] for f in result.firings if not f["is_attack"]}
    print(
        f"**{label} — ensemble recall {len(caught)}/{len(attacks)} = "
        f"{100 * len(caught) / len(attacks):.1f}%, false alarms "
        f"{len(false_alarms)}/{clean} clean contexts.**\n"
    )
    return caught


def main() -> int:
    here = os.path.dirname(__file__)
    corpus = os.path.join(here, os.pardir, "data", "bipia", "corpus.jsonl")
    if not os.path.exists(corpus):
        print(
            "Corpus not found. Run:\n"
            "  bash scripts/fetch_datasets.sh\n"
            "  python scripts/build_bipia_corpus.py",
            file=sys.stderr,
        )
        return 2

    events = load_bipia_events(corpus)
    n_att = sum(e.is_attack for e in events)
    print(f"Loaded {n_att} injected + {len(events) - n_att} clean real contexts (BIPIA).\n")

    rules_dir = os.path.join(here, "rules")
    direct = [load_sigma_file(os.path.join(rules_dir, "prompt_injection_keywords.yml"))]
    direct += _load_dir(os.path.join(rules_dir, "llm"))
    indirect = _load_dir(os.path.join(rules_dir, "llm_indirect"))

    direct_result = BacktestEngine(direct).run(events)
    print(to_markdown(direct_result, title="Direct-jailbreak rules vs indirect injections"))
    _ensemble(direct_result, events, "Direct-jailbreak rules")

    indirect_result = BacktestEngine(indirect).run(events)
    print(to_markdown(indirect_result, title="Indirect-injection rules vs indirect injections"))
    caught = _ensemble(indirect_result, events, "Indirect rules")

    # Where the indirect rules still miss: per attack category.
    missed = Counter(
        e.fields["attack_category"] for e in events if e.is_attack and e.id not in caught
    )
    total = Counter(e.fields["attack_category"] for e in events if e.is_attack)
    print("| Attack category | Missed |\n|---|---|")
    for category, n in sorted(total.items(), key=lambda kv: -missed[kv[0]] / kv[1]):
        print(f"| {category} | {missed[category]}/{n} |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
