"""Backtest a prompt-injection rule against real garak payloads (track B).

Prepare the corpus first:

    bash scripts/fetch_datasets.sh
    python scripts/build_garak_corpus.py

Real garak jailbreak/prompt-injection payloads are the attack set (self-
labelling: every probe is an attack). To make precision and false-positive rate
meaningful, we mix in a small set of benign prompts representative of normal
assistant usage. The keyword rule will catch the jailbreaks that use explicit
override phrasing and miss the ones that rely on role-play framing — a real
coverage gap the backtest surfaces.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "src"))

from drbt import BacktestEngine, Event, load_garak_events, load_sigma_file, to_markdown  # noqa: E402

BENIGN_PROMPTS = [
    "Summarize this quarterly earnings report in three bullet points.",
    "Translate the following paragraph into French.",
    "What is the capital of Canada?",
    "Write a polite follow-up email to a client about an overdue invoice.",
    "Explain how a hash table works with a small example.",
    "Draft a unit test for this Python function.",
    "Give me a recipe for a vegetarian chili.",
    "What are the trade-offs between TCP and UDP?",
]


def _benign_events() -> list[Event]:
    base = datetime(2026, 1, 2, tzinfo=timezone.utc)
    return [
        Event(
            id=f"benign-{i}",
            timestamp=base + timedelta(seconds=i * 5),
            source="llm-gateway",
            fields={"prompt": text, "src_ip": "10.0.0.20"},
            is_attack=False,
        )
        for i, text in enumerate(BENIGN_PROMPTS)
    ]


def main() -> int:
    here = os.path.dirname(__file__)
    corpus = os.path.join(here, os.pardir, "data", "garak", "corpus.jsonl")
    if not os.path.exists(corpus):
        print(
            "Corpus not found. Run:\n"
            "  bash scripts/fetch_datasets.sh\n"
            "  python scripts/build_garak_corpus.py",
            file=sys.stderr,
        )
        return 2

    attacks = load_garak_events(corpus)
    events = attacks + _benign_events()
    print(f"Loaded {len(attacks)} real garak attack prompts + {len(events) - len(attacks)} benign prompts.\n")

    rule = load_sigma_file(os.path.join(here, "rules", "prompt_injection_keywords.yml"))
    result = BacktestEngine([rule]).run(events)
    print(to_markdown(result, title="Real payloads — garak jailbreaks vs benign prompts"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
