"""Command-line entry point: load rules + corpora, backtest, print a report.

Examples
--------
    python -m drbt \
        --rules examples/rules \
        --sysmon examples/data/sysmon_sample.jsonl \
        --garak examples/data/garak_sample.jsonl

    python -m drbt --rules examples/rules --garak run.jsonl --json
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from typing import List

from .backtest import BacktestEngine
from .events import Event
from .loaders import load_garak_events, load_sysmon_events
from .report import to_markdown
from .rules import Rule
from .sigma import SigmaUnsupported, load_sigma_file


def _load_rules(rules_dir: str) -> List[Rule]:
    rules: List[Rule] = []
    paths = sorted(glob.glob(os.path.join(rules_dir, "**", "*.y*ml"), recursive=True))
    for path in paths:
        try:
            rules.append(load_sigma_file(path))
        except SigmaUnsupported as exc:
            print(f"[skip] {os.path.basename(path)}: {exc}", file=sys.stderr)
    return rules


def _load_events(args) -> List[Event]:
    events: List[Event] = []
    if args.sysmon:
        events += load_sysmon_events(args.sysmon)
    if args.garak:
        events += load_garak_events(args.garak)
    return events


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="drbt", description="Backtest detection rules against labelled corpora.")
    parser.add_argument("--rules", required=True, help="Directory of Sigma .yml rule files.")
    parser.add_argument("--sysmon", help="Track A: Sysmon/EVTX-style JSONL corpus.")
    parser.add_argument("--garak", help="Track B: garak report JSONL corpus.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of Markdown.")
    parser.add_argument("--title", default="Detection Rule Backtest", help="Report title.")
    return parser


def main(argv: List[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    rules = _load_rules(args.rules)
    if not rules:
        print("No usable rules loaded.", file=sys.stderr)
        return 2
    events = _load_events(args)
    if not events:
        print("No events loaded (pass --sysmon and/or --garak).", file=sys.stderr)
        return 2

    result = BacktestEngine(rules).run(events)
    if args.json:
        print(json.dumps(result.as_dict(), indent=2))
    else:
        print(to_markdown(result, title=args.title))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
