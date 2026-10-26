"""Detection quality gate: lint every rule, then replay real corpora against them.

Run by CI on every push, after the unit tests:

    bash scripts/fetch_datasets.sh
    python scripts/build_garak_corpus.py
    python scripts/build_bipia_corpus.py
    python scripts/quality_gate.py            # --lint-only skips the corpora

Two stages, either one fails the build:

1. **Lint** — every rule under ``examples/rules`` must load, carry an ``id``, a
   technique tag and a documented false-positive note, and contain no ``TODO``.
   A half-written detection does not ship.
2. **Backtest** — each suite in ``quality_gate.json`` replays a real corpus and
   checks ensemble recall against a floor and false alarms against a ceiling.
   This is the detection equivalent of a failing test: a rule edit that loses
   coverage or starts firing on clean content turns the build red.

The markdown report is appended to ``$GITHUB_STEP_SUMMARY`` when it exists.
"""

from __future__ import annotations

import argparse
import glob
import importlib.util
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
sys.path.insert(0, os.path.join(ROOT, "src"))

import yaml  # noqa: E402

from drbt import (  # noqa: E402
    BacktestEngine,
    load_bipia_events,
    load_garak_events,
    load_sigma_file,
    to_markdown,
)


def lint_rules() -> list[str]:
    problems: list[str] = []
    for path in sorted(glob.glob(os.path.join(ROOT, "examples", "rules", "**", "*.yml"), recursive=True)):
        rel = os.path.relpath(path, ROOT)
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
        if "TODO" in raw:
            problems.append(f"{rel}: contains TODO")
        doc = yaml.safe_load(raw) or {}
        if not doc.get("id"):
            problems.append(f"{rel}: missing id")
        if not doc.get("tags"):
            problems.append(f"{rel}: missing technique tag")
        if not doc.get("falsepositives"):
            problems.append(f"{rel}: missing falsepositives")
        try:
            load_sigma_file(path)
        except Exception as exc:  # any parse failure is a lint failure
            problems.append(f"{rel}: does not load ({exc})")
    return problems


def _garak_events() -> list:
    corpus = os.path.join(ROOT, "data", "garak", "corpus.jsonl")
    spec = importlib.util.spec_from_file_location(
        "run_real_garak", os.path.join(ROOT, "examples", "run_real_garak.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return load_garak_events(corpus) + module._benign_events()


def _bipia_events() -> list:
    return load_bipia_events(os.path.join(ROOT, "data", "bipia", "corpus.jsonl"))


CORPORA = {"garak_direct": _garak_events, "bipia_indirect": _bipia_events}


def _rules(suite: dict) -> list:
    paths = [os.path.join(ROOT, p) for p in suite.get("rule_files", [])]
    for d in suite.get("rule_dirs", []):
        paths += sorted(glob.glob(os.path.join(ROOT, d, "*.yml")))
    return [load_sigma_file(p) for p in paths]


def run_suites(config: dict, report: list[str]) -> list[str]:
    failures: list[str] = []
    for name, suite in config["suites"].items():
        events = CORPORA[name]()
        attacks = sum(e.is_attack for e in events)
        result = BacktestEngine(_rules(suite)).run(events)
        caught = {f["event_id"] for f in result.firings if f["is_attack"]}
        false_alarms = {f["event_id"] for f in result.firings if not f["is_attack"]}
        recall = len(caught) / attacks if attacks else 0.0

        ok_recall = recall >= suite["min_ensemble_recall"]
        ok_fp = len(false_alarms) <= suite["max_false_alarms"]
        status = "PASS" if ok_recall and ok_fp else "FAIL"
        line = (
            f"[{status}] {name}: ensemble recall {len(caught)}/{attacks} = {recall:.1%} "
            f"(floor {suite['min_ensemble_recall']:.0%}), false alarms {len(false_alarms)} "
            f"(ceiling {suite['max_false_alarms']})"
        )
        print(line)
        report += [f"### {status} — {name}", "", suite.get("description", ""), "", line, ""]
        report.append(to_markdown(result, title=f"Suite {name}"))
        if not ok_recall:
            failures.append(f"{name}: recall {recall:.1%} below floor {suite['min_ensemble_recall']:.0%}")
        if not ok_fp:
            failures.append(f"{name}: {len(false_alarms)} false alarms above ceiling {suite['max_false_alarms']}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--lint-only", action="store_true", help="skip the corpus backtests")
    args = parser.parse_args()

    report = ["# Detection quality gate", ""]
    problems = lint_rules()
    for p in problems:
        print(f"[LINT] {p}")
    report += ["## Rule lint", ""] + ([f"- {p}" for p in problems] or ["All rules pass lint."]) + [""]

    failures: list[str] = []
    if not args.lint_only:
        with open(os.path.join(ROOT, "quality_gate.json"), encoding="utf-8") as fh:
            config = json.load(fh)
        report += ["## Corpus backtests", ""]
        failures = run_suites(config, report)

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("\n".join(report) + "\n")

    if problems or failures:
        for f in failures:
            print(f"[GATE] {f}")
        return 1
    print("Quality gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
