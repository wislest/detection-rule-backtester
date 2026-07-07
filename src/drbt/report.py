"""Render a Markdown report from a backtest result.

Produces the per-rule performance table, the blended global ranking with
ensemble weights, and a coverage matrix grouped by technique (MITRE ATLAS /
OWASP LLM Top 10 / ATT&CK). This is the analogue of LomaXWin's
``get_predictor_performance_report``, aimed at a detection-engineering reader.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from .backtest import BacktestResult


def to_markdown(result: BacktestResult, title: str = "Detection Rule Backtest") -> str:
    lines: List[str] = [f"# {title}", ""]

    # --- per-rule performance table ---
    lines += ["## Per-rule performance", ""]
    lines += [
        "| Rule | Technique | Precision | Recall (scoped) | F1 | FP rate | Alerts | TP | FP | FN |",
        "|------|-----------|-----------|-----------------|----|---------|--------|----|----|----|",
    ]
    ranking = list(result.rankings.get("global_ranking", [])) if result.rankings else []
    ordered_ids = ranking or list(result.rule_metrics.keys())
    for rid in ordered_ids:
        m = result.rule_metrics[rid]
        cm = m.overall
        lines.append(
            f"| {m.rule_name} | {m.technique or '—'} | {cm.precision:.2f} | "
            f"{m.recall_scoped:.2f} | {m.f1_scoped:.2f} | {cm.false_positive_rate:.3f} | "
            f"{cm.alerts} | {cm.tp} | {cm.fp} | {cm.fn} |"
        )
    lines.append("")

    # --- global ranking + ensemble weights ---
    lines += ["## Global ranking & ensemble weights", ""]
    if ranking:
        lines += ["| # | Rule | Weight |", "|---|------|--------|"]
        for i, rid in enumerate(ranking, start=1):
            lines.append(
                f"| {i} | {result.rule_metrics[rid].rule_name} | {result.weights.get(rid, 0):.3f} |"
            )
    else:
        lines.append("_No rules evaluated._")
    lines.append("")

    # --- coverage matrix by technique ---
    lines += ["## Coverage by technique", ""]
    by_technique: Dict[str, List[str]] = defaultdict(list)
    for m in result.rule_metrics.values():
        by_technique[m.technique or "(untagged)"].append(m.rule_name)
    lines += ["| Technique | Rules |", "|-----------|-------|"]
    for technique in sorted(by_technique):
        lines.append(f"| {technique} | {', '.join(by_technique[technique])} |")
    lines.append("")

    # --- ensemble firings summary ---
    lines += ["## Ensemble firings", ""]
    if result.firings:
        true_pos = sum(1 for f in result.firings if f["is_attack"])
        lines.append(
            f"- {len(result.firings)} events triggered at least one rule "
            f"({true_pos} true attacks, {len(result.firings) - true_pos} false alarms)."
        )
        avg_conf_attack = _avg(
            [f["confidence"] for f in result.firings if f["is_attack"]]
        )
        avg_conf_benign = _avg(
            [f["confidence"] for f in result.firings if not f["is_attack"]]
        )
        lines.append(f"- Mean ensemble confidence on true attacks: {avg_conf_attack:.2f}")
        lines.append(f"- Mean ensemble confidence on false alarms: {avg_conf_benign:.2f}")
    else:
        lines.append("_No firings._")
    lines.append("")

    return "\n".join(lines)


def _avg(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0
