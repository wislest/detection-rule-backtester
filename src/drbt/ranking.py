"""Rank rules and derive ensemble weights.

Ported (in shape, not in domain) from LomaXWin's ``_rank_predictors`` and
``update_ensemble_weights``: rank each detector on several metrics, blend the
per-metric ranks into a weighted global score, then turn the inverse global
rank into normalized ensemble weights. Here the detectors are detection rules
and the metrics are F1 / precision / recall rather than lottery match rates.
"""

from __future__ import annotations

from typing import Dict, List, Mapping

from .metrics import RuleMetrics

# Weight of each per-metric rank in the blended global score. Precision is
# weighted highest: in detection engineering an alert nobody trusts is worse
# than a missed edge case.
_RANK_WEIGHTS = {"precision": 0.4, "f1": 0.35, "recall": 0.25}


def rank_rules(metrics: Mapping[str, RuleMetrics]) -> Dict[str, object]:
    """Return per-metric rankings, a blended global ranking, and its scores."""
    if not metrics:
        return {}

    rule_ids = list(metrics.keys())

    def ranking_by(metric: str) -> List[str]:
        return sorted(
            rule_ids,
            key=lambda rid: getattr(metrics[rid].overall, metric),
            reverse=True,
        )

    per_metric = {metric: ranking_by(metric) for metric in _RANK_WEIGHTS}

    # Blended score: lower is better (rank 1 = best). Sum of weighted ranks.
    global_scores: Dict[str, float] = {}
    for rid in rule_ids:
        global_scores[rid] = sum(
            weight * (per_metric[metric].index(rid) + 1)
            for metric, weight in _RANK_WEIGHTS.items()
        )

    global_ranking = sorted(rule_ids, key=lambda rid: global_scores[rid])

    return {
        "per_metric": per_metric,
        "global_ranking": global_ranking,
        "global_scores": global_scores,
    }


def ensemble_weights(global_ranking: List[str]) -> Dict[str, float]:
    """Normalized weights from inverse rank (best rank -> largest weight)."""
    n = len(global_ranking)
    if n == 0:
        return {}
    raw = {rid: (n - i) for i, rid in enumerate(global_ranking)}
    total = sum(raw.values())
    return {rid: value / total for rid, value in raw.items()}
