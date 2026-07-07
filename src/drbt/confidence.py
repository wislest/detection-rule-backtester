"""Ensemble voting confidence for a single event.

Ported from LomaXWin's ``RealisticConfidenceCalculator``: that module capped
per-method confidence and blended a base limit with a quality factor and a
historical-success factor, under a hard ceiling. Here the same shape scores how
much to trust a detection when several rules fire on one event.

The confidence of a firing is a weighted vote: each rule that fires contributes
its *backtested precision* (how trustworthy that rule proved to be) scaled by a
severity factor and its ensemble weight. The result is squashed into ``[0, 1]``
so a single mediocre rule can never assert certainty, while agreement between a
high-precision rule and a high-severity rule compounds.
"""

from __future__ import annotations

from typing import Dict, List, Mapping

from .metrics import RuleMetrics

_SEVERITY_FACTOR = {"low": 0.6, "medium": 0.8, "high": 1.0, "critical": 1.0}
_CONFIDENCE_CEILING = 0.99
_CONFIDENCE_FLOOR = 0.01


def _severity_of(rule_id: str, severities: Mapping[str, str]) -> float:
    return _SEVERITY_FACTOR.get(severities.get(rule_id, "medium"), 0.8)


def firing_confidence(
    fired_rule_ids: List[str],
    rule_metrics: Mapping[str, RuleMetrics],
    weights: Mapping[str, float],
    severities: Mapping[str, str],
) -> float:
    """Confidence in ``[floor, ceiling]`` that a firing is a true detection.

    Combines the fired rules with the "noisy-OR" rule of independent evidence:
    the event is a false alarm only if *every* firing rule is independently
    wrong, so ``1 - product(1 - trust_i)``.
    """
    if not fired_rule_ids:
        return 0.0

    disbelief = 1.0
    for rid in fired_rule_ids:
        metrics = rule_metrics.get(rid)
        if metrics is None:
            continue
        trust = metrics.overall.precision
        trust *= _severity_of(rid, severities)
        # Ensemble weight nudges better-ranked rules up, but never to zero.
        trust *= 0.5 + 0.5 * weights.get(rid, 0.0)
        disbelief *= (1.0 - trust)

    confidence = 1.0 - disbelief
    return max(_CONFIDENCE_FLOOR, min(_CONFIDENCE_CEILING, confidence))
