"""Moving-average performance trends.

Ported from LomaXWin's ``_calculate_performance_trends`` /
``_calculate_moving_average``: instead of smoothing prediction accuracy over the
last N draws, we smooth detection precision/recall over the last N time buckets
(e.g. days). This surfaces rule drift — a rule whose precision decays as benign
traffic evolves — which is a core detection-engineering concern.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import date
from typing import Dict, List, Optional

from .events import Event
from .metrics import ConfusionMatrix


def bucket_by_day(
    per_event_outcomes: List[tuple[Event, bool]],
) -> Dict[date, ConfusionMatrix]:
    """Aggregate (event, fired) outcomes into a per-day confusion matrix."""
    counters: Dict[date, Dict[str, int]] = defaultdict(
        lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    )
    for event, fired in per_event_outcomes:
        day = event.timestamp.date()
        if fired and event.is_attack:
            counters[day]["tp"] += 1
        elif fired and not event.is_attack:
            counters[day]["fp"] += 1
        elif not fired and event.is_attack:
            counters[day]["fn"] += 1
        else:
            counters[day]["tn"] += 1
    return {day: ConfusionMatrix(**c) for day, c in counters.items()}


def _window_average(matrices: List[ConfusionMatrix]) -> Optional[Dict[str, float]]:
    if not matrices:
        return None
    n = len(matrices)
    return {
        "precision": round(sum(m.precision for m in matrices) / n, 4),
        "recall": round(sum(m.recall for m in matrices) / n, 4),
        "f1": round(sum(m.f1 for m in matrices) / n, 4),
    }


def moving_averages(daily: Dict[date, ConfusionMatrix]) -> Dict[str, Optional[Dict[str, float]]]:
    """Recent-3, recent-7 and all-time averages over chronological buckets."""
    ordered = [daily[day] for day in sorted(daily)]
    return {
        "recent_3": _window_average(ordered[-3:]) if len(ordered) >= 3 else None,
        "recent_7": _window_average(ordered[-7:]) if len(ordered) >= 7 else None,
        "all_time": _window_average(ordered),
    }
