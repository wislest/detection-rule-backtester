"""Backtest engine — replay labelled events against rules and score them.

This is the recycled heart of LomaXWin's evaluator, decoupled from the lottery
domain. ``evaluate_predictions`` there iterated historical draws, compared each
predictor's output to the actual result, aggregated per-predictor metrics, and
ranked predictors. Here we iterate labelled events in chronological order, feed
each to every rule, and aggregate a per-rule confusion matrix, rankings, trends,
and per-event ensemble confidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Mapping

from .confidence import firing_confidence
from .events import Event
from .metrics import ConfusionMatrix, RuleMetrics
from .ranking import ensemble_weights, rank_rules
from .rules import Rule, sorted_by_time
from .trends import bucket_by_day, moving_averages


@dataclass
class BacktestResult:
    rule_metrics: Dict[str, RuleMetrics]
    rankings: Dict[str, object]
    weights: Dict[str, float]
    trends: Dict[str, Dict[str, object]]
    firings: List[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "rule_metrics": {rid: m.as_dict() for rid, m in self.rule_metrics.items()},
            "rankings": self.rankings,
            "weights": {rid: round(w, 4) for rid, w in self.weights.items()},
            "trends": self.trends,
            "firings": self.firings,
        }


class BacktestEngine:
    """Replays a corpus of events against a fixed set of rules."""

    def __init__(self, rules: List[Rule]) -> None:
        self.rules = rules

    def run(self, events: List[Event]) -> BacktestResult:
        ordered = sorted_by_time(events)
        for rule in self.rules:
            rule.reset()

        total_attacks = sum(1 for e in ordered if e.is_attack)

        # Per-rule tallies and per-rule per-event outcomes (for trends).
        counters: Dict[str, Dict[str, int]] = {
            rule.id: {"tp": 0, "fp": 0, "fn": 0, "tn": 0} for rule in self.rules
        }
        scoped_attacks: Dict[str, int] = {rule.id: 0 for rule in self.rules}
        scoped_hits: Dict[str, int] = {rule.id: 0 for rule in self.rules}
        outcomes: Dict[str, List[tuple[Event, bool]]] = {rule.id: [] for rule in self.rules}
        per_event_fired: List[tuple[Event, List[str]]] = []

        for event in ordered:
            fired_here: List[str] = []
            for rule in self.rules:
                fired = rule.feed(event)
                outcomes[rule.id].append((event, fired))
                if fired:
                    fired_here.append(rule.id)
                # Overall confusion matrix.
                if fired and event.is_attack:
                    counters[rule.id]["tp"] += 1
                elif fired and not event.is_attack:
                    counters[rule.id]["fp"] += 1
                elif not fired and event.is_attack:
                    counters[rule.id]["fn"] += 1
                else:
                    counters[rule.id]["tn"] += 1
                # Scoped recall: only attacks matching the rule's technique.
                if event.is_attack and rule.technique and event.technique == rule.technique:
                    scoped_attacks[rule.id] += 1
                    if fired:
                        scoped_hits[rule.id] += 1
            per_event_fired.append((event, fired_here))

        rule_metrics: Dict[str, RuleMetrics] = {}
        for rule in self.rules:
            cm = ConfusionMatrix(**counters[rule.id])
            scoped_total = scoped_attacks[rule.id]
            recall_scoped = (
                scoped_hits[rule.id] / scoped_total if scoped_total else cm.recall
            )
            rule_metrics[rule.id] = RuleMetrics(
                rule_id=rule.id,
                rule_name=rule.name,
                technique=rule.technique,
                overall=cm,
                recall_scoped=recall_scoped,
            )

        rankings = rank_rules(rule_metrics)
        global_ranking = list(rankings.get("global_ranking", [])) if rankings else []
        weights = ensemble_weights(global_ranking)
        severities = {rule.id: rule.severity for rule in self.rules}

        trends = {
            rule.id: moving_averages(bucket_by_day(outcomes[rule.id]))
            for rule in self.rules
        }

        # Per-event ensemble confidence for events where at least one rule fired.
        firings: List[dict] = []
        for event, fired_here in per_event_fired:
            if not fired_here:
                continue
            firings.append(
                {
                    "event_id": event.id,
                    "timestamp": event.timestamp.isoformat(),
                    "fired_rules": fired_here,
                    "is_attack": event.is_attack,
                    "confidence": round(
                        firing_confidence(fired_here, rule_metrics, weights, severities), 4
                    ),
                }
            )

        _ = total_attacks  # kept for future corpus-level summary
        return BacktestResult(
            rule_metrics=rule_metrics,
            rankings=rankings,
            weights=weights,
            trends=trends,
            firings=firings,
        )
