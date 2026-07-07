"""Per-rule confusion-matrix metrics.

This is where LomaXWin's evaluator changes shape. The lottery evaluator scored a
prediction by set-overlap of drawn numbers; a detection rule is instead a binary
classifier over events. For a given rule and a corpus of labelled events:

    predicted positive := the rule fired on the event
    actual positive    := the event is part of an attack (``is_attack``)

which yields the classic confusion matrix and precision / recall / F1 / false-
positive rate. One nuance matters for detection engineering and is preserved
here: a narrow rule should not be penalised on *recall* for attacks it was never
meant to catch. So recall is reported twice — against every attack in the corpus
(``recall_all``) and against only the attacks tagged with the rule's technique
(``recall_scoped``). False-positive rate is always measured against all benign
events, because a rule that is noisy is noisy regardless of scope.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ConfusionMatrix:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def alerts(self) -> int:
        """Total events on which the rule fired."""
        return self.tp + self.fp

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0

    def as_dict(self) -> dict:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "alerts": self.alerts,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
        }


@dataclass(frozen=True)
class RuleMetrics:
    """Metrics for one rule over a full backtest run."""

    rule_id: str
    rule_name: str
    technique: str | None
    overall: ConfusionMatrix
    recall_scoped: float

    @property
    def f1_scoped(self) -> float:
        """F1 pairing overall precision with scoped recall.

        Keeps the reported row internally consistent: a narrow rule is judged on
        precision (against all traffic) and recall within its own technique,
        rather than being penalised by attacks it never targeted.
        """
        p, r = self.overall.precision, self.recall_scoped
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def as_dict(self) -> dict:
        data = {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "technique": self.technique,
            "recall_scoped": round(self.recall_scoped, 4),
            "f1_scoped": round(self.f1_scoped, 4),
        }
        data.update(self.overall.as_dict())
        return data
