"""Detection rule abstractions and a small built-in matching engine.

The ``Rule`` protocol is intentionally narrow so external rule formats can be
adapted onto it: a Sigma rule compiled with ``pySigma``, an Agent Threat Rule
(ATR), or a Kusto/KQL analytic can each be wrapped as a ``Rule`` that answers
"does this event (or window of events) fire?".

Two concrete engines ship here:

* :class:`FieldMatchRule` — an atomic, per-event condition (equals / contains /
  regex / membership), the common denominator of most Sigma detections.
* :class:`ThresholdRule` — a correlation rule that fires when an inner matcher
  hits at least ``count`` times within ``window`` seconds for the same
  ``group_by`` field. This models analytics such as the Microsoft Defender for
  AI Services KQL rule "3+ prompt-injection attempts within 10 minutes from
  similar IPs".
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Callable, Deque, Dict, List, Optional, Protocol, runtime_checkable

from .events import Event

# A condition takes a field value and returns whether it satisfies the clause.
Condition = Callable[[Any], bool]


@runtime_checkable
class Rule(Protocol):
    """Minimal interface every rule (native or adapted) must satisfy."""

    id: str
    name: str
    severity: str
    technique: Optional[str]

    def feed(self, event: Event) -> bool:
        """Consume one event in chronological order and report a firing.

        Correlation rules keep internal state across calls; atomic rules simply
        evaluate the single event. Returns ``True`` when the rule fires *on this
        event*, so the backtest engine can attribute the detection to it.
        """
        ...

    def reset(self) -> None:
        """Clear any per-run internal state before a fresh backtest."""
        ...


# --- condition helpers -------------------------------------------------------

def equals(expected: Any) -> Condition:
    return lambda v: v == expected


def contains(substring: str, *, case_insensitive: bool = True) -> Condition:
    if case_insensitive:
        needle = substring.lower()
        return lambda v: isinstance(v, str) and needle in v.lower()
    return lambda v: isinstance(v, str) and substring in v


def matches_regex(pattern: str, *, flags: int = re.IGNORECASE) -> Condition:
    compiled = re.compile(pattern, flags)
    return lambda v: isinstance(v, str) and compiled.search(v) is not None


def is_in(options: Any) -> Condition:
    option_set = set(options)
    return lambda v: v in option_set


# --- concrete rules ----------------------------------------------------------

@dataclass
class FieldMatchRule:
    """Fires when *all* field conditions hold for a single event (logical AND)."""

    id: str
    name: str
    conditions: Dict[str, Condition]
    severity: str = "medium"
    technique: Optional[str] = None

    def feed(self, event: Event) -> bool:
        return all(cond(event.get(key)) for key, cond in self.conditions.items())

    def reset(self) -> None:  # no state to clear
        return None


@dataclass
class ThresholdRule:
    """Fires when ``inner`` matches ``count`` times within ``window`` seconds.

    Matches are grouped by the value of ``group_by`` (e.g. source IP or agent
    id). The rule fires on the event that pushes a group over the threshold.
    """

    id: str
    name: str
    inner: Rule
    count: int
    window_seconds: float
    group_by: str
    severity: str = "high"
    technique: Optional[str] = None
    _seen: Dict[Any, Deque] = field(default_factory=lambda: defaultdict(deque), init=False, repr=False)

    def feed(self, event: Event) -> bool:
        if not self.inner.feed(event):
            return False
        key = event.get(self.group_by)
        bucket = self._seen[key]
        bucket.append(event.timestamp)
        cutoff = event.timestamp - timedelta(seconds=self.window_seconds)
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        return len(bucket) >= self.count

    def reset(self) -> None:
        self._seen.clear()
        self.inner.reset()


def sorted_by_time(events: List[Event]) -> List[Event]:
    """Return events in chronological order (correlation rules require this)."""
    return sorted(events, key=lambda e: e.timestamp)
