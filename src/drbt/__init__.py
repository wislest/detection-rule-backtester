"""Detection Rule Backtester (drbt).

Replay labelled logs and AI-attack traces against detection rules (Sigma / ATR /
KQL-style) and measure precision, recall, false-positive rate and multi-rule
ensemble confidence per rule. The evaluation harness is recycled from a lottery
prediction backtester, decoupled from that domain.
"""

from .backtest import BacktestEngine, BacktestResult
from .confidence import firing_confidence
from .events import Event
from .loaders import (
    WINDOWS_FIELD_MAP,
    load_garak_events,
    load_sysmon_events,
    normalize_windows_fields,
)
from .metrics import ConfusionMatrix, RuleMetrics
from .ranking import ensemble_weights, rank_rules
from .report import to_markdown
from .rules import (
    FieldMatchRule,
    Rule,
    ThresholdRule,
    contains,
    equals,
    is_in,
    matches_regex,
)
from .sigma import SigmaRule, SigmaUnsupported, load_sigma_file

__version__ = "0.5.0"

__all__ = [
    "BacktestEngine",
    "BacktestResult",
    "Event",
    "ConfusionMatrix",
    "RuleMetrics",
    "FieldMatchRule",
    "ThresholdRule",
    "Rule",
    "contains",
    "equals",
    "is_in",
    "matches_regex",
    "rank_rules",
    "ensemble_weights",
    "firing_confidence",
    "to_markdown",
    "SigmaRule",
    "SigmaUnsupported",
    "load_sigma_file",
    "load_sysmon_events",
    "load_garak_events",
    "normalize_windows_fields",
    "WINDOWS_FIELD_MAP",
]
