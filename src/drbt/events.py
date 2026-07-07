"""Unified event model.

A single ``Event`` shape carries both classic security logs (track A —
Sysmon/EVTX, auth logs) and AI-attack traces (track B — LLM prompts, agent
tool-call arguments). The schema is deliberately generic: a timestamp, a
source, a flat bag of fields, and the ground-truth label used for backtesting.

The design is inspired by the event shapes exposed by AgentSigma (tool-call
telemetry) and the Microsoft Agent 365 -> Sentinel connector, kept minimal so
that adapters can normalize any log source into it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping, Optional


@dataclass(frozen=True)
class Event:
    """A single normalized event replayed against detection rules.

    Attributes:
        id: Stable unique identifier for the event.
        timestamp: When the event occurred (used for windowed correlation).
        source: Logical origin, e.g. ``"sysmon"``, ``"llm-gateway"``,
            ``"agent-tool-call"``.
        fields: Flat key/value payload the rules match against.
        is_attack: Ground truth — ``True`` if this event is part of an attack.
        technique: Optional taxonomy id the attack maps to (MITRE ATLAS /
            ATT&CK / OWASP LLM Top 10), used to scope per-rule recall.
    """

    id: str
    timestamp: datetime
    source: str
    fields: Mapping[str, Any] = field(default_factory=dict)
    is_attack: bool = False
    technique: Optional[str] = None

    def get(self, key: str, default: Any = None) -> Any:
        """Return a field value, tolerating a missing key."""
        return self.fields.get(key, default)
