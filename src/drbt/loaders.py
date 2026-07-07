"""Corpus loaders: normalize public formats into the unified ``Event`` schema.

Two adapters ship here, one per track:

* :func:`load_sysmon_events` — track A. Reads JSONL Windows-event records in the
  shape used by the Security-Datasets / Mordor project (fields like ``Image``,
  ``CommandLine``, ``EventID``, ``@timestamp``). Sigma ``process_creation`` rules
  match directly against these field names.
* :func:`load_garak_events` — track B. Reads a NVIDIA garak report JSONL, where
  each ``attempt`` carries a ``prompt`` and detector verdicts. Every probe is an
  attack attempt, so events are labelled ``is_attack=True``; the probe class maps
  to a technique tag.

Ground-truth labelling
-----------------------
Track A relies on an explicit label field (``label`` / ``is_attack``) or an
attack-tagging callback, because raw Sysmon logs are unlabelled. Track B is
self-labelling: garak only emits attack probes.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from .events import Event


def _parse_timestamp(value: Any, fallback: datetime) -> datetime:
    if value is None:
        return fallback
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    text = str(value).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return fallback


def _iter_jsonl(path: str):
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


def load_sysmon_events(
    path: str,
    *,
    label_fn: Optional[Callable[[Dict[str, Any]], bool]] = None,
    technique_fn: Optional[Callable[[Dict[str, Any]], Optional[str]]] = None,
) -> List[Event]:
    """Load Sysmon/EVTX-style JSONL records (track A).

    ``label_fn`` decides ``is_attack`` per record. If omitted, an ``is_attack``
    or ``label`` key on the record is used (``label == "attack"``).
    """
    events: List[Event] = []
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for i, rec in enumerate(_iter_jsonl(path)):
        ts = _parse_timestamp(rec.get("@timestamp") or rec.get("timestamp"), base)
        if label_fn is not None:
            is_attack = label_fn(rec)
        else:
            is_attack = bool(rec.get("is_attack")) or rec.get("label") == "attack"
        technique = technique_fn(rec) if technique_fn else rec.get("technique")
        events.append(
            Event(
                id=str(rec.get("id", f"sysmon-{i}")),
                timestamp=ts,
                source="sysmon",
                fields={k: v for k, v in rec.items() if not k.startswith("@")},
                is_attack=is_attack,
                technique=technique,
            )
        )
    return events


def load_garak_events(path: str, *, technique_prefix: str = "OWASP-LLM01") -> List[Event]:
    """Load a garak report JSONL as labelled prompt-injection events (track B).

    garak emits one JSON object per line; ``attempt`` entries hold ``prompt`` and
    ``probe_classname``. Non-attempt bookkeeping lines are skipped. Every attempt
    is an attack (``is_attack=True``); the probe class refines the technique tag.
    """
    events: List[Event] = []
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    idx = 0
    for rec in _iter_jsonl(path):
        if rec.get("entry_type") not in (None, "attempt"):
            continue
        prompt = rec.get("prompt")
        if prompt is None:
            continue
        probe = rec.get("probe_classname") or rec.get("probe")
        technique = f"{technique_prefix}:{probe}" if probe else technique_prefix
        ts = _parse_timestamp(rec.get("timestamp"), base)
        events.append(
            Event(
                id=str(rec.get("uuid", f"garak-{idx}")),
                timestamp=ts,
                source="llm-gateway",
                fields={
                    "prompt": prompt if isinstance(prompt, str) else json.dumps(prompt),
                    "src_ip": rec.get("src_ip", "garak-harness"),
                    "probe": probe,
                },
                is_attack=True,
                technique=technique,
            )
        )
        idx += 1
    return events
