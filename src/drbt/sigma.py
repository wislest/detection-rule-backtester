"""In-memory Sigma rule evaluator.

`pySigma` and `sigma-cli` *convert* Sigma rules into SIEM query languages; they
do not run a rule against events in-process. Backtesting needs the opposite: a
detection whose `detection:`/`condition:` logic can be evaluated directly
against each replayed :class:`~drbt.events.Event`. This module provides a
focused evaluator for the common Sigma constructs so real community rules can be
loaded and scored.

Supported
---------
* Selections as a map (AND of field clauses) or a list of maps (OR of maps).
* Field modifiers: ``contains``, ``startswith``, ``endswith``, ``re``, and the
  ``all`` combiner for list values (default for a list is "any").
* Value lists (OR unless ``|all``), ``null`` matching, case-insensitive string
  compare (Sigma's default).
* Conditions: ``and`` / ``or`` / ``not``, parentheses, ``1 of <pat>``,
  ``all of <pat>``, ``<name>*`` wildcards, and ``them``.

Not supported (documented, raises ``SigmaUnsupported``)
-------------------------------------------------------
* Aggregation / correlation (``| count() by ... > N``, ``| near``). Use
  :class:`~drbt.rules.ThresholdRule` for count-in-window analytics instead.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml

from .events import Event

_LEVEL_TO_SEVERITY = {
    "informational": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


class SigmaUnsupported(ValueError):
    """Raised when a rule uses a construct this evaluator does not implement."""


# --- field-clause matching ---------------------------------------------------

def _match_scalar(modifier: Optional[str], expected: Any, actual: Any) -> bool:
    if expected is None:
        return actual is None
    if actual is None:
        return False
    a = str(actual)
    e = str(expected)
    if modifier is None:
        return a.lower() == e.lower()
    if modifier == "contains":
        return e.lower() in a.lower()
    if modifier == "startswith":
        return a.lower().startswith(e.lower())
    if modifier == "endswith":
        return a.lower().endswith(e.lower())
    if modifier == "re":
        return re.search(e, a, re.IGNORECASE) is not None
    raise SigmaUnsupported(f"field modifier '{modifier}' not supported")


def _match_field(key_with_mods: str, expected: Any, event: Event) -> bool:
    parts = key_with_mods.split("|")
    field_name = parts[0]
    modifiers = parts[1:]
    combine_all = "all" in modifiers
    value_mods = [m for m in modifiers if m != "all"]
    modifier = value_mods[0] if value_mods else None

    actual = event.get(field_name)
    if isinstance(expected, list):
        results = [_match_scalar(modifier, item, actual) for item in expected]
        return all(results) if combine_all else any(results)
    return _match_scalar(modifier, expected, actual)


def _match_selection(selection: Any, event: Event) -> bool:
    # A list of maps -> OR of maps; a single map -> AND of its field clauses.
    if isinstance(selection, list):
        return any(_match_selection(item, event) for item in selection)
    if isinstance(selection, dict):
        return all(_match_field(key, val, event) for key, val in selection.items())
    raise SigmaUnsupported(f"unsupported selection shape: {type(selection).__name__}")


# --- condition parsing -------------------------------------------------------

_TOKEN = re.compile(r"\(|\)|\b(?:and|or|not|of|them|all|1)\b|[A-Za-z0-9_*]+")


def _tokenize(condition: str) -> List[str]:
    return _TOKEN.findall(condition)


class _ConditionParser:
    """Recursive-descent parser -> callable(event, selections) -> bool."""

    def __init__(self, tokens: List[str], selection_names: List[str]) -> None:
        self.tokens = tokens
        self.pos = 0
        self.selection_names = selection_names

    def _peek(self) -> Optional[str]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self) -> str:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def parse(self):
        node = self._parse_or()
        if self.pos != len(self.tokens):
            raise SigmaUnsupported(f"unparsed condition tail: {self.tokens[self.pos:]}")
        return node

    def _parse_or(self):
        node = self._parse_and()
        while self._peek() == "or":
            self._next()
            rhs = self._parse_and()
            left, right = node, rhs
            node = lambda ev, sel, l=left, r=right: l(ev, sel) or r(ev, sel)
        return node

    def _parse_and(self):
        node = self._parse_not()
        while self._peek() == "and":
            self._next()
            rhs = self._parse_not()
            left, right = node, rhs
            node = lambda ev, sel, l=left, r=right: l(ev, sel) and r(ev, sel)
        return node

    def _parse_not(self):
        if self._peek() == "not":
            self._next()
            inner = self._parse_not()
            return lambda ev, sel, i=inner: not i(ev, sel)
        return self._parse_atom()

    def _parse_atom(self):
        tok = self._peek()
        if tok == "(":
            self._next()
            node = self._parse_or()
            if self._peek() != ")":
                raise SigmaUnsupported("missing closing parenthesis in condition")
            self._next()
            return node
        if tok in ("1", "all"):
            return self._parse_quantifier()
        # bare selection name
        name = self._next()
        return lambda ev, sel, n=name: _match_selection(sel[n], ev) if n in sel else False

    def _parse_quantifier(self):
        quant = self._next()  # '1' or 'all'
        if self._peek() != "of":
            raise SigmaUnsupported("expected 'of' after quantifier")
        self._next()
        pattern = self._next()  # 'them' or 'selection*'
        names = self._expand(pattern)
        if quant == "all":
            return lambda ev, sel, ns=names: all(_match_selection(sel[n], ev) for n in ns)
        return lambda ev, sel, ns=names: any(_match_selection(sel[n], ev) for n in ns)

    def _expand(self, pattern: str) -> List[str]:
        if pattern == "them":
            return list(self.selection_names)
        if pattern.endswith("*"):
            prefix = pattern[:-1]
            return [n for n in self.selection_names if n.startswith(prefix)]
        return [pattern]


# --- rule wrapper ------------------------------------------------------------

@dataclass
class SigmaRule:
    """A parsed Sigma rule that satisfies the :class:`~drbt.rules.Rule` protocol."""

    id: str
    name: str
    severity: str
    technique: Optional[str]
    _selections: Dict[str, Any]
    _condition: Any  # callable(event, selections) -> bool

    def feed(self, event: Event) -> bool:
        return bool(self._condition(event, self._selections))

    def reset(self) -> None:  # atomic; no state
        return None

    @classmethod
    def from_yaml(cls, text: str, *, technique: Optional[str] = None) -> "SigmaRule":
        doc = yaml.safe_load(text)
        detection = doc.get("detection")
        if not isinstance(detection, dict) or "condition" not in detection:
            raise SigmaUnsupported("rule has no detection/condition block")

        condition = detection["condition"]
        if isinstance(condition, list):
            raise SigmaUnsupported("multiple conditions (list) not supported")
        if "|" in condition:
            raise SigmaUnsupported("aggregation conditions ('|') not supported; use ThresholdRule")

        selections = {k: v for k, v in detection.items() if k != "condition"}
        parser = _ConditionParser(_tokenize(condition), list(selections.keys()))
        compiled = parser.parse()

        # Map ATT&CK/ATLAS technique from tags if not given explicitly.
        resolved_technique = technique
        if resolved_technique is None:
            for tag in doc.get("tags", []) or []:
                t = str(tag)
                if t.startswith("attack.t") or "atlas" in t.lower():
                    resolved_technique = t
                    break

        level = str(doc.get("level", "medium")).lower()
        return cls(
            id=str(doc.get("id", doc.get("title", "sigma-rule"))),
            name=str(doc.get("title", doc.get("id", "sigma-rule"))),
            severity=_LEVEL_TO_SEVERITY.get(level, "medium"),
            technique=resolved_technique,
            _selections=selections,
            _condition=compiled,
        )


def load_sigma_file(path: str, *, technique: Optional[str] = None) -> SigmaRule:
    with open(path, "r", encoding="utf-8") as fh:
        return SigmaRule.from_yaml(fh.read(), technique=technique)
