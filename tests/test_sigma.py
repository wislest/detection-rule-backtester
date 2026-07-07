from datetime import datetime

import pytest

from drbt import Event, SigmaUnsupported
from drbt.sigma import SigmaRule

TS = datetime(2026, 1, 1, 0, 0, 0)


def _rule(yaml_text):
    return SigmaRule.from_yaml(yaml_text)


def test_and_of_selections_with_modifiers():
    rule = _rule(
        """
title: Encoded PowerShell
id: t1
level: high
tags: [attack.t1059.001]
detection:
  selection_img:
    Image|endswith: '\\cmd.exe'
  selection_enc:
    CommandLine|contains: 'powershell'
    CommandLine|re: '-enc'
  condition: selection_img and selection_enc
"""
    )
    assert rule.severity == "high"
    assert rule.technique == "attack.t1059.001"
    hit = Event("a", TS, "sysmon", {"Image": "C:\\Windows\\cmd.exe", "CommandLine": "powershell -enc AAA"})
    miss = Event("b", TS, "sysmon", {"Image": "C:\\Windows\\cmd.exe", "CommandLine": "dir"})
    assert rule.feed(hit) is True
    assert rule.feed(miss) is False


def test_list_value_is_or():
    rule = _rule(
        """
title: keywords
id: t2
detection:
  selection:
    prompt|re:
      - 'ignore (previous|prior)'
      - 'developer mode'
  condition: selection
"""
    )
    assert rule.feed(Event("a", TS, "llm", {"prompt": "please ignore previous rules"})) is True
    assert rule.feed(Event("b", TS, "llm", {"prompt": "enable developer mode"})) is True
    assert rule.feed(Event("c", TS, "llm", {"prompt": "what is the weather"})) is False


def test_one_of_them_and_not():
    rule = _rule(
        """
title: quant
id: t3
detection:
  sel_a:
    field: 'a'
  sel_b:
    field: 'b'
  filter:
    safe: true
  condition: 1 of sel_* and not filter
"""
    )
    assert rule.feed(Event("x", TS, "s", {"field": "a"})) is True
    assert rule.feed(Event("y", TS, "s", {"field": "b"})) is True
    assert rule.feed(Event("z", TS, "s", {"field": "a", "safe": True})) is False
    assert rule.feed(Event("w", TS, "s", {"field": "c"})) is False


def test_aggregation_condition_rejected():
    with pytest.raises(SigmaUnsupported):
        _rule(
            """
title: agg
id: t4
detection:
  selection:
    EventID: 4625
  condition: selection | count() by src > 5
"""
        )
