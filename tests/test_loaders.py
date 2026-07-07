import os

from drbt import load_garak_events, load_sysmon_events

HERE = os.path.dirname(__file__)
EXAMPLES = os.path.join(HERE, os.pardir, "examples", "data")


def test_load_sysmon_labels_and_fields():
    events = load_sysmon_events(os.path.join(EXAMPLES, "sysmon_sample.jsonl"))
    assert len(events) == 6
    attacks = [e for e in events if e.is_attack]
    assert len(attacks) == 2
    assert all(e.technique == "attack.t1059.001" for e in attacks)
    # @-prefixed keys are stripped from fields; log fields remain.
    assert "CommandLine" in events[0].fields
    assert not any(k.startswith("@") for k in events[0].fields)


def test_load_garak_skips_bookkeeping_and_labels_attacks():
    events = load_garak_events(os.path.join(EXAMPLES, "garak_sample.jsonl"))
    # 5 attempt lines; start/completion bookkeeping skipped.
    assert len(events) == 5
    assert all(e.is_attack for e in events)
    assert all(e.source == "llm-gateway" for e in events)
    assert events[0].technique.startswith("OWASP-LLM01:")
    assert "prompt" in events[0].fields
