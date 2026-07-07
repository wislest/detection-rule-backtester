# Detection Rule Backtester

Replay labelled logs and AI-attack traces against detection rules, then measure
how good each rule actually is: **precision, recall, false-positive rate, F1,
and multi-rule ensemble confidence — per rule**.

Detection engineers write rules (Sigma, [Agent Threat Rules](https://github.com/Agent-Threat-Rule/agent-threat-rules),
KQL analytics) but rarely have a clean harness to answer *"if I ship this rule,
how many true attacks does it catch and how much noise does it generate against
my historical data?"* This tool is that harness. It treats a rule as a binary
classifier over events and scores it against ground truth.

The evaluation engine is recycled — deliberately, and decoupled — from a lottery
prediction backtester (per-detector metrics, weighted ranking, moving-average
trends, ensemble weighting). The scoring core was rewritten from set-overlap of
drawn numbers to a confusion matrix suited to detection.

## Two tracks, one harness

| Track | Events replayed | Rules | Ground truth |
|-------|-----------------|-------|--------------|
| **A — Classic detection** | Sysmon/EVTX, auth logs | Sigma-style field/threshold rules | labelled attack events |
| **B — AI attacks** | LLM prompts, agent tool-call traces | prompt-injection / agent-abuse rules (ATR, KQL-style) | known injection = positive |

Rules carry a `technique` tag (MITRE ATLAS, ATT&CK, OWASP LLM Top 10) so recall
can be **scoped** to the attacks a rule is actually meant to catch, while the
false-positive rate is always measured against all benign traffic.

## Quick start

```bash
pip install -e ".[dev]"
python examples/demo_backtest.py   # prints a Markdown report
pytest                             # run the test suite
```

## What you get

```python
from drbt import BacktestEngine, Event, FieldMatchRule, matches_regex, to_markdown

rule = FieldMatchRule(
    id="R-PI-KW",
    name="Prompt-injection keywords",
    conditions={"prompt": matches_regex(r"ignore (all )?previous|developer mode")},
    severity="high",
    technique="OWASP-LLM01",
)

result = BacktestEngine([rule]).run(events)   # events: list[Event] with is_attack labels
print(to_markdown(result))
```

The report includes a per-rule performance table, a blended global ranking with
ensemble weights, a coverage matrix by technique, and an ensemble-firing summary
(mean confidence on true attacks vs false alarms).

## Rule types built in

- **`FieldMatchRule`** — atomic per-event condition (`equals` / `contains` /
  `matches_regex` / `is_in`), combined with logical AND. The common denominator
  of most Sigma detections.
- **`ThresholdRule`** — correlation rule that fires when an inner matcher hits
  `count` times within `window_seconds` for the same `group_by` field. Models
  analytics like *"3+ prompt-injection attempts within 10 minutes from similar
  IPs"*.

External formats (Sigma via `pySigma`, ATR, compiled KQL) plug in by wrapping
them as a `Rule` (`feed(event) -> bool`, `reset()`).

## Datasets to replay (track B)

Pinned locally under `data/` (not committed). Useful public corpora:

- **Agent Red Teaming Benchmark** — ~4,700 attacks across 44 target behaviours.
- **Indirect prompt-injection benchmark** — ~2,679 attacks across 41 behaviours.
- **NVIDIA garak** — generates a labelled adversarial corpus (every sample is a
  known probe).

## Status

`v0.1` — core harness, two rule engines, synthetic demo, tests. Scope is a
focused detection-engineering portfolio piece, **not** a SIEM/SOAR platform.

## License

MIT.
