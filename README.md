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

# Backtest real Sigma rules against sample corpora (track A + track B):
drbt --rules examples/rules \
     --sysmon examples/data/sysmon_sample.jsonl \
     --garak  examples/data/garak_sample.jsonl

python examples/demo_backtest.py   # same idea, hand-built rules, no Sigma
pytest                             # run the test suite (12 tests)
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

- **`SigmaRule`** — a real Sigma rule loaded from YAML and evaluated **in
  memory** against each event. `pySigma`/`sigma-cli` only *convert* Sigma into
  SIEM query languages; backtesting needs to run the `detection:`/`condition:`
  logic directly, so `drbt` ships a focused evaluator (see below).

Other formats (ATR, compiled KQL) plug in the same way — wrap them as a `Rule`
(`feed(event) -> bool`, `reset()`).

## Loading real Sigma rules and corpora

```python
from drbt import BacktestEngine, load_sigma_file, load_sysmon_events, load_garak_events, to_markdown

rules  = [load_sigma_file("examples/rules/encoded_powershell.yml")]
events = load_sysmon_events("examples/data/sysmon_sample.jsonl")
print(to_markdown(BacktestEngine(rules).run(events)))
```

The in-memory Sigma evaluator supports selections (map = AND, list-of-maps =
OR), field modifiers (`contains`, `startswith`, `endswith`, `re`, `all`), value
lists, and conditions with `and`/`or`/`not`, parentheses, `1 of`/`all of`, name
wildcards and `them`. Aggregation conditions (`| count() by ... > N`) are
rejected with a clear error — model those as a `ThresholdRule` instead.

Loaders normalize public corpora into the `Event` schema:

- **`load_sysmon_events`** — Security-Datasets / Mordor style Windows-event JSONL
  (track A); labels come from a `label`/`is_attack` field or a callback.
- **`load_garak_events`** — a NVIDIA garak report JSONL (track B); every probe is
  an attack, its probe class becomes the technique tag.

> Scoping caveat surfaced by the demo: per-rule *scoped recall* only engages when
> the rule's `technique` tag matches the corpus label taxonomy. A rule tagged
> `atlas.aml.t0051` will not scope against events labelled `OWASP-LLM01:*` — keep
> rule and corpus taxonomies aligned, or scoped recall falls back to overall
> recall.

## Datasets to replay (track B)

Pinned locally under `data/` (not committed). Useful public corpora:

- **Agent Red Teaming Benchmark** — ~4,700 attacks across 44 target behaviours.
- **Indirect prompt-injection benchmark** — ~2,679 attacks across 41 behaviours.
- **NVIDIA garak** — generates a labelled adversarial corpus (every sample is a
  known probe).

## Status

`v0.2` — core harness, three rule engines (field / threshold / **in-memory
Sigma**), corpus loaders (Sysmon + garak), `drbt` CLI, synthetic demo, 12 tests.
Scope is a focused detection-engineering portfolio piece, **not** a SIEM/SOAR
platform.

## License

MIT.
