# Backtesting detection rules — including the ones for AI attacks

*How a lottery-prediction backtester became a harness for measuring detection
rules, and two things it revealed on real public data.*

## The premise

Detection engineers write rules — Sigma, KQL analytics, the newer
[Agent Threat Rules](https://github.com/Agent-Threat-Rule/agent-threat-rules)
for AI agents — but the feedback loop is weak. You ship a rule and find out how
good it was from production noise, weeks later. The question you actually want
answered before shipping is simple: *against my historical data, how many real
attacks does this rule catch, and how much noise does it make?*

That is a backtest. And it turns out the machinery for it is the same machinery
you'd build to backtest a market strategy — or, in my case, a lottery
predictor. I had an old project (LomaXWin) whose one honest conclusion was that
no method beats random. But its evaluation harness — replay history, score each
predictor, rank them, weight an ensemble, track drift — was solid and entirely
wasted on a coin flip. So I lifted the harness out, threw away the lottery
models, and rewrote the scoring core as a confusion matrix. The result is the
[Detection Rule Backtester](https://github.com/wislest/detection-rule-backtester).

A rule becomes a binary classifier over events:

```
predicted positive := the rule fired on the event
actual positive    := the event is part of an attack (ground-truth label)
```

From there you get precision, recall, F1 and false-positive rate per rule,
rankings, and a multi-rule ensemble confidence. Two tracks share one harness:
classic logs (Sysmon/EVTX) and AI-attack traces (LLM prompts, agent tool
calls). Below are two findings from running it on real public data — one from
each track — because a harness is only interesting if it tells you something you
didn't already know.

## Finding 1 (track A): a rule can be right and still blind

I ran two Sigma rules against a real
[OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) capture — an
Empire launcher that uses `regsvr32` to pull a remote `.sct` scriptlet
(Squiblydoo, `T1218.010`) which spawns an encoded-PowerShell agent
(`T1059.001`) beaconing to a C2. 2,390 events. Since these captures don't ship
per-event labels, I anchored ground truth on the attack's IOCs — the C2 address
and the `regsvr32 → powershell` process lineage — deliberately *independent* of
the process patterns the rules test, to avoid grading the rules on their own
answer key.

Both rules fired at precision 1.0. But the Squiblydoo rule scored **scoped
recall 0.5**. It caught the attack once and missed it once — the *same* process
creation, logged twice: by Sysmon (EventID 1) and by Windows Security (EventID
4688). The rule keys on `Image`, a Sysmon field name. The 4688 record carries
the identical data under `NewProcessName`. Different schema, same event, and a
rule authored against one schema is blind to the other.

The fix is not cleverer regex — it's **field normalization**, the same idea as
Sigma processing pipelines or the OSSEM data dictionary. Map the Security field
names onto the Sysmon names before evaluating:

```python
events = load_sysmon_events(capture, normalize=True)   # 4688 gains Image/ParentImage
```

Scoped recall goes from 0.5 to 1.0. The harness printed both runs side by side,
which is the point: it didn't just score the rule, it localised *why* the rule
under-performed and let me prove the fix moved the number.

## Finding 2 (track B): keyword rules barely dent real jailbreaks

For AI attacks I replayed 666
[in-the-wild jailbreak prompts](https://github.com/NVIDIA/garak) shipped with
NVIDIA's garak, plus a few named DAN / Developer-Mode payloads, mixed with
benign prompts so precision and false-positive rate mean something.

A classic prompt-injection rule keyed on instruction-override phrasing —
*"ignore previous instructions", "developer mode", "reveal your system prompt"*
— caught **8.8% (59/669)**, at precision 1.0. That low number is the finding.
When I counted markers across the corpus, literal override phrasing is rare:
"ignore/disregard previous" appears in 6.5% of prompts, "developer mode" in
3.6%. Real jailbreaks are dominated by *role-play framing* — "you are now",
"act as", "pretend to be" — at 42.6%, and *restriction-removal* framing —
"no restrictions", "unfiltered" — at 33.2%.

So I added three more rule families for exactly those patterns and let the
harness rank them and vote. **Ensemble recall rose to 70.4% (471/669)**, still
with zero false alarms on the benign set. The ranking the harness produced:

| Rank | Rule family | Ensemble weight |
|-----:|-------------|:---------------:|
| 1 | Role-play / persona framing | 0.40 |
| 2 | Restriction-removal framing | 0.30 |
| 3 | DAN persona | 0.20 |
| 4 | Instruction-override keywords | 0.10 |

The override-keyword rule — the one most people reach for first — ranks last.
And even the four families together leave ~30% of real jailbreaks uncaught. That
residual is the quantified argument for semantic detection: keyword and regex
rules are a cheap first layer with a hard ceiling, and now I can say where the
ceiling is instead of asserting it.

## Why this shape matters

Neither finding is exotic. What's useful is that both came out of the *same*
measurement loop, and the loop is honest about its own limits: the Sigma
evaluator ignores `logsource` (so pre-filter by source), scoped recall depends
on rule and corpus taxonomies agreeing, and IOC-based labels are approximate.
Those caveats are in the README, not hidden, because a backtester that flatters
your rules is worse than none.

The through-line from a dead lottery project is the real lesson: the value was
never in the models, it was in the harness that measured them. Point it at
detection rules — classic and AI-facing alike — and it earns its keep.

---

*Code, rules and reproducible runs: <https://github.com/wislest/detection-rule-backtester>.
Every number above regenerates from `examples/run_real_dataset.py` and
`examples/run_real_garak.py` after `bash scripts/fetch_datasets.sh`.*
