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

That is a backtest. And the machinery for it is the same machinery you'd build
to backtest a market strategy, or — in my case — a lottery predictor. Yes, I
once built a system (LomaXWin) to predict lottery numbers. No, it doesn't work,
and I know that precisely because I made the harness prove it: every model run
against a pure-random baseline over ten thousand simulations, with a chi-square
test to catch any edge over chance. None of them had one. That could have been
the end of the project. Instead it was the useful part: the harness around those
useless models was solid. Replay history, score each predictor, rank them,
weight an ensemble, track drift, all of it spent on a coin flip. So I lifted the harness out, threw
away the models, and rewrote the scoring core as a confusion matrix. The result
is the [Detection Rule Backtester](https://github.com/wislest/detection-rule-backtester).

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

Both rules fired at precision 1.0, which looked fine until I checked the
Squiblydoo rule's recall: 0.5. It had caught the attack once and missed it once,
and that stopped me for a minute, because there was only one attack to catch.
The answer was that the same process creation gets logged twice — once by Sysmon
(EventID 1) and once by Windows Security (EventID 4688). The rule keys on
`Image`, a Sysmon field name; the 4688 record carries the identical data under
`NewProcessName`. Same event, different schema, and a rule written against one
schema is blind to the other.

The fix is not cleverer regex — it's **field normalization**, the same idea as
Sigma processing pipelines or the OSSEM data dictionary. Map the Security field
names onto the Sysmon names before evaluating:

```python
events = load_sysmon_events(capture, normalize=True)   # 4688 gains Image/ParentImage
```

Scoped recall goes from 0.5 to 1.0. The harness printed both runs side by side,
and that is what I wanted from it: not just a score, but a hint at where the
rule was losing ground, and a way to confirm the fix actually moved the number.

## Finding 2 (track B): keyword rules barely dent real jailbreaks

For AI attacks I replayed 666
[in-the-wild jailbreak prompts](https://github.com/NVIDIA/garak) shipped with
NVIDIA's garak, plus a few named DAN / Developer-Mode payloads, mixed with
benign prompts so precision and false-positive rate mean something.

A classic prompt-injection rule keyed on instruction-override phrasing —
*"ignore previous instructions", "developer mode", "reveal your system prompt"*
— caught **8.8% (59/669)**, at precision 1.0. The low number is the interesting
part. When I counted markers across the corpus, literal override phrasing turned
out to be rare:
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

The override-keyword rule, the one most people reach for first, ranks last. And
even all four families together leave about 30% of real jailbreaks uncaught.
That residual is the honest argument for semantic detection: keyword and regex
rules are a cheap first layer with a hard ceiling, and now I can point to where
the ceiling sits instead of just asserting there is one.

## Why this shape matters

Neither finding is exotic. What's useful is that both came out of the *same*
measurement loop, and the loop is honest about its own limits: the Sigma
evaluator ignores `logsource` (so pre-filter by source), scoped recall depends
on rule and corpus taxonomies agreeing, and IOC-based labels are approximate.
Those caveats are in the README, not hidden, because a backtester that flatters
your rules is worse than none.

The through-line from a dead lottery project turned out to be simple: the value
was never in the models, it was in the harness that measured them. Repointed at
detection rules, classic and AI-facing alike, it finally has something worth
measuring.

---

*Code, rules and reproducible runs: <https://github.com/wislest/detection-rule-backtester>.
Every number above regenerates from `examples/run_real_dataset.py` and
`examples/run_real_garak.py` after `bash scripts/fetch_datasets.sh`.*
