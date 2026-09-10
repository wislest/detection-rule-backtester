# LinkedIn post draft

**Timing.** Every major 2026 study (Buffer, Sprout Social, RecurPost, Publora) ranks
weekends last for LinkedIn — Saturday indexes around 28 against Tuesday at 100. Aim for
Tuesday–Thursday, 10–11 a.m. in your audience's timezone. The one thing that outranks the
day is being present: LinkedIn's distribution leans on the first 60–90 minutes of replies,
so a slot you can actually work beats a statistically better slot you can't.

**Links.** Keep them out of the post body — external links carry a reach penalty. Post the
text, then drop the links as your own first comment within the minute, and let the post say
"in the comments."

---

Keyword rules catch 8.8% of real jailbreaks.

I replayed 669 in-the-wild jailbreak prompts — NVIDIA garak's corpus plus a few named DAN and Developer-Mode payloads — against the prompt-injection rule most teams write first: the one that greps for "ignore previous instructions" and "developer mode."

It caught 59. That's 8.8%, at precision 1.0.

The low number is the interesting part. Almost nobody jailbreaks that way anymore. Literal override phrasing shows up in 6.5% of the corpus. Role-play framing — "you are now", "act as", "pretend to be" — shows up in 42.6%, and restriction-removal framing in 33.2%.

So I added rule families for those, let the harness rank them and vote, and ensemble recall went to 70.4% — still with zero false alarms on the benign set. The keyword rule ranked dead last.

The ~30% that still slips through is the honest case for semantic detection.

I found this with a backtester I built by stripping the models out of an old lottery predictor that never worked, and repointing its evaluation harness at Sigma rules. The value was never in the models. It was in the thing that measured them.

If you ship prompt-injection rules today: have you measured recall against a real corpus, or does the rule just look right?

Write-up and open-source code in the comments.

#DetectionEngineering #AISecurity #ThreatDetection #LLMSecurity

---

## First comment (post it yourself, immediately)

```
Write-up: https://wistonlestin.com/posts/backtesting-detection-rules
Code: https://github.com/wislest/detection-rule-backtester
```
