# LinkedIn post draft

Post the text below. Put the link in the post itself, or — if you want to test
whether LinkedIn's reach penalty for external links is hurting you — in the
first comment instead and add "link in comments" to the post.

---

Keyword rules catch 8.8% of real jailbreaks.

I replayed 666 in-the-wild jailbreak prompts against the prompt-injection rule most teams write first — the one that greps for "ignore previous instructions" and "developer mode."

It caught 59 of them. 8.8%.

Not because the rule is bad, but because almost nobody jailbreaks that way anymore. Real attacks lean on role-play and persona framing: "you are now…", "act as…", "pretend to be…". I added rule families for those, let the harness rank and vote, and recall jumped to 70% — with the keyword rule ranked dead last.

The ~30% that still slips through is the honest case for semantic detection.

I found this with a backtester I built by stripping the models out of an old (failed) lottery predictor and repointing its evaluation harness at Sigma rules. The value was never in the models — it was in the thing that measured them.

Write-up + open-source code 👇

https://blog.secureorbit.cloud/posts/backtesting-detection-rules.html

#DetectionEngineering #AISecurity #ThreatDetection #LLMSecurity
