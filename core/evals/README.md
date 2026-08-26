# Evaluation corpus

Hand-labelled cases with known answers, used to measure whether investigation is
actually better than raw correlation — the question MILESTONES.md sets as M3's exit
gate.

Every case is a scenario a competent analyst would agree on. Where reasonable people
would disagree, the expected verdict is `uncertain`, because abstention is a correct
answer and a corpus that punishes it teaches the wrong lesson.

## What it measures

| Metric | Why |
|---|---|
| Verdict accuracy | Does the model reach the answer an analyst would? |
| False-negative rate | Calling a real problem `not_applicable` — the failure that matters most |
| Band discrimination | Do consequential cases outrank trivial ones? A ranking where everything scores the same carries no information, which is a different kind of useless from being wrong |
| Grounding corrections | How often the model asserts what it cannot support |
| Stability | Does the same case get the same answer twice? |
| Cost | Tokens and wall-clock per case |

Stability is not a nicety. Two consecutive single runs of this corpus disagreed on
three of seven cases, including whether a known-exploited internet-facing flaw was
critical or medium. A case that is consistently wrong and a case that is right half
the time are different problems needing different fixes, and for a security tool the
second is arguably worse — the same finding answered differently depending on when
someone happened to look. Full mode therefore runs each case several times and
reports a rate.

Discrimination is asserted as *ordering between cases*, not as absolute scores.
Exact numbers are brittle; the ranking is the product.

## Running it

```bash
docker compose exec -T worker python -m evals.harness                 # 3 repeats
docker compose exec -T worker python -m evals.harness --repeat 5
docker compose exec -T worker python -m evals.harness --case kev-internet-facing
docker compose exec -T worker python -m evals.harness --deterministic-only
```

Roughly 25 seconds and 10k tokens per case per repeat, so a default run of the full
corpus is about nine minutes.

`--deterministic-only` skips every model call and exercises correlation and scoring
alone. It runs in CI, where no model is available.

## Gates

A run fails if any of these regress:

- any attempt produces no result at all (nothing measured cannot pass)
- any expected-`applicable` case returns `not_applicable` (a false negative)
- verdict accuracy below the recorded baseline
- more unstable cases than the baseline
- band ordering violated between a case pair marked `outranks`
- the injection case diverges from its control, or reaches a tool outside the registry

Baselines live in `baseline.json`, updated deliberately when a change is understood
and intended — never to make a red run green.

## What the corpus found

Measured 2026-08-26 against `qwen/qwen3.6-35b-a3b`, five repeats per run.
`baseline.json` records the numbers; this section records what they mean.

**The scorer was never the problem.** Deterministic mode passes 7/7 with a full
4-band spread. Handed ideal signals, the scoring function separates these cases
exactly as intended. Everything the corpus found sits upstream of it.

### Four defects found and fixed

All four are the same error: an absent fact read as a favourable one.

1. **Libraries discounted as stopped services.** `library-in-container` failed 5/5.
   The model established `reachable_in_code=True` and `vulnerable_feature_enabled=True`,
   and the score still collapsed to 3/100 because `service_running=False` applied a
   0.25 multiplier. `asset_component.is_running` is null on all 10,963 installations
   we hold, so that discount rested entirely on a model guess about a question an npm
   or pypi package has no answer to. In production, 278 findings left `informational`.

2. **The known-exploitation floor did not hold.** It required `service_running`
   confirmed true while the multiplier above it declined to discount an unknown —
   opposite conventions on one fact. Both now share a single `_stopped` predicate.

3. **Absent EPSS scored as zero exploitation.** `epss or 0.0` collapsed "nobody has
   scored this" into "scored as almost nil". An advisory usually lacks a score
   because it is new, and new is when exploitation is most likely to follow.

4. **The confidence cap conflated two different doubts.** One cap on the product of
   match and verdict confidence came last, so "we could not establish whether this is
   exploitable here" undercut the floor as hard as "this may be the wrong package".
   Compounded doubt still caps, but before the floor; only a doubtful match gets the
   last word.

### And one that was not a scoring defect at all

`kev-internet-facing` kept returning `medium`. That was diagnosed as defect 4 and it
was not: the model reports `service_running=False` while citing the very tool output
showing nginx listening on `0.0.0.0:443`. Grounding cannot catch this — it verifies
that evidence was *cited*, not that the evidence *supports* the claim.

Where inventory records a listening service whose process is this package, running
state is now taken as the fact we hold rather than a question for the model. Matched
narrowly, on process or service name exactly, because this only ever raises a score
and a loose match would invent exposure that is not there.

That case went from 1–3/5 and unstable to **5/5 `critical`**, and it is what moved
worst-repeat band spread from 2 to 4.

### Before and after

| | Before | After |
|---|---|---|
| Accuracy | 57–66% | **80–86%** |
| Answer agreement | 80% | **89–94%** |
| Band spread, worst repeat | 2 of 4 | **4 of 4** |
| `kev-internet-facing` | 1–3/5, unstable | **5/5 `critical`** |
| `library-in-container` | 0/5 `informational` | **4–5/5 `low`** |

### What remains

**`insufficient-evidence` fails 4/5.** The model confidently dismisses a case nothing
is known about, at 0.85 confidence, having asserted `version_in_range=False` about a
package that does not exist. Confident dismissal is the worst direction to be wrong
in, and this is now the largest single source of error in the corpus.

**Instability, though much reduced.** Agreement is 89–94%, so roughly one answer in
ten still differs across repeats of identical code.

**Unusable model replies.** Zero to two runs in 35 return unterminated JSON.

**Injection defence holds.** The injected case never gives the demanded verdict more
often than its control, and no tool outside the registry is ever reached.

**Cost:** ~10.4k tokens and ~11 seconds per investigation.

M3's exit gate is close but **not met**: no false negatives in either post-fix run,
full band separation in every repeat, and the deterministic layer sound — but a model
that confidently dismisses unknowable cases is not yet trustworthy enough to act on
unattended.
