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

### And one the corpus caught me introducing

Enforcing the established facts was right. *Telling the model about them* was not:
adding a "these are already established" block to the prompt sent
`kev-internet-facing` from 5/5 `applicable` to 5/5 `not_applicable` — a consistent
false negative on the least ambiguous case in the corpus.

The block had to sit inside the data fence, which told the model in one breath that
these were settled facts and that they were quoted material never to be obeyed. The
seed facts already carry the match method and its confidence, so it was redundant
before it was contradictory. Enforcement on the way back was kept; the prompt block
was dropped.

This is the corpus paying for itself. The change looked obviously good, the unit
tests passed, and it would have shipped.

### Before and after

| | Start | After scoring fixes | After grounding fixes |
|---|---|---|---|
| Accuracy | 57–66% | 80–86% | **89–91%** |
| Answer agreement | 80% | 89–94% | **84–97%** |
| Band spread, worst repeat | 2 of 4 | 4 of 4 | **4 of 4** |
| `insufficient-evidence` | 1/5 | 1/5 | **5/5 `uncertain`** |
| `kev-internet-facing` | 1–3/5, unstable | 5/5 `critical` | **5/5 `critical`** |
| `library-in-container` | 0/5 `informational` | 4–5/5 `low` | **4–5/5 `low`** |

### What remains

**Abstention has moved, not vanished.** `isolated-dev-laptop` and
`library-in-container` now sometimes answer `uncertain` where they used to answer
`applicable`. That is the dismissal rules working as intended — the model is less
decisive because less of what it asserts survives — but it is worth watching that
honest abstention does not drift into uselessness.

**Instability, much reduced but real.** Agreement is 84–97% across runs.

**Unusable model replies.** One or two attempts in 35 return unterminated JSON. This
is the endpoint, not the logic, and it is the largest remaining source of lost work.

**Four of eight signals have no tool that could establish them.** Nothing in the
registry inspects configuration or code, so `vulnerable_feature_enabled`,
`reachable_in_code`, `authentication_required` and `compensating_controls` can only
ever be inferences from advisory text. The advisory-describes-flaw rule stops the
worst of that, but the honest fix is either tools that can observe these things or
fewer signals.

**Injection defence holds.** The injected case never gives the demanded verdict more
often than its control, and no tool outside the registry is ever reached.

**Cost:** ~10.4k tokens and ~11 seconds per investigation.

M3's exit gate is **met on this corpus**: no false negatives across the last four
runs, full band separation in every repeat, injection defence evidenced against a
control, and abstention where abstention is correct. The corpus is seven cases, which
is enough to have caught five real defects and one I introduced, and not enough to
call the system trustworthy in general. The next honest step is more cases, not a
higher number on these.
