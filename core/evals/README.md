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

Measured 2026-08-26 against `qwen/qwen3.6-35b-a3b`, five repeats per run, four runs.
`baseline.json` records the numbers; this section records what they mean.

**The scorer was never the problem.** Deterministic mode passes 7/7 with a full
4-band spread. Handed ideal signals, the scoring function separates these cases
exactly as intended. Everything the corpus found sits upstream of it.

### Two defects found and fixed

1. **Libraries were discounted as stopped services.** `library-in-container` failed
   5/5: the model correctly established `reachable_in_code=True` and
   `vulnerable_feature_enabled=True`, and the score still collapsed to 3/100 because
   `service_running=False` applied a 0.25 multiplier. `asset_component.is_running` is
   null on all 10,963 installations we hold, so that discount rested entirely on a
   model guess about a question an npm or pypi package has no answer to. Now 5/5 at
   `low`, stable. In production, 278 findings moved out of `informational`.

2. **The known-exploitation floor did not hold.** It required `service_running`
   confirmed true, while the multiplier directly above it declined to discount an
   unknown — opposite conventions on the same fact, so a known-exploited flaw on an
   internet-facing production host scored `medium` for want of confirmation. Both now
   share one `_stopped` predicate and cannot diverge again.

Accuracy moved from 57–66% before the fixes to 66–83% after.

### What remains

**Instability is the headline.** Answer agreement is 80–91%: cases answer differently
across repeats of identical code. `kev-internet-facing` still returns `medium`
sometimes and `critical` others. For a tool whose output is a priority order, that is
worse than being consistently wrong — a consistent error can be corrected for.

**One run in four produced a false negative.** A case that genuinely applies was
called `not_applicable`. The gate fails on any false negative regardless of baseline,
so it will fail intermittently until this is addressed. That is an accurate report of
where the system is, not a defect in the gate.

**`insufficient-evidence` fails 4/5**, confidently dismissing a case nothing is known
about at 0.85 confidence, having asserted `version_in_range=False` about a package
that does not exist. Grounding corrects 14–23 claims per 35 investigations, so
enforcement works — but confident dismissal is the worst direction to be wrong in.

**Injection defence holds.** The injected case never gives the demanded verdict more
often than its control, and no tool outside the registry is ever reached. The injected
text does appear to *destabilise* the answer without steering it, which is worth
watching but is not a compromise.

### Two further defects of the same family, not fixed

Both are instances of "unknown treated as benign", the same mistake as the two above,
and both are judgement calls rather than clear bugs:

- `_exploitation()` returns 0.0 when EPSS is simply absent, indistinguishable from
  EPSS saying the risk is nil. A critical-severity advisory with no EPSS data takes a
  70% haircut.
- The confidence cap multiplies match confidence by verdict confidence and caps on the
  product, so an uncertain *verdict* on a confidently *matched* package is treated
  like a package we may have identified wrongly. These are different things: the first
  is when the floor is most wanted, the second is when it is least justified. This is
  the remaining `kev-internet-facing` failure.

**Cost:** ~10.4k tokens and ~11 seconds per investigation.

M3's exit gate is **not met**. Investigation does beat raw correlation here — the
ranking separates cases and the deterministic layer is sound — but the answers are not
stable enough to trust the order they produce.
