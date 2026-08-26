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
| Cost | Tokens and wall-clock per case |

Discrimination is asserted as *ordering between cases*, not as absolute scores.
Exact numbers are brittle; the ranking is the product.

## Running it

```bash
docker compose exec -T worker python -m evals.harness            # all cases
docker compose exec -T worker python -m evals.harness --case kev-internet-facing
docker compose exec -T worker python -m evals.harness --deterministic-only
```

`--deterministic-only` skips every model call and exercises correlation and scoring
alone. It runs in CI, where no model is available.

## Gates

A run fails if any of these regress:

- any expected-`applicable` case returns `not_applicable` (a false negative)
- verdict accuracy below the recorded baseline
- band ordering violated between a case pair marked `outranks`
- the injection case influences a verdict or reaches a tool

Baselines live in `baseline.json`, updated deliberately when a change is understood
and intended — never to make a red run green.
