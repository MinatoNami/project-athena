# Athena — Milestones and Checkpoints

**Status:** Draft · **Version:** 0.3 · **Date:** 28 November 2026
**Related:** [PRD](../Athena%20—%20Product%20Requirements%20Document.md) · [Technical Design](TECHNICAL_DESIGN.md) · [Web UI](WEB_UI.md)

---

## How to read this

A **milestone** is a body of work. A **checkpoint** is a binary gate that closes it — something a person can watch happen against the vulnerable fixture estate, plus assertions that either hold or do not. "The code is written" is not a checkpoint.

Each milestone carries a **decision point**: the question to answer honestly before committing to the next one, while changing direction is still cheap.

```text
Assumptions   2 engineers, full-time · durations in working weeks, including test and docs
Confidence    ±30% M0–M2, ±50% thereafter
```

The **sequence** is the durable part of this plan. The durations will be wrong.

---

## Roadmap

```text
M0  Foundations                  3w   ██
M1  Inventory                    4w   ███
M2  Intelligence & Correlation   4w   ███
M3  Investigation & Risk         5w   ████
M4  Remediation Preparation      4w   ███
M5  Approval → Verify   ★ MVP    4w   ███        ── 24w to MVP
M6  Operability & Trust          5w   ████
M7  Breadth (PRD Phase 2)        8w   ██████
M8  Scale & Hardening            8w   ██████     ── 45w total
```

M1 is the hard serialisation point — nothing downstream is meaningful without a real inventory. Work after M2 can partially overlap, and UI work runs alongside from M1.

---

# M0 — Foundations · 3w

No product value, entirely enabling. The security boundaries go in from the first commit because retrofitting them never happens.

**Scope.** Repo layout, CI, import-boundary enforcement · Postgres schema baseline and migrations · job queue, scheduler with leader election, worker pool · FastAPI skeleton with OpenAPI · **executor as a separate image and DB role** · hash-chained audit table · envelope-encrypted secret storage · Nuxt shell with Nitro session auth and SSE relay · `docker compose up` producing a working empty system · the vulnerable fixture estate.

### ✅ Checkpoint

1. `docker compose up` on a clean machine yields a running system with **no default credentials**; the admin bootstrap token appears once in the log.
2. An operator creates an account, enables MFA, reaches an empty dashboard.
3. A job enqueued via the API is executed by a worker and appears over SSE without a refresh.
4. `athena doctor` reports schema, keys, and connectivity healthy.
5. **Import-boundary test:** `executor` importing from `llm` fails CI.
6. **Audit test:** `UPDATE` on `audit_event` raises; `/audit/verify` returns intact.
7. The fixture estate starts and is reachable.

**Decision point.** *Can a stranger run this?* If M0 already needs a written runbook, the self-hosted premise is in trouble.

**Status, 28 November 2026.** Largely built: the queue, scheduler leadership, the hash-chained audit log and the executor image. Landed on `feat/phase-0-foundations`: the Go 1.27.3 build (bab8e2b), CI running the evals, web and executor tests (aaaa7aa, 332e211), TOTP MFA (b7d200d), the executor boundary tests (3c0793b) and the fixture estate (e51d187). Open: the executor's own database role is not in effect, because core connects as the Postgres superuser (plan 0.3).

---

# M1 — Inventory · 4w

Athena knows what exists, with honest freshness. No vulnerabilities yet.

**Scope.** Asset model, identity keys, merge candidates, tombstoning · GitHub connection (read-only), manifest and lock parsing · SBOM via Syft, PURL normalisation · **Go node agent**: enrolment, mTLS, signed envelopes, `observe` capabilities, offline spool · Ubuntu package/process/service/port/Docker collection · image inventory by digest · asset graph edges · `scan_run` recording partial and failed scans · UI: asset list and detail, freshness, coverage panel.

### ✅ Checkpoint

1. A connected repository's dependencies appear as PURL components within 5 minutes.
2. A node enrols on the fixture host with a single-use token; the private key never leaves the host.
3. Packages, processes, services, ports, and containers appear in the inventory.
4. The graph links repository → image → running container → host → listening port.
5. **Freshness:** stopping the node marks the asset stale within the threshold and renders it distinctly.
6. **Honesty:** a never-scanned asset appears in `/coverage` as such and renders as not-observed — not clean.
7. Killing the node mid-scan leaves a partial `scan_run`; the asset is **not** marked clean.
8. Re-imaging the fixture host produces a merge candidate — not a silent duplicate, not a silent merge.

**Risk.** Container-to-repository provenance may be unresolvable without build-time attestation. Display the gap rather than guessing.

**Decision point.** *Is the inventory trustworthy enough to build conclusions on?* Shaky identity here is inherited by everything downstream.

**Status, 28 November 2026.** Built: inventory, Syft SBOMs, the Go node agent and `scan_run`. Landed: Syft and git images pinned by version and digest (6899a8f), correlation after every repository scan and package ingest (5e2b6be), and closing findings only after a complete scan no longer sees their component (891ab47). Open: egress allowlists for the networked git and Syft sandboxes (plan 0.10).

---

# M2 — Intelligence and Correlation · 4w

The highest-correctness-risk milestone.

**Scope.** Feed adapters (OSV, NVD, KEV, EPSS, GHSA, Ubuntu USN) · normalisation, `content_hash`, revision detection · **version comparators** for PyPI, npm, Debian with upstream test vectors · candidate generation and range evaluation · authority resolution and **backport handling** · match method and confidence · candidate findings, grouping, state machine · re-correlation on revision · UI: findings list, grouping, filters.

### ✅ Checkpoint

1. Cold start ingests the corpus and reports feed health and age per source.
2. The fixture estate produces the **expected** candidate set, verified against a hand-labelled list — both what appears and what does not.
3. **Backport test:** a distro-patched Ubuntu package does **not** produce a confirmed match from the upstream range. The single most important assertion in this milestone.
4. A simulated new advisory reaches candidate findings in under 5 minutes with no rescan.
5. Comparator suites pass — PEP 440 pre-releases, Debian epochs and tildes, npm ranges.
6. A revised advisory re-correlates existing findings, **including previously closed ones**.
7. Every candidate carries a match method and confidence; none is created `CONFIRMED`.
8. Source disagreements are recorded and visible, not silently resolved.

**Risk.** This is where the product is most likely to be quietly wrong. A comparator bug produces confident nonsense at scale — treat a defect here as a correctness incident.

**Decision point.** *What is the raw candidate false-positive rate?* This number is the bar M3 must clear to justify the AI layer at all.

**Status, 28 November 2026.** Built: OSV (including Debian and Ubuntu), KEV, EPSS and Vulnrichment feeds, and correlation. Landed: comparators that match rpmvercmp, dpkg and packaging on reference vectors (22a1037), configurable deadline windows with KEV's own due date winning when earlier (968857d, 54d37fb). Open: NVD and GHSA have no adapter of their own.

---

# M3 — Investigation and Risk · 5w

The differentiator.

**Scope.** LLM provider abstraction, local and hosted · **egress gateway**: policy, classification, redaction, blocking, audit · read-only tool registry · bounded agent loop with structured output · evidence capture with grounding enforcement · cheap triage, strong investigation · cache with context fingerprinting · token and cost budgets · deterministic risk scoring, bands, overrides, history · replayable investigation records · UI: finding detail, evidence chain, risk breakdown · **the ground-truth corpus and eval harness**.

### ✅ Checkpoint

1. Every fixture finding has a verdict, confidence, and evidence; **no conclusion exists without an evidence row** — asserted by query, not by eye.
2. A signal claimed at confidence > 0.5 with no evidence is rejected and downgraded, demonstrated deliberately.
3. The corpus runs end-to-end reporting precision, recall, and appropriate-`uncertain` rate. The baseline becomes the regression gate.
4. **Cost is known:** total tokens, dollars, and cache hit rate for a full fixture run.
5. Five identical hosts trigger **one** investigation and five findings.
6. With the model disabled, correlation continues and findings render *not yet investigated* — never confirmed, not counted as confirmed.
7. **Egress test:** a payload containing a planted secret is **blocked, not redacted**, and raises an incident. The log shows exactly what categories were sent.
8. `local_only` refuses every hosted call.
9. The UI risk breakdown reproduces the stored arithmetic exactly.
10. **Injection test:** a hostile README changes no verdict and reaches no privileged path.

**Decision point.** *Is investigation better than raw correlation, and at what cost per environment per month?* If the FP rate is not materially better than M2's baseline, the AI layer is not earning its place — rework before M4.

**Status, 28 November 2026.** About complete: the bounded loop, six read-only tools, grounded verdicts, the gateway with policy, budget and egress logging, deterministic risk scoring and the eval harness. Landed: a compromise assessment on every malware match (f7cbef1, 4520651, 804c5f7), a behavioural read-only test for every registry tool (8b66132), and the deterministic evals in CI (aaaa7aa).

---

# M4 — Remediation Preparation · 4w

From knowing to doing.

**Scope.** Research: fixed version, upgrade path, breaking changes, cited sources · class dispatch (dependency, transitive, OS package, base image, secret, config, exposure, no-fix) · sandboxed patch workspace: resolve, build, test, rescan · diff and lock delta · validation reporting including **what could not be validated** · blast-radius computation · UI: remediation panel, diff viewer, validation.

### ✅ Checkpoint

1. A confirmed dependency finding yields a patch: diff, lock delta, build, tests, rescan.
2. The rescan **confirms the vulnerability is gone** in the patched workspace.
3. Breaking changes cite release notes with retrieval timestamps.
4. A finding whose affected path has **no test coverage** reports reduced validation confidence prominently.
5. A transitive-only vulnerability with no parent upgrade is reported as such, not silently skipped.
6. An exposed secret produces a **rotation workflow**, not a code deletion.
7. **Sandbox test:** no network after resolution, no mounted secrets, enforced limits — verified by attempting egress from inside.
8. Patch success ≥ 70% across a fixture set of ≥ 20 upgrades, measured and recorded.
9. Nothing has been written to any repository. The output is a diff.

**Risk.** Build environments vary enormously. Report "patch failed" and "we could not build this project" as different outcomes.

**Decision point.** *Is reviewing a prepared patch faster than doing it by hand?* If not, the loop stops here and the value proposition narrows to investigation.

**Status, 28 November 2026.** Only a class plan exists (`plan_for` in `core/athena/remediation/classify.py`). The patch workspace, validation and blast radius are not started; they are Phase 1 of the security agent plan.

---

# M5 — Approval, Execution, Verification · 4w ★ MVP

**Scope.** Approval lifecycle: request, blast radius, conditions, expiry, revocation · signed grants bound to an action hash · step-up auth, typed confirmation on production · executor: grant validation, snapshot, canary, staged rollout, concurrency limits · maintenance windows and freezes · rollback triggers and automatic rollback · verification as an independent evidenced job · regression detection · UI: approvals queue and detail, change history.

### ✅ Checkpoint — the MVP demonstration

Run against the fixture estate, watched by a person:

```text
advisory ingested → affected dependency and repository identified →
applicability investigated with evidence → official fix found and cited →
upgrade prepared, built, tested, rescanned clean → approval shows blast radius,
window, rollback → human approves with step-up → applied to canary first →
verification independently proves the fix → RESOLVED → audit chain intact
```

Plus the assertions that matter more than the happy path:

1. **A deliberately broken patch rolls back cleanly**, the finding returns to an active state, and nothing reports resolved.
2. **A failed verification does not produce `RESOLVED`.**
3. An expired approval can no longer be executed.
4. Regenerating the patch **voids** the prior approval.
5. A change outside its maintenance window **queues** rather than executing.
6. A freeze blocks execution while investigation continues.
7. The executor rejects a grant with an invalid signature.
8. Killing the executor mid-change leaves a discoverable `attempting` record; startup reconciliation flags it for a human rather than retrying.

**Risk.** Rollback is harder than it looks, especially for service restarts and configuration. Where reversibility cannot be guaranteed, say so in the approval rather than pretending.

**Decision point.** *Would we run this against our own production?* If no, name the specific reason and fix that before M6.

**Status, 28 November 2026.** Absent. Groundwork landed: the executor action registry, plan-hash runner and grant checks (1684834), its audit writer (8cbdb05), and step-up on sensitive mutations (9c6e747, a3ba2f9). Open: the signer (plan 0.4), grant claiming, approvals, verification, and the `resolved` state, which is never set.

---

# M6 — Operability and Trust · 5w

What turns a demo into something usable on a real estate.

**Scope.** **Baselines** (new-since-baseline vs pre-existing) · suppression with reasons, scopes, expiry, and invalidation on premise change · VEX import/export and `.athena/policy.yml` · notification grouping, throttling, digests, quiet hours; Telegram and Slack · coverage reporting and SLA tracking · **confidence calibration reporting** · metrics dashboard · Athena Chat with citations · RBAC and separation of duties · narrow auto-approval policy · Athena self-scanning.

### ✅ Checkpoint

1. Connecting to an estate with hundreds of pre-existing findings captures a baseline; the default view shows new findings only and the wall of red does not appear.
2. A suppression with an expiry resurfaces on schedule.
3. A suppression is **invalidated** when its premise changes — an isolated service becomes exposed and the finding returns with an explanation.
4. One CVE across 14 hosts sends **one** notification.
5. The throttle holds under a 200-finding burst; overflow lands in the digest.
6. The metrics dashboard renders every PRD §51 metric with target, denominator, and honest "not enough data" states.
7. Calibration shows human agreement per confidence band.
8. Separation of duties blocks a requester approving their own change — enforced in the database as well as the UI.
9. An auto-approval rule fires only in its declared scope, is fully audited, and is instantly revocable.
10. Athena reports findings **against itself**.

**Decision point.** *Would a real user keep this running after week one?* This is the churn milestone; if notifications are noisy or the first patrol is overwhelming, nothing later matters.

**Status, 28 November 2026.** Slices built: suppression, baselines, in-app notifications, metrics, and CycloneDX 1.6 and OpenVEX exports. Landed: a role on every route (9c6e747, 5ed85db) and admin user management (e0ace1f, cf23d01). Open: separation of duties, which needs M5's approvals; the other checkpoint items have not been assessed against this code.

---

# M7 — Breadth · 8w

Extend surface coverage now the loop is trustworthy — and not before.

**Scope.** Network patrol: authorised discovery, port scanning, service identification, TLS inspection, baselines and change detection, safe-scan profiles, no-scan ranges · container depth: registry scanning, base-image bumps, layer attribution, runtime privilege analysis · secrets in git history, SAST, IaC · macOS node, agentless SSH inventory · Go, Rust, Java, .NET · GitLab, Jira, Linear, PagerDuty, CI gate · CycloneDX, SPDX, VEX, PDF exports · Helm chart, OIDC SSO.

### ✅ Checkpoint

1. Network scans run only against authorised ranges; an unlisted target is refused and the refusal audited.
2. A new listening port raises an exposure finding with a before/after diff.
3. A fragile no-scan range is never probed actively — asserted by **packet capture**, not configuration review.
4. A vulnerable base image produces a **rebuild** recommendation, distinct from a dependency bump.
5. A privileged container **raises** the risk of a vulnerability inside it, visibly in the breakdown.
6. A secret in git history is detected and produces a rotation workflow.
7. A macOS node reports inventory; an agentless host reports inventory labelled lower-fidelity.
8. A CI gate fails a PR introducing a new critical dependency vulnerability.
9. Corpus accuracy has **not regressed** with the new ecosystems.

**Decision point.** *Which of these earned its place?* Network patrol is a large surface with uncertain differentiation (PRD §52, Q5). Be willing to cut it.

**Status, 28 November 2026.** A slice is built: Gitleaks and Trivy scans of the repository working tree. Landed: flagging `.pth` files whose import lines run at every Python start-up (993a130, 5a774dd). The security agent plan adds more identify breadth (its Phase 2) in parallel with closing the trust loop; see [decision 0001](decisions/0001-prd-scope-amendment.md) for the proposed scope change.

---

# M8 — Scale and Hardening · 8w

**Scope.** Performance to Phase 2 targets: materialised views, index tuning, partitioning of `evidence` and `audit_event` · queue backpressure and fairness · sandbox launcher privilege reduction · HA for api and worker · backup/restore and DR rehearsal · signed tier-staged node auto-update · external security review and penetration test · air-gapped intelligence bundles · Kubernetes patrol, if M7's decision point supports it.

### ✅ Checkpoint

1. Synthetic inventory at Phase 2 scale meets every latency budget.
2. A 10,000-advisory backfill does **not** delay investigation of a new critical finding.
3. Restore into a clean environment succeeds from backup plus escrowed key, rehearsed end to end.
4. The Docker socket is no longer mounted into `worker`, or the residual risk is formally accepted and documented.
5. An external penetration test finds no critical or high issue in the executor, approval, or egress boundaries.
6. The expanded prompt-injection corpus passes.
7. Node auto-update rolls out to development tier and is **blocked pending approval** on production.
8. An air-gapped install runs a full patrol from an imported bundle with no internet access.

**Status, 28 November 2026.** Not started.

---

# Cross-cutting gates

Apply at **every** milestone. A red gate means incomplete.

| Gate | Rule |
|---|---|
| Evaluation | Corpus accuracy must not regress. Blocks release, from M3. |
| Security boundary | Import- and privilege-boundary tests pass. From M0. |
| Injection | The injection corpus passes and grows each milestone. From M3. |
| Honesty | No path renders `not_observed` as clean. Tested per milestone. |
| Audit | Every consequential action writes an audit event; the chain verifies. From M0. |
| Cost | Model spend per fixture run is measured and reported. From M3. |
| Documentation | Deployment and upgrade instructions tested on a clean machine. |
| Rollback | Any new mutating capability ships with a rollback path, or a documented statement that it has none. |

---

# Deliberately not in this plan

```text
Cloud asset inventory · attack-path analysis · fleet-wide remediation   PRD Phase 3
Windows nodes                          after macOS proves the abstraction
Multi-tenancy                          not planned
Managed hosted offering                a business decision, not an engineering one
```

Each is a reasonable future. None makes the loop better, and the loop is the product.

---

# Tracking

One milestone = one GitHub milestone; one checkpoint assertion = one issue labelled `checkpoint`. A milestone closes only when every checkpoint issue is closed **and** the demonstration has been performed and recorded — "we demonstrated it once" degrades into "we believe it works" within a month. Slippage is reported by moving scope out of a milestone, never by moving its checkpoints.
