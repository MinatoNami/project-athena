# Athena — Technical Design Document

**Status:** Draft · **Version:** 0.2 · **Date:** 19 August 2026
**Source:** [PRD](../Athena%20—%20Product%20Requirements%20Document.md) v0.2

> The PRD owns *what* and *why*. This document owns *how*, and does not restate the PRD.
> Scope is the MVP (PRD §47). Kubernetes, cloud, macOS/Windows nodes, HA, and multi-tenancy
> are out of scope here; the architecture must not preclude them, but must not pay for them now.

---

## Contents

[1. Principles](#1-principles) · [2. Topology](#2-topology) · [3. Components](#3-components) · [4. Process Model](#4-process-model) · [5. Data](#5-data) · [6. Correlation](#6-correlation) · [7. Investigation](#7-investigation) · [8. Risk Scoring](#8-risk-scoring) · [9. Remediation](#9-remediation) · [10. Approval and Execution](#10-approval-and-execution) · [11. Node Agent](#11-node-agent) · [12. Scanner Sandbox](#12-scanner-sandbox) · [13. Intelligence](#13-intelligence) · [14. Security](#14-security) · [15. API](#15-api) · [16. Realtime](#16-realtime) · [17. Observability](#17-observability) · [18. Deployment](#18-deployment) · [19. Performance](#19-performance) · [20. Test Harness](#20-test-harness) · [21. Decisions](#21-decisions) · [22. Repository Layout](#22-repository-layout) · [23. Open Questions](#23-open-questions)

---

# 1. Principles

**Facts, conclusions, and actions are separate tables.** Evidence is immutable and timestamped; a conclusion references evidence; an action references a conclusion. A conclusion with no evidence rows is a bug.

**The model never holds authority.** The LLM proposes structured claims; code makes decisions. The investigation tool registry contains no mutating tool, enforced by the executor being a separate process with a separate database role — not by a code convention.

**Deterministic where possible.** Version comparison, range evaluation, risk scoring, state transitions, and policy are pure functions with unit tests. The AI layer supplies their inputs and prose for humans, nothing else.

**Absence of data is never absence of risk.** Every read path distinguishes `observed_clean`, `observed_vulnerable`, and `not_observed`. Aggregates carry a coverage denominator.

**Everything is idempotent and resumable.** Jobs are keyed and retried. An executed change is written before it is attempted, so a crash mid-change is discoverable.

---

# 2. Topology

```text
browser ──HTTPS──► Nuxt 4 / Nitro ──private──► ATHENA CORE ──► PostgreSQL
                   (only exposed             api · worker · scheduler
                    component)               executor (isolated)
                                                   │
                        ┌──────────────────────────┼──────────────────────┐
                        ▼                          ▼                      ▼
                 scanner sandbox           egress gateway          node channel
                 ephemeral, no net         policy + audit          mTLS, node-initiated
                                                 │                        │
                                          feeds / models          Athena Nodes (Go)
```

Two properties carry the design:

1. **Nodes dial out.** Core never initiates a connection to a protected host; no inbound listener is opened on anything Athena protects.
2. **One internet-facing surface.** Nuxt is the only exposed component; FastAPI binds to the private network.

---

# 3. Components

| Component | Process | Language | Responsibility |
|---|---|---|---|
| `api` | long-running | Python / FastAPI | REST + SSE, authn/authz, read models |
| `scheduler` | singleton, leader-elected | Python | Patrol cadence, feed polling, expiry sweeps |
| `worker` | N replicas | Python | Scans, correlation, investigation, patch prep, verification |
| `executor` | isolated singleton | Python | The only component that may mutate protected systems |
| `node` | per host | Go | Collection and constrained execution |
| `web` | long-running | Nuxt 4 | Dashboard and BFF |
| `db` | — | PostgreSQL 16 | State, queue, pub/sub, audit chain |

The PRD's eleven logical services are **modules in one deployable**, with boundaries enforced by import linting:

```text
inventory · intel · correlation · investigation · risk · remediation
policy · approval · execution · verification · findings
```

The exception is `executor`, separated on day one because that separation is a security control rather than a scaling decision.

---

# 4. Process Model

### Queue

Postgres-backed, `SELECT … FOR UPDATE SKIP LOCKED`.

```sql
CREATE TABLE job (
    id bigserial PRIMARY KEY,
    kind text NOT NULL,
    key  text NOT NULL,                    -- idempotency
    payload jsonb NOT NULL,
    priority smallint NOT NULL DEFAULT 5,
    run_after timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz, finished_at timestamptz,
    attempts int NOT NULL DEFAULT 0, max_attempts int NOT NULL DEFAULT 5,
    last_error text,
    lease_until timestamptz,               -- a dead worker releases its job
    UNIQUE (kind, key)
);
CREATE INDEX ON job (priority, run_after) WHERE finished_at IS NULL;
```

### Job kinds

```text
intel.poll.<source>      correlate.advisory     investigate.finding    execute.change
intel.advisory.ingest    correlate.asset        risk.score             verify.change
scan.repository          scan.image             remediate.research     verify.regression
scan.host                scan.network           remediate.prepare      suppression.expire
                                                                       notify.dispatch
```

Per-kind concurrency caps prevent a 10,000-advisory backfill from starving investigation of a critical finding. Investigation additionally consumes a token budget (§7); on exhaustion, jobs park in `awaiting_budget` rather than failing.

---

# 5. Data

### Core tables

```sql
CREATE TYPE asset_kind AS ENUM ('host','repository','image','container','service','network_host');
CREATE TYPE tier       AS ENUM ('production','staging','development','personal','unknown');
CREATE TYPE exposure   AS ENUM ('internet','internal','isolated','unknown');

CREATE TABLE asset (
    id uuid PRIMARY KEY,
    kind asset_kind NOT NULL,
    identity_key text NOT NULL,              -- see below
    display_name text NOT NULL,
    tier tier NOT NULL DEFAULT 'unknown',
    exposure exposure NOT NULL DEFAULT 'unknown',
    criticality smallint,                    -- 1..5; NULL = unset, never 0
    owner text, data_class text[],
    first_seen timestamptz NOT NULL, last_seen timestamptz NOT NULL,
    last_inventoried_at timestamptz,         -- drives freshness UI
    tombstoned_at timestamptz,
    UNIQUE (kind, identity_key)
);

CREATE TABLE asset_edge (
    src_id uuid REFERENCES asset(id), dst_id uuid REFERENCES asset(id),
    relation text NOT NULL,                  -- runs_on|built_from|contains|depends_on|exposes
    observed_at timestamptz NOT NULL, confidence real NOT NULL,
    PRIMARY KEY (src_id, dst_id, relation)
);

CREATE TABLE component (
    id uuid PRIMARY KEY, purl text, cpe text,
    ecosystem text NOT NULL, name text NOT NULL, version text NOT NULL,
    UNIQUE (ecosystem, name, version)
);

CREATE TABLE asset_component (
    asset_id uuid, component_id uuid,
    scope text NOT NULL,                     -- direct|transitive|os|runtime
    install_path text, is_running boolean,
    observed_at timestamptz NOT NULL, scan_run_id uuid NOT NULL,
    PRIMARY KEY (asset_id, component_id, scope)
);

CREATE TABLE vulnerability (
    id text PRIMARY KEY, aliases text[] NOT NULL DEFAULT '{}',
    summary text, cwe text[],
    cvss_vector text, cvss_score real,
    epss_score real, epss_updated_at timestamptz,
    kev boolean NOT NULL DEFAULT false, kev_ransomware boolean NOT NULL DEFAULT false,
    exploit_public boolean NOT NULL DEFAULT false,
    published_at timestamptz,
    revision int NOT NULL DEFAULT 1, revised_at timestamptz,
    content_hash text NOT NULL               -- detects material change
);

CREATE TABLE affected_range (
    id bigserial PRIMARY KEY, vulnerability_id text REFERENCES vulnerability(id),
    ecosystem text NOT NULL, package text NOT NULL,
    introduced text, fixed text, last_affected text,
    source text NOT NULL, authority smallint NOT NULL   -- §6.3
);

CREATE TYPE finding_state AS ENUM (
  'discovered','investigating','confirmed','remediation_found','patch_prepared',
  'awaiting_approval','remediating','verifying','resolved',
  'false_positive','mitigated','accepted_risk','deferred','no_fix_available','regressed');

CREATE TABLE finding (
    id uuid PRIMARY KEY, group_id uuid NOT NULL,
    vulnerability_id text, asset_id uuid, component_id uuid,
    state finding_state NOT NULL,
    match_method text NOT NULL, match_confidence real NOT NULL,
    risk_score smallint, risk_band text, confidence real,
    advisory_revision int NOT NULL,
    first_seen timestamptz NOT NULL, state_changed_at timestamptz NOT NULL,
    due_at timestamptz,
    UNIQUE (vulnerability_id, asset_id, component_id)
);

CREATE TABLE evidence (
    id uuid PRIMARY KEY, finding_id uuid REFERENCES finding(id),
    kind text NOT NULL,                      -- tool_output|http_source|node_observation|model_claim
    claim text NOT NULL, value jsonb NOT NULL,
    source_ref text, content_hash text NOT NULL,
    observed_at timestamptz NOT NULL
);
```

### Identity keys

| Kind | `identity_key` |
|---|---|
| host | `machine-id:<id>` → `hw-uuid:<uuid>` → `node-key:<fingerprint>` |
| repository | normalised remote URL, lowercased, `.git` stripped |
| image | `sha256:<digest>` — never a tag |
| container | `<host identity>/<container-id>` |
| service | `<host identity>/<proto>/<port>` |
| network_host | `mac:<addr>` → `fingerprint:<hash>` — always low confidence |

Ambiguous matches create a `merge_candidate` for human confirmation. Athena never merges silently: a wrong merge corrupts history irreversibly, a wrong split is merely untidy.

### Audit chain

```sql
CREATE TABLE audit_event (
    seq bigserial PRIMARY KEY, at timestamptz NOT NULL DEFAULT now(),
    actor text NOT NULL,       -- user:<id>|system|node:<id>|model:<name>
    action text NOT NULL, subject text NOT NULL, detail jsonb NOT NULL,
    prev_hash bytea NOT NULL, hash bytea NOT NULL   -- sha256(prev_hash || canonical(row))
);
```

Append-only via a `BEFORE UPDATE OR DELETE` trigger that raises. A periodic job signs the head hash so tail truncation is detectable.

### Freshness

Every observation carries `observed_at`, `observed_by` (tool + version), and `scan_run_id`. `scan_run` records what was attempted, what succeeded, and **what was skipped or failed** — a partial scan must never be indistinguishable from a complete one.

---

# 6. Correlation

The highest-correctness-risk component: every downstream conclusion inherits its errors.

### 6.1 Pipeline

```text
advisory or asset change
   → candidate generation      index lookup, high recall, deliberately over-inclusive
   → version range evaluation  ecosystem-specific comparator
   → authority resolution      distro advisory beats upstream range (§6.3)
   → match confidence          method + source quality → 0..1
   → candidate finding         state = DISCOVERED, never CONFIRMED
```

Correlation produces candidates only. Confirmation is §7's job.

### 6.2 Comparators

String comparison of versions is the most common source of silent error in this class of tool. Each ecosystem gets a real comparator with the upstream project's own test vectors: **PyPI** (PEP 440 epochs, pre/post/dev), **npm** (SemVer ranges), **Debian/Ubuntu** (`dpkg` epoch/tilde ordering), **RPM** (`rpmvercmp`), **Alpine**, **Maven**, **Go** (pseudo-versions, `+incompatible`). Lexical fallback is permitted only with a low-confidence flag. A comparator bug is a correctness incident, not a bug ticket.

### 6.3 Match confidence and source authority

```text
purl_exact_range       0.95      authority  4  distro tracker for that distro + release
distro_advisory        0.95                 3  upstream advisory (GHSA/OSV)
cpe_range              0.70                 2  NVD CPE range
binary_fingerprint     0.60                 1  vendor bulletin, no machine-readable ranges
name_version_heuristic 0.40                 0  heuristic
generic_fallback       0.25
```

**Backport rule:** for `deb`/`rpm`/`apk` components, a range from authority < 4 may create at most an `informational` candidate. Ubuntu's `openssl 3.0.2-0ubuntu1.15` may carry the fix for a CVE whose upstream fixed version is `3.0.13`; naive upstream matching produces a false positive on every Ubuntu host in the estate. Source conflicts are recorded on the finding and surfaced, never resolved silently.

### 6.4 Reverse correlation and revisions

New advisories query the component index rather than rescanning assets (`component(ecosystem, name)` and `asset_component(component_id)` indexes; target < 5 minutes). When an advisory's `content_hash` changes, every finding on an older `advisory_revision` is re-correlated and re-scored — **including findings already closed** — and suppressions whose premise is invalidated are flagged for review.

---

# 7. Investigation

### 7.1 Shape

```text
candidate finding
  → context assembly     asset facts, component facts, advisory, prior evidence
  → triage (cheap model) obviously not applicable → close with reason; critical → raise budget
  → agent loop           read-only tools, bounded calls and wall-clock
  → structured verdict   signals + confidence + evidence refs
  → persist evidence     then deterministic scoring (§8)
```

### 7.2 Tool registry

Tools are questions, not commands. Hard allowlist, no mutating tool present:

```text
inventory.get_asset · list_components · get_graph
host.is_process_running · read_config(allowlisted, redacted) · list_listening_ports
network.check_reachability
code.search · get_dependency_path
intel.get_advisory · get_kev · get_epss
web.fetch_source(allowlisted domains, returned as data)
findings.get_prior_verdict
```

### 7.3 Verdict schema

The model returns a schema-validated object, never prose that is parsed:

```json
{
  "signals": {
    "component_present":  {"value": true, "confidence": 1.0, "evidence": ["ev_01"]},
    "service_running":    {"value": true, "confidence": 1.0, "evidence": ["ev_03"]},
    "network_reachable":  {"value": true, "confidence": 0.9, "evidence": ["ev_04"]},
    "vulnerable_feature_enabled": {"value": "unknown", "confidence": 0.4, "evidence": []},
    "reachable_in_code":  {"value": "unknown", "confidence": 0.3, "evidence": []}
  },
  "verdict": "applicable",
  "verdict_confidence": 0.86,
  "rationale": "…",
  "uncertainties": ["Could not determine whether the TLS renegotiation path is enabled."]
}
```

Enforced in code, not prompt:
- A signal with `confidence > 0.5` and empty `evidence` is rejected, retried once, then downgraded to `unknown`.
- `verdict ∈ {applicable, not_applicable, uncertain}` — `uncertain` is valid and unpenalised.
- The model may not emit a risk band, a severity, or a resolution.

### 7.4 Cache

```text
key = sha256(vulnerability_id ‖ advisory_revision ‖ component_purl ‖ context_fingerprint)

context_fingerprint = os + release, running state, exposure class, tier,
                      relevant config toggles, container privilege
```

Fourteen identical hosts produce **one** investigation and fourteen findings, each with its own per-instance score. Invalidated by advisory revision or a change in any fingerprinted fact.

### 7.5 Budgets, reproducibility, degradation

Ceilings per investigation (tool calls, tokens, wall-clock), scaled by severity, under global daily/monthly caps. On exhaustion: queue and alert — never silent degradation.

Every run persists model identity, prompt template hash, ordered tool calls and outputs, token count, cost, and verdict, so it can be replayed. A conclusion that cannot be reconstructed is not shown as evidence.

When the model is unavailable, correlation continues and findings stay `DISCOVERED`, labelled *not yet investigated*, and are **not** counted as confirmed in posture totals.

---

# 8. Risk Scoring

Deterministic, pure, unit-tested. The model supplies signal values; this function supplies the number.

```python
def score(f: Finding) -> tuple[int, Band]:
    base       = cvss_normalised(f.cvss_score)
    exploit    = max(1.0 if f.kev else 0.0, f.epss or 0.0, 0.7 if f.exploit_public else 0.0)
    exposure   = EXPOSURE_W[f.effective_exposure]      # internet 1.0 … isolated 0.2
    running    = 1.0 if f.service_running else 0.25
    importance = TIER_W[f.tier] * CRIT_W[f.criticality]
    reach      = REACH_W[f.reachable_in_code]          # confirmed 1.0 … no 0.05
    conf       = f.match_confidence * f.verdict_confidence

    raw = base * (0.30 + 0.70 * exploit) * exposure * running * importance * reach
    return round(100 * raw), band(raw, conf)
```

```text
CRITICAL ≥ 0.70   HIGH ≥ 0.45   MEDIUM ≥ 0.20   LOW ≥ 0.05   else INFORMATIONAL
```

Overrides, applied after the arithmetic and always recorded:

```text
KEV + internet-exposed + running   → never below HIGH
verdict = not_applicable           → INFORMATIONAL regardless of score
confidence < 0.4                   → cap at MEDIUM until investigated
tier = production + exploit ≥ 0.9  → escalate one band
no_fix_available                   → band unchanged, SLA clock paused
```

The API returns the factor breakdown with every score so "why is this critical?" is answerable without reading code. Rescoring is triggered by advisory revision, EPSS refresh, KEV addition, tier or exposure change, verification result, or suppression expiry, and writes a `risk_history` row.

---

# 9. Remediation

Research resolves current → fixed version → upgrade path, preferring sources in PRD §21 order, with every claim citing a source URL and retrieval timestamp. Dispatch is by class — these are genuinely different pipelines:

| Class | Pipeline |
|---|---|
| dependency (direct) | manifest edit → lock resolve → build → test → rescan |
| dependency (transitive) | parent upgrade, or ecosystem override/pin; flag if neither is possible |
| OS package | node-side upgrade plan + restart plan + snapshot |
| base image | `FROM` bump → rebuild → test → rescan → digest diff |
| exposed secret | **rotation and revocation**, plus history advisory — never a code deletion |
| configuration | config diff + reload plan |
| exposure | firewall / bind-address change plan |
| no fix | compensating control proposal + residual risk statement |

### Patch workspace

```text
ephemeral container
├── network:    egress to the package registry only, only during resolve
├── filesystem: shallow clone, read-only source, writable overlay
├── secrets:    none mounted, ever
├── identity:   unprivileged uid, no docker socket, seccomp, no-new-privileges
└── limits:     cpu, memory, pids, wall-clock
```

Output is a **diff**, not a commit: unified diff, lock delta, build log, test report, rescan result, cited breaking changes, blast radius, and an explicit statement of what could not be validated (missing test coverage on the affected path is itself worth surfacing).

---

# 10. Approval and Execution

### Grant

An approval binds to a specific prepared change by content hash. Regenerating the patch voids it.

```json
{
  "grant_id": "…", "approval_id": "…",
  "action": "apply_patch", "action_hash": "sha256:…",
  "asset_ids": ["…"],
  "conditions": {"window": "maintenance", "canary_first": true, "max_concurrency": 1},
  "issued_at": "…", "expires_at": "…",
  "signature": "ed25519(core_signing_key, canonical(grant))"
}
```

### Executor isolation

Separate process, **separate database role** (write access only to `change_record`, `snapshot`, and its own job table), no LLM client library in the image, and no ability to mint grants — it validates a signature it cannot produce. This is the structural guarantee behind PRD §31: a manipulated reasoning layer has no path to a valid grant.

### Sequence

```text
validate grant (signature, expiry, conditions, window, freeze)
  → write change_record (attempting)          ← before the change
  → capture snapshot (versions, configs, image digests, service state, firewall)
  → apply to canary → health checks + soak
       pass → batch rollout, bounded concurrency
       fail → rollback from snapshot → alert → finding returns to REMEDIATION_FOUND
```

An interrupted execution is discoverable: `change_record` sits in `attempting` with no terminal status, and startup reconciliation surfaces it for a human rather than retrying blindly.

### Verification

A distinct job with its own evidence, never a claim by the executor: installed version, running process version, container digest, dependency lock, service config, network exposure, application tests, scanner rescan. Only a successful evidenced verification reaches `RESOLVED`; failure returns the finding to an active state and marks the change a rollback candidate.

`verify.regression` re-proves `RESOLVED` findings weekly. A fix reverted by a redeploy or container restart becomes `REGRESSED` — it does not reopen as a new finding, because the history matters.

---

# 11. Node Agent

**Go**, for a single static binary with no runtime dependency on the protected host. Shipping a Python runtime and dependency tree onto every protected host would add attack surface to the machines Athena exists to protect.

### Transport and task envelope

Node-initiated, outbound-only, mutual TLS, WebSocket with long-poll fallback; heartbeat every 30s.

```json
{"task_id":"…","capability":"list_packages","args":{},
 "issued_at":"…","expires_at":"…","nonce":"…","grant":null,
 "signature":"ed25519(core_key, canonical(envelope))"}
```

The node verifies, in order: signature against the pinned core key, expiry, nonce unseen, capability granted. Privileged capabilities additionally require a valid grant (§10). Any failed check rejects and reports.

### Capabilities

```text
observe (always)     get_system_info · list_packages · list_processes ·
                     list_services · list_ports · inspect_docker
inspect (per node)   read_file (allowlisted, redacted) · inspect_service · run_security_scan
mutate (grant req.)  apply_approved_patch · upgrade_packages · restart_service ·
                     apply_config · rollback
```

**There is no `run_shell` capability.** Every capability is a named, argument-validated operation. This is the difference between a node agent and a backdoor.

### Lifecycle

```text
enrolment  single-use token (15 min) → keypair generated on the host, private key never leaves
offline    bounded local spool with gap markers; core marks inventory stale and reports it
limits     CPU quota, memory ceiling, scan concurrency 1 — must not degrade the host it protects
updates    signed, tier-staged, never automatic on production
removal    revokes the certificate, tombstones the asset, retains history
```

---

# 12. Scanner Sandbox

Scanners parse hostile input — crafted archives, adversarial container layers — so they run in ephemeral containers, never in the worker process.

```text
image: pinned digest · network: none (registry allowlist during pull only)
mounts: input read-only, one writable tmpfs · user: unprivileged, no-new-privileges,
seccomp, dropped caps · limits: cpu, memory, pids, wall-clock, output size
result: schema-validated JSON on stdout
```

Adapters: **Syft** (SBOM), **Trivy** (image/fs/OS/IaC), **OSV-Scanner** (ecosystem matching), **Gitleaks** (secrets, incl. history), **Semgrep** (SAST), **Nmap** (Phase 2). Each is a thin versioned translator to the evidence model, with tool name and version on every evidence row.

A scanner crash or timeout writes a partial `scan_run` with the failure recorded. **It never marks the target clean.**

---

# 13. Intelligence

Sources and cadence are in PRD §16. This layer adds:

**Normalisation.** Each adapter preserves `source` and `authority`. Multiple sources for one vulnerability merge into one `vulnerability` row with many `affected_range` rows — never collapsed, because the disagreements are informative. `content_hash` covers only verdict-relevant fields (ranges, CVSS, KEV, fix versions); a change bumps `revision` and triggers re-correlation.

**Politeness and resilience.** Published rate limits respected, conditional and delta requests, exponential backoff with jitter, persistent local cache so a restart does not re-download the corpus. On sustained failure: serve cached data, mark stale, alert past a threshold — never fail the patrol.

**Offline.** A signed importable bundle (`athena-intel-YYYYMMDD.tar.zst`); the importer verifies the signature and records the bundle date so intelligence age is displayed honestly.

---

# 14. Security

### Trust zones

```text
0  operator browser      untrusted input to the UI
1  Nuxt BFF              internet-facing; sessions, no domain authority
2  core api / workers    knows everything, can mutate nothing external
3  executor              can mutate everything, reasons about nothing
4  nodes                 constrained capabilities on protected hosts
X  scanner sandbox       hostile input; no network, no credentials
Y  retrieved content     ALWAYS data, never instruction
```

Authority decreases as capability increases.

### Controls

- **Sessions:** `HttpOnly`/`Secure`/`SameSite=Lax`, server-side and individually revocable; Argon2id; TOTP MFA; **step-up re-auth for every approval**. No default credentials — first run prints a single-use bootstrap token.
- **RBAC:** viewer / operator / approver / admin / auditor, optionally scoped per asset group. Separation of duties enforced by a database check constraint as well as in code.
- **Secrets:** envelope encryption; master key from env, file, or KMS — never the database. Integration credentials default to read-only; write scope is per-repository and only when patch PRs are enabled. A redaction filter runs on all log and evidence writes.

### Egress gateway

Every outbound call to a model or feed passes through one component:

```text
call → PolicyGate → Classifier → Redactor → ProviderAdapter → EgressLog
```

The classifier labels payload segments (`package_metadata`, `advisory_text`, `source_code`, `config_values`, `hostnames`, `secrets`); anything above the permitted class is redacted, and a payload containing a **detected secret is blocked, not redacted**, raising an incident. `EgressLog` records provider, data classes, payload hash, tokens, and cost — so "what has left my network?" is answerable exactly. `local_only` mode refuses every hosted call.

### Prompt injection

Enforcement is structural, not textual: retrieved content travels in a dedicated data channel, never the instruction region; the investigation tool registry has nothing mutating to call; grants are signed by a key the reasoning layer cannot access; outputs are schema-validated so free text cannot become an action. A red-team corpus runs in CI asserting no privileged path is reachable.

Athena registers itself as an asset and patrols itself. Releases are signed and ship an SBOM.

---

# 15. API

REST over HTTPS, `/api/v1`, OpenAPI 3.1 generated by FastAPI, cursor pagination, RFC 9457 errors.

```text
/auth          login · logout · me · step-up
/assets        list · get · patch(tier,owner,criticality,exposure) · graph · components · freshness
/findings      list(filters) · get · evidence · investigation · risk · suppress · reopen
/finding-groups/{id}
/patches       get · diff · validation
/approvals     list · get · blast-radius · approve(step-up) · reject · revoke
/changes       list · get · rollback
/vulnerabilities/{id}          /intel/sources   (feed health + age)
/patrols       list · run       /coverage        (stale + never-scanned)
/metrics       summary · timeseries · ai-spend
/nodes         list · enrol-token · delete
/policy · /settings/ai · /audit · /audit/verify · /chat
```

Contract rules:
- Every response containing a fact includes `observed_at` and `observed_by`.
- Every aggregate includes a denominator: `{"critical":1,"of_assets_observed":38,"of_assets_total":41}`.
- Consequential endpoints require `Idempotency-Key`.
- `approve` requires a step-up token issued within 5 minutes.

---

# 16. Realtime

Postgres `LISTEN/NOTIFY` → in-process broker → **SSE**. No Redis, no WebSocket server.

```text
domain event → outbox → NOTIFY → api broker → SSE → Nuxt → store refetch
GET /api/v1/events?topics=findings,approvals,patrols
```

Events carry `{topic, id, version, seq}`, not payloads — the client refetches, so authorisation is re-checked on the normal read path. The outbox sequence gives reconnect-with-cursor, so a 30-second drop catches up rather than silently missing an approval. Traffic is one-directional; commands travel over normal REST.

---

# 17. Observability

Structured JSON logs with a correlation id per request and job, secrets filtered at the writer. OpenTelemetry traces across api → worker → sandbox → node, with the investigation loop as a span tree so a slow or expensive investigation is diagnosable. Prometheus at `/metrics` (operational), distinct from `/api/v1/metrics` (product).

```text
athena_job_queue_depth{kind}           athena_investigation_tokens_total{model}
athena_job_duration_seconds{kind}      athena_investigation_cost_usd_total
athena_intel_source_age_seconds{src}   athena_assets_stale_total
athena_node_last_seen_seconds{node}    athena_egress_blocked_total{reason}
athena_scan_failures_total{tool}
```

Alerts ship with the product: intel stale > 6h, node unseen > 24h, sustained queue depth, budget > 80%, any egress block, any audit-chain failure.

---

# 18. Deployment

Single-node Docker Compose; `docker compose up` to first finding in under 30 minutes.

```yaml
# deploy/compose.yaml (abridged)
services:
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: athena
      POSTGRES_USER: athena
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    secrets: [db_password]
    volumes: [athena-db:/var/lib/postgresql/data]
    networks: [private]                  # never published

  api:       { image: athena-core,     command: athena serve,      networks: [private] }
  worker:    { image: athena-core,     command: athena worker,     networks: [private],
               volumes: ["/var/run/docker.sock:/var/run/docker.sock"] }   # sandbox launcher
  scheduler: { image: athena-core,     command: athena scheduler,  networks: [private] }
  executor:  { image: athena-executor, command: athena executor,   networks: [private] }
               # separate image, no LLM libs, separate DB role

  web:
    image: athena-web
    environment: { NUXT_ATHENA_API_URL: "http://api:8000" }
    ports: ["443:3000"]                  # the only published port
    networks: [private, public]

volumes: { athena-db: {} }
networks: { private: {internal: true}, public: {} }
secrets:  { db_password: {file: ./secrets/db_password} }
```

The `docker.sock` mount on `worker` launches the scanner sandbox. It is a real privilege, documented as such; reducing it is a Phase 2 item (§23).

**Bootstrap:** migrations run automatically → first run prints a single-use admin token to the log → operator creates the account and enables MFA → onboarding wizard (AI mode and data policy → repository → node → network scope) → first patrol, baseline captured.

**Upgrades:** `api`/`worker`/`web` are stateless and roll. Migrations are backward-compatible for one minor version (expand → migrate → contract). `athena doctor` validates schema, keys, connectivity, feed age, and node health.

**Backup:** `athena backup` (pg_dump + wrapped key manifest) and `athena restore`, which verifies key availability *before* restoring. The master key is not in the backup by default; a backup without the key is unrecoverable, and the command warns if the key is not separately escrowed.

---

# 19. Performance

Scale targets are in PRD §44. Latency budgets:

```text
advisory ingested → candidate findings     < 5 min
candidate → investigated (critical)        < 30 min
repository scan (medium repo)              < 5 min
host inventory refresh                     < 2 min
dashboard p95 API response                 < 300 ms
findings list, 25k rows, filtered          < 500 ms
```

Sizing at MVP: 2 vCPU / 4 GB / 20 GB, dominated by advisory data (~2 GB) plus evidence retention.

Known hotspots: advisory backfill fan-out (mitigated by per-kind concurrency caps and priority); investigation cost (mitigated by the cache — expected > 80% hit rate on homogeneous fleets, **measured, not assumed**); findings aggregation (materialised view refreshed on the outbox event, not per request).

---

# 20. Test Harness

Levels are in PRD §46. The mechanics that need specifying:

```text
evals/corpus/<case-id>/
├── case.yaml       vulnerability, environment fixture, expected verdict + rationale
├── fixture/        pinned images, package sets, config, repo state
└── expected.json   verdict, key signals, expected remediation
```

The corpus runs on every model, prompt, comparator, or scanner change, reporting precision/recall on `applicable` and, separately, the rate of appropriate `uncertain`. **Accuracy regression blocks release.**

The fixture estate is a reproducible compose environment: an outdated Ubuntu host, a repository with vulnerable direct and transitive dependencies, a container running a vulnerable service, an exposed port, and a planted secret.

The five tests that matter most:

1. Does Athena correctly **decline** inapplicable findings?
2. Does it **refuse to claim success** when a fix failed?
3. Does a deliberately broken patch **roll back** cleanly?
4. Can any injected instruction reach a mutating capability? (must be no, every time)
5. Does a **distro backport** avoid a false positive?

---

# 21. Decisions

| Decision | Chosen | Rationale |
|---|---|---|
| Core language | Python 3.12 + FastAPI | Security tooling ecosystem; typed via Pydantic |
| Node agent | **Go** | Static binary, no runtime on protected hosts |
| Database | PostgreSQL 16 only | JSONB, LISTEN/NOTIFY, SKIP LOCKED cover queue and pub/sub |
| Queue | Postgres SKIP LOCKED | No second datastore at MVP scale; swappable module |
| Realtime | SSE over LISTEN/NOTIFY | One-directional traffic; no extra server component |
| Frontend | **Nuxt 4 / Vue 3** | SSR + Nitro BFF keeps core off the internet — [WEB_UI.md](WEB_UI.md) |
| Topology | Modular monolith + isolated executor | Executor separation is a security control; the rest is premature |
| Scanners | Ephemeral sandboxed containers | They parse hostile input |
| Risk scoring | Deterministic function | Auditable, reproducible, testable |
| Migrations | Alembic, expand/contract | Safe rolling upgrades |
| Egress | Single gateway with policy + audit | "What left my network?" must be answerable |
| Audit | Hash-chained append-only table | Tamper-evident without new infrastructure |

Superseded decisions get a new ADR, never an edit in place.

---

# 22. Repository Layout

```text
athena/
├── core/athena/
│   ├── api/ domain/ db/ workers/
│   ├── inventory/ intel/ correlation/ investigation/ risk/
│   ├── remediation/ policy/ approval/ execution/ verification/ findings/
│   ├── scanners/    adapters + sandbox launcher
│   └── llm/         provider abstraction + egress gateway
├── executor/        separate image, minimal deps, no LLM libraries
├── node/            cmd/athena-node · internal/{collect,transport,capability,spool}
├── web/             Nuxt 4 — see WEB_UI.md
├── deploy/          compose, helm, systemd, install script
├── evals/           corpus, fixture estate, harness
└── docs/
```

Import linting enforces the boundaries in CI — `executor` may not import `llm`, `investigation` may not import `execution`. A security boundary that depends on discipline is not a boundary.

---

# 23. Open Questions

1. **Sandbox launcher privilege.** The Docker socket mount on `worker` is a real privilege. Alternatives: a narrow sandbox-runner service, rootless Podman, gVisor. Decide before Phase 2.
2. **Reachability analysis.** Call-graph reachability for Python/JS is research-grade. Ship without it and rely on exposure and runtime signals, or restrict it to tractable ecosystems? Materially affects the `reach` factor.
3. **Repository write access.** Direct PR creation versus diff-only in v1. Diff-only is safer and slower to adopt.
4. **Minimum viable local model.** Determines whether `local_only` is a real product or a checkbox. Must be measured against the corpus.
5. **Container→repository provenance** is unreliable without build-time attestation. Consider requiring a build hook.
6. **Evidence retention.** Proposal: raw tool output 90 days, hashes and structured claims indefinitely.
7. **Multi-user in v1.** Recommendation: build the schema now, ship single-admin, enable roles at M6.
8. **Node self-update** requires a node to fetch and execute a binary — the pattern Athena warns about elsewhere. Proposal: signed, operator-approved on production, never automatic.
