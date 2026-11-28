# 0001 — Amend the PRD scope

**Status:** Proposed · **Date:** 28 November 2026
**Related:** [Security Agent Implementation Plan](../SECURITY_AGENT_PLAN.md), decision 6.1 · [PRD](../../Athena%20—%20Product%20Requirements%20Document.md) §50 Non-Goals · [Milestones](../MILESTONES.md)

---

## Context

The [security agent plan](../SECURITY_AGENT_PLAN.md) grows Athena from finding weaknesses into a general security agent that identifies, mitigates and resolves threats. Its Phase 5 adds runtime telemetry, detection, indicator intel, cloud posture and virtual patching. Each of those collides with the PRD as written.

PRD §50 says Athena is not intended to:

- act as an EDR, IDS or antivirus, because it finds weaknesses and does not detect active intrusion;
- act as a SIEM or log analysis platform;
- act as a WAF or any inline runtime control.

The same section keeps the limits this decision does not touch. Athena must not execute every suggested remediation automatically, must not give a model unrestricted root access, and must not treat every CVE match as confirmed. It stays a defensive system for environments the operator owns or is authorised to assess.

Two more constraints apply:

- `docs/MILESTONES.md` defers cloud asset inventory to PRD Phase 3.
- M7 extends breadth only once the trust loop is proven, and not before.

The research behind the plan shows why the line matters now. The npm campaigns and the `agent-framework` stealer ran at install or start-up, so a package-only view cannot tell whether a compromise happened. Answering that needs evidence from the host and the cloud account.

The plan's decision 6.1 must be settled before Phase 5 starts.

## Decision (recommended)

Amend §50 explicitly, rather than letting Phase 5 work erode it:

1. **Detection and telemetry come in as evidence for investigation, not as a SIEM replacement.** Node events, sensor output and indicator matches are stored with short retention and a per-source watermark. They become findings that are investigated, never raw alerts. Athena does not offer search, dashboards or alerting over logs.
2. **Runtime control happens only through executor grants.** Any enforcement, such as a Tetragon policy or a shield, is a registered executor action. It runs under a grant that a separate signer issues after a human approves it, and it is recorded in the audit chain. Nothing inline, and nothing automatic.
3. **Cloud posture moves forward from PRD Phase 3.** It uses read-only credentials, a sandbox with an egress allowlist, and misconfiguration findings.

Record the amendment by updating §50 and `docs/MILESTONES.md` when this decision is accepted. Phase 5 starts only after acceptance and after Phase 1's acceptance tests pass on the fixture estate.

## Consequences

- Phase 5 of the plan (workstreams 5.1 to 5.5) becomes in scope. Without this decision it is dropped.
- §50's EDR, IDS and SIEM lines change from "never" to "only as evidence for investigation". The WAF and inline-control line changes to "only as a granted, approved, audited executor action".
- The invariants in section 5 of the plan apply unchanged. The model never decides outcomes, every consequential action is audited, and unobserved never means clean. A telemetry gap shows as a gap.
- Athena takes on an event store, retention and a volume budget per source (decision 6.4), and a runtime sensor (decision 6.5). That is new operational weight for a self-hosted product.
- Enforcement depends on Phase 0 and Phase 1 being real: the signer, the executor, approvals, separation of duties and rollback.
- Positioning needs care. Users must not read Athena as an EDR or SIEM, and the documentation must say what it does not watch.

## Alternatives

- **Keep §50 as written, and drop Phase 5.** Athena stays a weakness finder with a remediation loop. This is simpler and has less surface, but compromise assessment stays manual, and the plan's runtime and cloud evidence is lost.
- **Adopt detection fully, as a SIEM or EDR.** This was rejected. It competes with mature products, multiplies the data Athena holds, and pulls the product away from investigation and resolution.
- **Allow inline runtime control outside the executor.** This was rejected. It would bypass the grant, approval and audit path that every other action uses.
