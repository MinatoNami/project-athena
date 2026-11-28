# Athena — Documentation

| Document | What it answers |
|---|---|
| [Product Requirements Document](../Athena%20—%20Product%20Requirements%20Document.md) | What Athena does, for whom, and why |
| [Technical Design](TECHNICAL_DESIGN.md) | How the system is built |
| [Web UI Specification](WEB_UI.md) | How the Nuxt dashboard is built |
| [Milestones and Checkpoints](MILESTONES.md) | What gets built when, and how each stage is proven |
| [Security Agent Implementation Plan](SECURITY_AGENT_PLAN.md) | How Athena grows to identify, mitigate and resolve threats |
| [Security Tooling Research, Nov 2026](RESEARCH_2026-11.md) | Which tools, standards and threats from 27 Oct to 27 Nov 2026 shape that plan |

### Reading order

New to the project: **PRD** → **Milestones** → **Technical Design**.
Starting implementation: **Milestones M0** → **Technical Design §§1–6** → the module sections you are working in.

### Conventions

- The PRD owns intent. The Technical Design owns mechanism. Where they conflict, each wins in its own domain and the other is updated.
- Superseded technical decisions are recorded as new ADRs, never edited in place.
- Every document carries a version and a date. Bump both when the content changes materially.
