# Security tooling research, 27 Oct to 27 Nov 2026

**Status:** Draft · **Version:** 0.1 · **Date:** 27 November 2026
**Related:** [Implementation plan](SECURITY_AGENT_PLAN.md) · [Technical Design](TECHNICAL_DESIGN.md) · [Milestones](MILESTONES.md)

---

## How to read this

This catalogue covers the tools, standards and threats released or reported between 27 October and 27 November 2026 that bear on growing Athena into a general security agent. It merges three research passes: AI and agent security; detection, response and threat intel; and vulnerability management, supply chain, cloud and identity.

Labels carried over from the research:

- **slightly older**: released before 27 October 2026, kept because it matters.
- **pre-release**: not a stable release.
- **secondary source**: confirmed only through press or third-party coverage.
- **unverified**: could not be confirmed.

Vendor claims about effectiveness are the vendors' own. Every URL is the source the research cited.

## Agentic and AI security

| Name | Project | Date | License | What it does | Source |
|---|---|---|---|---|---|
| Perception (GA) | Microsoft | 2026-11-17 | Proprietary | Red, blue and green agent teams run through playbooks. GA covers alert triage, attack investigation, detection authoring, threat intel and recon; vulnerability shielding is in preview. Humans approve high-impact actions. | https://www.microsoft.com/en-us/security/blog/2026/11/17/security-for-the-agentic-era-powered-by-microsoft-perception/ |
| MAI Cyber 2 Flash (secondary source) | Microsoft | 2026-11-17 | Proprietary | A cyber model for finding vulnerabilities, fixing them and investigating. Available only inside Microsoft products; benchmarks are Microsoft's own. | https://www.testingcatalog.com/microsoft-launches-mai-cyber-2-flash-security-model/ |
| Codename MDASH open-source pilot | GitHub and Microsoft | 2026-11-17 | Proprietary | Cut 9,791 AI findings down to 99 verified reports and 55 fixes across 6 OSS projects. | https://github.blog/open-source/maintainers/maintainers-dont-need-more-ai-bug-reports-they-need-fixes/ |
| Agent Insider Threat Detection, AI Kill Switch | CrowdStrike | 2026-11-04 | Proprietary | Baselines each AI agent's behaviour and flags drift; a kill switch stops or pauses agents. | https://www.crowdstrike.com/en-us/press-releases/crowdstrike-extends-agentic-soc-detect-stop-agent-insider-threat/ |
| GPT-6 Cyber | OpenAI | 2026-11-05 | Proprietary, gated | Finds and validates exploitable bugs within scope. Approved Daybreak Red customers only. | https://openai.com/index/introducing-gpt-6-cyber/ |
| Daybreak Red Team, Defense Factory | OpenAI | 2026-11-12 | Proprietary, early access | Red Team validates reported flaws; Defense Factory drafts patches as PRs with a test proving the fix. | https://openai.com/daybreak/defense-factory/ and https://cybersecuritynews.com/openai-two-ai-cybersecurity-tools/ |
| NeMo Guardrails v0.25.0 | NVIDIA | 2026-11-19 | Apache-2.0 | Tool-call rails: CEL checks on tool arguments and results, allow and block lists, pre-tool-use hooks for coding agents, fixes for injection-detection bypasses. | https://github.com/NVIDIA-NeMo/Guardrails/releases |
| PyRIT 1.2.0 (1.2.1 on 11-18 is packaging only) | Microsoft | 2026-11-13 | MIT | Red-teaming framework. Adds A2A targets, tool-call scoring and the CyberSecEval prompt-injection dataset. | https://github.com/microsoft/PyRIT/releases |
| Agent Threat Rules v4.3.0/4.3.1, pyATR 0.5.0 | ATR community | 2026-11-04 to 11-09 | MIT | 844 Sigma-style YAML rules for prompt injection, tool poisoning and MCP attacks, with a Python engine. Regex-heavy: v4.3.1 had to narrow 13 rules that fired on benign content. | https://github.com/Agent-Threat-Rule/agent-threat-rules/releases |
| agent-scan v0.7.0/0.7.1 | Snyk | 2026-11-18 / 11-24 | Apache-2.0 (license from a secondary source) | Finds agent configs, MCP servers and skills on a machine and scans them. Needs a Snyk token. | https://github.com/snyk/agent-scan/releases |
| MCP Scanner 4.8.7 (slightly older) | Cisco AI Defense | 2026-10-20 | Apache-2.0 | Scans MCP tools, prompts and resources with YARA rules, LLM analysis or the Cisco API. The YARA engine works offline. | https://github.com/cisco-ai-defense/mcp-scanner/releases |
| OpenShell joins CNCF Sandbox | NVIDIA, CNCF | 2026-11-10 (secondary source) | Apache-2.0 | Agent sandbox that enforces policy on the files, network, credentials and model endpoints an agent can reach. | https://futurumgroup.com/insights/ai-agents-gain-an-open-runtime-as-agent-governance-lags-at-kubecon-cloudnativecon-na-2026/ |
| CWE-bench v2 | Collinear et al. | 2026-11-07 (v1 on 10-12) | 100 of 250 tasks public; paper CC BY 4.0 | Defensive benchmark: audit a repo and repair it. The verifier checks that the exploit is blocked and that features still work. | https://arxiv.org/abs/2610.17020 |
| Cyber Index (slightly older) | Artificial Analysis | 2026-09-28 | Stirrup harness open; test sets held out | Defensive index covering find, reproduce and patch. | https://artificialanalysis.ai/articles/artificial-analysis-cyber-index |
| Agentic Autofix GA (slightly older) | GitHub | October 2026, exact day unclear | Proprietary | Copilot fixes code-scanning alerts, re-runs CodeQL to check the fix, and opens draft PRs. | https://visualstudiomagazine.com/articles/2026/10/23/github-makes-agentic-autofix-generally-available-for-code-scanning-alerts.aspx |

## Detection, response and threat intel

| Name | Project | Date | License | What it does | Source |
|---|---|---|---|---|---|
| Shirudo (pre-release) | Cisco and OpenAI (Isovalent team) | 2026-11-23/24 | BSD-2-Clause; BPF programs BSD/GPL | Signed eBPF or Java-bytecode "shields" block an exploit until a patch lands. A TPM provides attestation of what was loaded. A rewrite of Tetragon. | https://github.com/shirudo-dev/shirudo, https://www.theregister.com/security/2026/11/24/cisco-and-openai-pitch-ebpf-kernel-plugins-as-the-way-to-tame-the-patchpocalypse/5311795 and https://thehackernews.com/2026/11/openai-and-cisco-unveil-ai-assisted.html |
| Tetragon v1.8.0 | Cilium, Isovalent (CNCF) | 2026-10-30 (blog 11-11) | Apache-2.0 | eBPF runtime observability and in-kernel enforcement. Adds stateful policies, uprobe `Override` (experimental; needs Linux 6.18 or later and glibc 2.34 or later) and `MatchCEL`. | https://github.com/cilium/tetragon/releases and https://isovalent.com/blog/post/tetragon-v1.8-release |
| pySigma 2.1.0 (2.1.2 on 11-24; 2.0.0 on 10-04 is slightly older) | SigmaHQ | 2026-11-09 | LGPL-2.1 | New `sigma.matching` module checks events against Sigma rules, including correlation rules, in-process. 2.0 added SigmaPolicy and made RE2 the default regex engine. 2.1.1 and 2.1.2 fixed a Jinja sandbox escape and a ReDoS bug. | https://github.com/SigmaHQ/pySigma/releases and https://github.com/SigmaHQ/pySigma/pull/608 |
| YARA-X 1.23 / 1.24 / 1.25 | VirusTotal | 2026-11-05 / 11-20 / 11-26 | BSD-3-Clause | Rust YARA engine. 1.25 changes the compiled-rule format, so compiled rules must be rebuilt. | https://github.com/VirusTotal/yara-x/releases |
| Suricata 8.0.8 | OISF | 2026-10-29 | GPL-2.0 | IDS/IPS/NSM release fixing 32 vulnerabilities (6 high). 7.x and libhtp are end-of-life. | https://suricata.io/2026/10/29/suricata-8-0-8-released/ |
| Zeek 9.0 LTS (slightly older) | Zeek | 2026-09-17 | BSD-3 | Network monitoring. ZeroMQ cluster by default and new NTP logs. | https://zeek.org/2026/09/introducing-zeek-9/ |
| Falco 0.45.2 | Falco (CNCF) | 2026-10-29 | Apache-2.0 | Syscall runtime detection. The 0.45 line adds raw-byte matching, reload endpoints and GPU-abuse rules. | https://github.com/falcosecurity/falco/releases |
| osquery 5.24.1 | osquery (LF) | 2026-10-29 | Apache-2.0/GPL-2.0 | SQL endpoint telemetry. Adds memory-safety hardening, disables TLS 1.0 and 1.1, restores the BPF tables. | https://github.com/osquery/osquery/releases |
| Velociraptor 0.77.4 | Velocidex (Rapid7) | 2026-11-23 | AGPL-3.0 | DFIR and hunting. Adds Windows forensic artifacts, Sigma correlation fixes and multi-org security fixes. | https://github.com/Velocidex/velociraptor/releases |
| Wazuh 5.0.0-rc2 (pre-release) | Wazuh | 2026-10-30 | GPL-2.0 | XDR/SIEM. A new engine replaces analysisd; agents talk over HTTPS; Filebeat is removed; CVSS 4 supported. | https://github.com/wazuh/wazuh/releases/tag/v5.0.0-rc2 |
| Elastic Security 9.6 | Elastic | 2026-11-23 (self-managed AlertZero and Defend features "early Dec") | Source-available; key features need an Enterprise licence | AlertZero agent workers run at three autonomy levels, and a human approves each isolate or kill action. Adds Linux ransomware protection and YARA memory scanning. | https://www.elastic.co/security-labs/blog/elastic-security-9-6-release-highlights |
| MISP 2.5.52 | MISP | 2026-11-18 | AGPL-3.0 | Security release with 50+ fixes. Needs Python 3.11 or later, ships PyMISP 3.0.0, and removes some API endpoints. | https://github.com/MISP/MISP/releases/tag/v2.5.52 |
| OpenCTI 7.2611xx (latest 7.261127.0) | Filigran | 2026-11-03 to 11-27 | Apache-2.0 community edition | Threat-intel platform. Adds a playbook editor, asset criticality, exposure and owner fields, and purl on software observables. | https://github.com/OpenCTI-Platform/opencti/releases |
| Tracecat 1.5.2 / 1.6.0-alpha.1 | Tracecat | 2026-11-10 to 11-20 | AGPL-3.0 | Open-source agentic SOAR and case management. | https://github.com/TracecatHQ/tracecat/releases |
| ARTEX IP feed | Vision Security | 2026-11-24 | Free (format and licence unverified) | About 12,000 IPs tied to ARTEX, an AI-agent attack framework. | https://securityboulevard.com/2026/11/vision-security-adds-free-feed-to-track-artex-ip-addresses/ |

## Vulnerability data and scanners

| Name | Project | Date | License | What it does | Source |
|---|---|---|---|---|---|
| Vulnerability-Lookup 7.0.0 | CIRCL | 2026-11-16 | AGPL-3.0 | Self-hosted vulnerability aggregator. Adds a GCVE validate endpoint and an `enisa_euvd` feeder; EUVD IDs now come only from ENISA. Breaking migrations; logs every user out once. | http://www.vulnerability-lookup.org/2026/11/16/vulnerability-lookup-7-0-0/ |
| Grype 0.122.0 / 0.122.1 | Anchore | 2026-11-16 / 11-18 | Apache-2.0 | Fixes RPM caret ordering and JVM version comparison, prefers the newest CVSS version, adds Docker Hardened Images OSV support. `--scope all-layers` output changed. | https://github.com/anchore/grype/releases |
| Grype 0.120.0 / 0.121.0 (slightly older) | Anchore | 2026-10-02 / 10-19 | Apache-2.0 | NVD SSVC decision points (0.120.0) and OS end-of-life warnings (0.121.0). | https://github.com/anchore/grype/releases |
| Syft 1.57.0 to 1.57.2 | Anchore | 2026-11-05 to 11-16 | Apache-2.0 | Records GNU ELF build IDs; fixes dpkg deduplication and `.dist-info/licenses` handling. | https://github.com/anchore/syft/releases |
| Trivy v0.76.2 | Aqua | 2026-11-05 | Apache-2.0 | Security rebuilds. The eMudhra mitigation (built with Go 1.27.3) is in the release notes of the earlier v0.76.1 (2026-10-21, slightly older), not v0.76.2. | https://github.com/aquasecurity/trivy/releases/tag/v0.76.2 |
| OSV-Scanner v2.7.1 | Google | 2026-11-09 | Apache-2.0 | Prefers ecosystem severity, adds `IgnoredVulns.EffectiveUntil`, and `--serve` binds to loopback. | https://github.com/google/osv-scanner/releases |
| Dependabot reachability analysis (preview) | GitHub | 2026-10-28 | Proprietary | Marks each alert reachable, potentially reachable or unreachable. JS/TS only, GitHub Enterprise Cloud only. | https://github.blog/changelog/2026-10-28-prioritize-dependabot-alerts-with-reachability-analysis/ |
| Dependabot alerts pause on inactive repos | GitHub | Announced 2026-11-10, effective 2026-12-08 | Proprietary | Turns alerts off on repos with no activity for a year. Alerts are archived, not deleted. | https://github.blog/changelog/2026-11-10-dependabot-alerts-will-pause-on-inactive-repositories/ |

## Supply chain and secrets

| Name | Project | Date | License | What it does | Source |
|---|---|---|---|---|---|
| Renovate 45 | Mend, Renovate | 2026-11-26 | AGPL-3.0 | pnpm security updates are no longer exempt from `minimumReleaseAge` by default. Requires Node 24 or 26. | https://github.com/renovatebot/renovate/discussions/48151 |
| PyPI project-page security signals | PSF, PyPI | about 2026-11-06 (date inferred from the post's URL) | Apache-2.0 (Warehouse) | Shows provenance state for each release, warns on loss or change of provenance, and adds a quarantine banner. No API change announced. | https://blog.pypi.org/posts/2026-11-06-ui-updates-complete/ |
| Betterleaks v2.0.0-rc.7 to rc.15 (stable is v1.10.1, 11-12) | Betterleaks | 2026-11-04 to 11-25 | MIT | Secret scanner with rule-defined live validation, entropy detection on by default, and new AI-provider rules. rc.9 removed the top-level `reason` field. | https://github.com/betterleaks/betterleaks/releases |
| TruffleHog v3.99.8 to v3.100.1 | Truffle Security | 2026-11-02 to 11-23 | AGPL-3.0 | New detectors and tighter verification: proxy 403s are no longer reported as live. | https://github.com/trufflesecurity/trufflehog/releases |

## Cloud and identity

| Name | Project | Date | License | What it does | Source |
|---|---|---|---|---|---|
| Prowler 5.48 to 5.53 | Prowler | 2026-11-06 to 11-27 | Apache-2.0 | Realtime AWS detection and remediation; Bedrock and AgentCore identity checks; GitHub OIDC trust-restriction check; IPv6 exposure checks. Its MCP tools declare read-only and destructive hints (5.47.0, 10-29). | https://github.com/prowler-cloud/prowler/releases |
| Entra Agent ID for local agents (preview); Defender local-agent discovery (GA) | Microsoft | 2026-11-17 | Proprietary | Discovers 60 kinds of local coding agent and gives each an identity of its own, subject to Conditional Access. | https://techcommunity.microsoft.com/blog/agent-365-blog/whats-new-in-microsoft-agent-365-ignite-2026/4571753 |
| RFC 10070 | IETF OAuth WG | 2026-11 (datatracker 11-07) | Open standard | Fixes audience injection: a client-authentication JWT's `aud` must be the authorization server's issuer. | https://datatracker.ietf.org/doc/rfc10070/ |

## Standards and regulation

| Name | Project | Date | License | What it does | Source |
|---|---|---|---|---|---|
| CSAF 2.1 Committee Specification 01 | OASIS CSAF TC | 2026-11-19 | Open standard | Next advisory and VEX format. A Committee Specification, not yet an OASIS Standard. | https://www.oasis-open.org/2026/11/19/csaf-v2-1-approved-as-committee-specification/ |
| OCSF 1.10 | OCSF (LF) | 2026-11-20 | Apache-2.0 | Adds a DNS zone-transfer class, `firewall_rule_evaluation` and `ai_capability`; likelihood on Detection Finding; resolved time on Incident Finding. | https://github.com/ocsf/ocsf-schema/releases |
| MITRE ATT&CK v20 (slightly older) | MITRE | 2026-10-13 | ATT&CK terms of use | 9 new Enterprise techniques, among them direct and indirect prompt injection and Impair Autonomous Defenses, and 15 detection strategies. | https://attack.mitre.org/resources/updates/ |
| CycloneDX 2.0 (pending, not released) | OWASP, Ecma TC54 | Ecma approval expected December 2026 | Open standard | VEX with confidence and evidence, threat models, agent-behaviour data, and the Transparency Exchange API. | https://cyclonedx.org/news/cyclonedx-v2.0-coming-soon/ |
| Securing Agentic Applications Guide v2 | OWASP GenAI | 2026-11-10 | CC BY-SA 4.0 (site default) | Covers architecture, identity, runtime protection, supply chain and assurance testing for agents. | https://genai.owasp.org/resource/securing-agentic-applications-v2/ |
| Design Tenets for Agent Identity Management Systems (secondary source) | NIST with MITRE | 2026-10-27 | US government work | Ten tenets, including delegation that narrows at each hop, deterministic access decisions, policy kept apart from reasoning, and tamper-evident evidence. A blog post, not a standard. | https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-agent-identity-design-tenets-20261109/ |
| Finding and Fixing Software Vulnerabilities Using AI | OpenSSF | 2026-11-09 | Free; license not stated | Sandbox AI tools, validate their findings, and never trust an AI patch without tests and human review. | https://openssf.org/press-release/2026/11/09/openssf-welcomes-new-members-and-expands-ai-security-resources/ |
| EU Cyber Resilience Act reporting | European Commission | Mandatory from 2026-09-11 | Regulation | Manufacturers report on their own products through ENISA's Single Reporting Platform: 24 h early warning and 72 h notification. For actively exploited vulnerabilities, the final report is due 14 days after a corrective measure is available; for severe incidents, one month. Open-source stewards are covered from 2027-12-11. | https://digital-strategy.ec.europa.eu/en/policies/cra-reporting |

Other dated changes the research found, with no primary URL in the reports:

- **CISA BOD 26-04 (2026-06-10).** Remediation priority comes from asset exposure, KEV status, exploit automation and technical impact. The 3/14/60-day windows were reported only in secondary coverage, not confirmed in CISA's text.
- **EU Digital Omnibus (2026-10-21; secondary sources, unverified).** The Council's mandate routes incident reports to national entry points. Trilogue is pending.
- **npm 12 (July 2026).** Install scripts are opt-in. 2FA-bypass tokens reportedly lose publish rights in January 2027 (unverified).
- **NVD and Vulnrichment.** Since April 2026, NVD reportedly enriches only a prioritised subset of CVEs (secondary sources). The Vulnrichment GitHub repo lags CVE Services by about 4.8k CVEs (issue #348).
- **CMMC Phase 2.** The 2026-11-10 start was suspended in July 2026, with no new date.

## Threat landscape

| Item | Date | Summary | Source |
|---|---|---|---|
| wfx-loot CI secret stealer | Began 2026-11-10 | 4,837 hijacked GitHub accounts pushed workflow and postinstall injection; the payload ran in at least 1,835 repos. Vendor counts differ. | https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories |
| Malicious Microsoft `agent-framework` 1.26.1/1.26.2 on PyPI | 2026-11-17 | A `.pth` startup-hook stealer that runs even if the package is never imported; likely a stolen publishing certificate. | https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi |
| eMudhra intermediate CA compromise (slightly older) | 2026-10-17 to 10-21 | Eight intermediate keys compromised. Go 1.27.3 and 1.26.10 distrust them; Go 1.25 and older get no fix. | https://thehackernews.com/2026/10/eight-emudhra-ca-keys-compromised.html |
| #StopRansomware: SafePay AA26-293A (slightly older) | 2026-10-20 | TTPs: VPN credential abuse, PsExec and WinRM, RClone exfiltration, shadow-copy deletion, NAS backup resets. | https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a |

Reported in the window without a primary URL in the reports:

- **KEV additions** on 10, 20, 24 and 25 November. They include Outlook CVE-2026-124194, Chrome CVE-2026-125350, vCenter CVE-2026-123890, Cisco Expressway hard-coded credentials, SAP NetWeaver, Drupal core CVE-2026-132165, five Mitel MiCollab flaws and Juniper Session Smart. Some due dates fell within 3 days.
- **vCenter CVE-2026-123890.** Reportedly exploited from early September, before Broadcom's patch on 19 November. Matching CVEs to assets alone would have missed months of compromise.
- **Xen Orchestra auth bypass (VSA-2026-062).** Exploited using a crafted cookie, with vendor IOCs published.
- **OPTIMJACK (13 to 16 November).** Injected Optimizely-hosted JavaScript reached 178 organisations.
- **npm.** The Axios maintainer was social-engineered (reported 19 November), and GitHub published 58 npm malware advisories on 25 November.
- **AI-driven offence.** GTIG's 16 November report on an agent that turns patch diffs into exploits with no human involved, and the ARTEX IP feed.
- **MCP gateways** (secondary source). Fixes in the AWS, Microsoft and IBM gateways, including an SSRF fixed in AWS mcp-gateway-registry 1.35.0.

## Checked and not found in the window

- No new MCP spec; the latest is still 2026-07-28.
- No CoSAI publication.
- No new CycloneDX AI-BOM version; 1.7 is current.
- No new OpenSSF model-signing release.
- MITRE ATLAS "2026.10" is unverified.
- Wiz Cyber Model Arena v3.9 and the PointGuard AI Gateway are unverified.
- Nuclei v4 is not released.
- SPDX 3.1 is a release candidate only.
- No new EPSS model; v5 dates from 2026-06-15.
- No major cosign or Sigstore release, and no new OpenVEX, SSVC or CVSS versions.
- The SigmaHQ rule packs are still r2026-07-01.
- STIX and TAXII are still 2.1; CACAO is still v2.0 CS; D3FEND is 1.6.0 (31 August).
- Nothing confirmed for the OpenTelemetry security semantic conventions.

## Trends

- **Verifying and fixing is now the bottleneck, not finding bugs.** MDASH filtered 9,791 findings down to 99 reports. Defense Factory and CWE-bench both require a test proving the fix.
- **Shielding before a patch is now a product category.** Shirudo, Microsoft's vulnerability shielding and Astelia's network mitigation (24 November) all arrived as exploit timelines shrink.
- **AI agents are treated as identities and possible insiders.** Examples are Entra Agent ID, CrowdStrike's agent baselines and kill switch, and the NIST tenets.
- **Guardrails are moving to the tool-call boundary.** Examples are NeMo tool rails, PyRIT tool-call scoring and ATR.
- **The strongest cyber models are gated.** A self-hosted Athena should not depend on them.

## License constraints

- **AGPL-3.0 components run only as separate services or subprocesses, never imported or linked into Athena's code.** These are MISP, Velociraptor, TruffleHog, Vulnerability-Lookup, Tracecat and Renovate. Each runs as its own container or a sandboxed subprocess, and Athena talks to it over its API or CLI output.
- **GPL-2.0 components (Suricata, Wazuh, osquery's GPL side) follow the same rule.**
- **pySigma is LGPL-2.1 and would be the one copyleft library imported in-process.** Have the licence owner confirm that before it ships.
- **Elastic's AlertZero and Defend features need an Enterprise licence, and its detection-rules repository is not OSI-licensed.** Treat Elastic as a design reference and an optional integration target, not a dependency.
- **Snyk agent-scan needs a Snyk token and sends tool descriptions to Snyk.** That breaks Athena's self-hosted, `local_only` default, so prefer Cisco MCP Scanner's offline YARA mode.
