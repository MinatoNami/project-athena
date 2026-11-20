"""Gitleaks adapter: a repository checkout → secret observations.

Three rules govern this module, all about not becoming the leak it reports.

1. **The secret never leaves the sandbox.** Gitleaks runs with `--redact`, which
   replaces the value inside the detector before any report is written. The adapter
   then refuses to keep `Secret` or `Match` at all, redacted or not: `Match` carries
   the surrounding line, and a line that holds one credential often holds another.

2. **Identity is location, not value.** Gitleaks' own `Fingerprint` embeds the
   absolute path inside the container — which includes the per-scan random checkout
   directory — so it changes on every run and would resolve-then-recreate every
   finding each patrol. The fingerprint here is built from the rule, the path
   relative to the repository root, and the occurrence's ordinal within that file,
   so an unrelated edit above it does not make it a new finding.

3. **Exit codes do not mean findings.** Gitleaks exits 1 for "leaks *or* error", so
   it runs with `--exit-code 0` and a failure is anything that is not a JSON array.

Only the working tree is scanned (`gitleaks dir`). History needs a full clone, and
the checkout is shallow by design; a secret removed from HEAD but alive in history
is real and is not detected here — the scan says so in its stats.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from typing import Any

from athena.codefindings.model import CodeObservation
from athena.config import get_settings
from athena.scanners.sandbox import Mount, SandboxResult, SandboxSpec, run_sandboxed

TIMEOUT = 300
ROOT = "/scan"

# Gitleaks rules are about credentials; how bad a leaked one is depends on what it
# unlocks, which the rule id says more about than any field in the report.
_CRITICAL_HINTS = (
    "private-key",
    "aws",
    "gcp",
    "azure",
    "github",
    "gitlab",
    "slack-bot",
    "stripe",
    "npm",
    "pypi",
    "jwt",
    "hashicorp",
    "vault",
)


def scan(path_in_volume: str, *, work_volume: str) -> SandboxResult:
    return run_sandboxed(
        SandboxSpec(
            image=get_settings().gitleaks_image,
            command=[
                "dir",
                f"{ROOT}/{path_in_volume}",
                "--report-format",
                "json",
                "--report-path",
                "-",
                "--redact",
                "--no-banner",
                "--exit-code",
                "0",
            ],
            mounts=[Mount(volume=work_volume, target=ROOT, read_only=True)],
            network="none",
            timeout=TIMEOUT,
        )
    )


def _relative(path: str, checkout: str) -> str:
    prefix = f"{ROOT}/{checkout}/"
    if path.startswith(prefix):
        return path[len(prefix) :]
    return path.lstrip("/")


def _severity(rule_id: str) -> str:
    rule = rule_id.lower()
    if any(hint in rule for hint in _CRITICAL_HINTS):
        return "critical"
    if "generic" in rule:
        # The generic rule is entropy over assignments — the noisiest Gitleaks has.
        return "medium"
    return "high"


def parse(stdout: str, *, checkout: str) -> list[CodeObservation]:
    """Translate a Gitleaks JSON report. Raises ValueError if it is not one."""
    report = json.loads(stdout or "null")
    if not isinstance(report, list):
        raise ValueError("gitleaks did not produce a JSON array")

    entries: list[dict[str, Any]] = [e for e in report if isinstance(e, dict)]
    by_file: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        rule = str(entry.get("RuleID") or "unknown-rule")
        path = _relative(str(entry.get("File") or ""), checkout)
        by_file[(rule, path)].append(entry)

    out: list[CodeObservation] = []
    for (rule, path), hits in by_file.items():
        hits.sort(key=lambda e: (int(e.get("StartLine") or 0), int(e.get("StartColumn") or 0)))
        for ordinal, entry in enumerate(hits):
            line = entry.get("StartLine")
            identity = f"secret:{rule}:{path}:{ordinal}"
            out.append(
                CodeObservation(
                    kind="secret",
                    rule_id=rule,
                    title=str(entry.get("Description") or rule)[:300],
                    severity=_severity(rule),
                    path=path,
                    line=int(line) if isinstance(line, int) else None,
                    fingerprint=hashlib.sha256(identity.encode()).hexdigest(),
                    # Deliberately absent: Secret, Match, Author, Email. The first two
                    # are the credential and its context; the last two are personal
                    # data from history this scan does not read anyway.
                    detail={
                        "entropy": entry.get("Entropy"),
                        "end_line": entry.get("EndLine"),
                        "tags": entry.get("Tags") or [],
                        "redacted": entry.get("Secret") in ("REDACTED", "", None),
                    },
                )
            )
    return out
