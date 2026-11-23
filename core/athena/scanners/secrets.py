"""Gitleaks adapter: a repository checkout → secret observations.

Three rules govern this module, all about not becoming the leak it reports.

1. **The secret never leaves the sandbox.** Gitleaks runs with `--redact`, which
   replaces the value inside the detector before any report is written. The adapter
   then refuses to keep `Secret` or `Match` at all, redacted or not: `Match` carries
   the surrounding line, and a line that holds one credential often holds another.

2. **Identity follows the credential, never its value.** Gitleaks' own
   `Fingerprint` embeds the absolute path inside the container — which includes the
   per-scan random checkout directory — and the line, so it changes on every run and
   on every edit above the secret. The fingerprint here is the rule, the path
   relative to the repository root, and the Shannon entropy Gitleaks reports for the
   matched value. Entropy is a property of the value that cannot be turned back into
   it, it survives `--redact`, and it stays put when the line moves — so removing one
   of two tokens in a file no longer hands the survivor the removed one's identity,
   which is what an occurrence ordinal did.

   Two hits that agree on all three (the same credential pasted twice, or a rare
   entropy tie) are told apart only by their order, and nothing in the report says
   which copy went when one does. Each carries an `identity_group`, so the scan
   recorder can hold such a finding open rather than assert it resolved; see
   `record_code_scan`.

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


def _entropy_key(value: Any) -> str:
    """Gitleaks' entropy, at a precision every release prints the same way.

    Reported as a float32 (`4.6841836`); four places is well inside its precision
    and far finer than two different credentials tend to agree on. Absent or
    malformed, it is a fixed token, and identity falls back to order alone.
    """
    try:
        return f"{float(value):.4f}"
    except (TypeError, ValueError):
        return "-"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def parse(stdout: str, *, checkout: str) -> list[CodeObservation]:
    """Translate a Gitleaks JSON report. Raises ValueError if it is not one."""
    report = json.loads(stdout or "null")
    if not isinstance(report, list):
        raise ValueError("gitleaks did not produce a JSON array")

    entries: list[dict[str, Any]] = [e for e in report if isinstance(e, dict)]
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        rule = str(entry.get("RuleID") or "unknown-rule")
        path = _relative(str(entry.get("File") or ""), checkout)
        groups[(rule, path, _entropy_key(entry.get("Entropy")))].append(entry)

    out: list[CodeObservation] = []
    for (rule, path, entropy), hits in groups.items():
        hits.sort(key=lambda e: (int(e.get("StartLine") or 0), int(e.get("StartColumn") or 0)))
        group = _sha(f"secret:{rule}:{path}:{entropy}")
        for ordinal, entry in enumerate(hits):
            line = entry.get("StartLine")
            # The first occurrence keeps the group's own identity, so a credential
            # that appears once never depends on the order of anything else.
            identity = group if ordinal == 0 else _sha(f"secret:{rule}:{path}:{entropy}:{ordinal}")
            out.append(
                CodeObservation(
                    kind="secret",
                    rule_id=rule,
                    title=str(entry.get("Description") or rule)[:300],
                    severity=_severity(rule),
                    path=path,
                    line=int(line) if isinstance(line, int) else None,
                    fingerprint=identity,
                    # Deliberately absent: Secret, Match, Author, Email. The first two
                    # are the credential and its context; the last two are personal
                    # data from history this scan does not read anyway.
                    detail={
                        "entropy": entry.get("Entropy"),
                        "end_line": entry.get("EndLine"),
                        "tags": entry.get("Tags") or [],
                        "redacted": entry.get("Secret") in ("REDACTED", "", None),
                        "identity_group": group,
                    },
                )
            )
    return out
