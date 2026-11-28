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
        return "medium"
    return "high"


def _entropy_key(value: Any) -> str:
    try:
        return f"{float(value):.4f}"
    except (TypeError, ValueError):
        return "-"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def parse(stdout: str, *, checkout: str) -> list[CodeObservation]:
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
