from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from athena.codefindings.model import CodeObservation, normalise_severity
from athena.config import get_settings
from athena.scanners.sandbox import Mount, SandboxResult, SandboxSpec, run_sandboxed

TIMEOUT = 300
ROOT = "/scan"

_ID = re.compile(r"^(?:AVD-)?([A-Z]+)-?0*(\d+)$")


def canonical_rule(rule_id: str | None) -> str:
    rule = (rule_id or "").strip().upper()
    match = _ID.match(rule)
    if not match:
        return rule or "UNKNOWN"
    return f"{match.group(1)}-{int(match.group(2)):04d}"


def scan(path_in_volume: str, *, work_volume: str) -> SandboxResult:
    return run_sandboxed(
        SandboxSpec(
            image=get_settings().trivy_image,
            command=[
                "fs",
                "--scanners",
                "misconfig",
                "--format",
                "json",
                "--skip-db-update",
                "--skip-java-db-update",
                "--skip-check-update",
                "--offline-scan",
                "--disable-telemetry",
                "--skip-version-check",
                "--quiet",
                f"{ROOT}/{path_in_volume}",
            ],
            mounts=[Mount(volume=work_volume, target=ROOT, read_only=True)],
            network="none",
            timeout=TIMEOUT,
            env={"TRIVY_CACHE_DIR": "/tmp/trivy", "HOME": "/tmp"},  # noqa: S108
        )
    )


def parse(stdout: str) -> tuple[list[CodeObservation], dict[str, Any]]:
    report = json.loads(stdout or "null")
    if not isinstance(report, dict):
        raise ValueError("trivy did not produce a JSON object")

    out: list[CodeObservation] = []
    files = passed = 0
    for result in report.get("Results") or []:
        if not isinstance(result, dict) or result.get("Class") != "config":
            continue
        files += 1
        passed += int((result.get("MisconfSummary") or {}).get("Successes") or 0)
        target = str(result.get("Target") or "").lstrip("/")
        for m in result.get("Misconfigurations") or []:
            if not isinstance(m, dict) or (m.get("Status") or "FAIL") != "FAIL":
                continue
            rule = canonical_rule(m.get("ID") or m.get("AVDID"))
            cause = m.get("CauseMetadata") or {}
            resource = str(cause.get("Resource") or "")
            line = cause.get("StartLine")
            identity = f"misconfiguration:{rule}:{target}:{resource}"
            out.append(
                CodeObservation(
                    kind="misconfiguration",
                    rule_id=rule,
                    title=str(m.get("Title") or rule)[:300],
                    severity=normalise_severity(m.get("Severity")),
                    path=target,
                    line=int(line) if isinstance(line, int) else None,
                    fingerprint=hashlib.sha256(identity.encode()).hexdigest(),
                    detail={
                        "message": str(m.get("Message") or "")[:1000],
                        "resolution": str(m.get("Resolution") or "")[:1000],
                        "reference": m.get("PrimaryURL"),
                        "file_type": result.get("Type"),
                        "provider": cause.get("Provider"),
                        "service": cause.get("Service"),
                        "resource": resource or None,
                        "end_line": cause.get("EndLine"),
                    },
                )
            )
    return out, {"files_checked": files, "checks_passed": passed}


def version_of(stdout: str) -> str | None:
    try:
        report = json.loads(stdout or "null")
    except json.JSONDecodeError:
        return None
    trivy = (report or {}).get("Trivy") if isinstance(report, dict) else None
    return (trivy or {}).get("Version") if isinstance(trivy, dict) else None
