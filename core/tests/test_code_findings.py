"""Secrets and misconfigurations: adapters, identity, and what a scan may conclude.

The two reports below are trimmed from real runs of the pinned images
(gitleaks v8.30.1, trivy 0.76.2) under Athena's sandbox flags against a fixture with
a planted, fake GitHub token and a root-user Dockerfile.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import pytest

from athena.codefindings import record_code_scan
from athena.codefindings.model import normalise_severity
from athena.scanners import misconfig, secrets

GITLEAKS_REPORT = json.dumps(
    [
        {
            "RuleID": "github-pat",
            "Description": "Uncovered a GitHub Personal Access Token, potentially leading to "
            "unauthorized repository access and sensitive content exposure.",
            "StartLine": 2,
            "EndLine": 2,
            "StartColumn": 18,
            "EndColumn": 57,
            "Match": "REDACTED",
            "Secret": "REDACTED",
            "File": "/scan/checkout-0123456789ab/app/settings.py",
            "SymlinkFile": "",
            "Commit": "",
            "Entropy": 4.853056,
            "Author": "",
            "Email": "",
            "Date": "",
            "Message": "",
            "Tags": [],
            "Fingerprint": "/scan/checkout-0123456789ab/app/settings.py:github-pat:2",
        }
    ]
)

TRIVY_REPORT = json.dumps(
    {
        "SchemaVersion": 2,
        "Trivy": {"Version": "0.76.2"},
        "ArtifactName": "/scan/checkout-0123456789ab",
        "ArtifactType": "filesystem",
        "Results": [
            {
                "Target": "Dockerfile",
                "Class": "config",
                "Type": "dockerfile",
                "MisconfSummary": {"Successes": 24, "Failures": 3},
                "Misconfigurations": [
                    {
                        "Type": "Dockerfile Security Check",
                        "ID": "DS-0002",
                        "Title": "Image user should not be 'root'",
                        "Message": "Specify at least 1 USER command in Dockerfile",
                        "Resolution": "Add 'USER <non root user name>' line to the Dockerfile",
                        "Severity": "HIGH",
                        "PrimaryURL": "https://avd.aquasec.com/misconfig/ds-0002",
                        "Status": "FAIL",
                        "CauseMetadata": {"Provider": "Dockerfile", "Service": "general"},
                    },
                    {
                        "Type": "Dockerfile Security Check",
                        "ID": "DS-0029",
                        "Title": "'apt-get' missing '--no-install-recommends'",
                        "Severity": "HIGH",
                        "Status": "FAIL",
                        "CauseMetadata": {
                            "Provider": "Dockerfile",
                            "Service": "general",
                            "StartLine": 2,
                            "EndLine": 2,
                            "Code": {
                                "Lines": [
                                    {
                                        "Number": 2,
                                        "Content": "RUN apt-get update && apt-get install -y curl",
                                    }
                                ]
                            },
                        },
                    },
                    {"ID": "DS-0001", "Title": "passes", "Severity": "LOW", "Status": "PASS"},
                ],
            }
        ],
    }
)


# ── gitleaks ─────────────────────────────────────────────────────────────────


def test_gitleaks_report_becomes_a_redacted_observation():
    [obs] = secrets.parse(GITLEAKS_REPORT, checkout="checkout-0123456789ab")
    assert obs.kind == "secret" and obs.rule_id == "github-pat"
    assert obs.path == "app/settings.py"
    assert obs.line == 2
    assert obs.severity == "critical"
    # Neither the value nor its surrounding line is kept, redacted or not.
    blob = json.dumps(obs.detail)
    assert "Match" not in blob and "Secret" not in blob and "REDACTED" not in blob
    assert obs.detail["redacted"] is True


def test_secret_identity_survives_the_random_checkout_directory():
    """Gitleaks' own fingerprint embeds the per-scan checkout path and would make
    every patrol resolve and recreate every finding."""
    a = secrets.parse(GITLEAKS_REPORT, checkout="checkout-0123456789ab")[0]
    moved = GITLEAKS_REPORT.replace("checkout-0123456789ab", "checkout-ba9876543210")
    b = secrets.parse(moved, checkout="checkout-ba9876543210")[0]
    assert a.fingerprint == b.fingerprint


def test_secret_identity_survives_an_edit_above_it():
    shifted = GITLEAKS_REPORT.replace('"StartLine": 2', '"StartLine": 40')
    a = secrets.parse(GITLEAKS_REPORT, checkout="checkout-0123456789ab")[0]
    b = secrets.parse(shifted, checkout="checkout-0123456789ab")[0]
    assert a.fingerprint == b.fingerprint and b.line == 40


def test_an_empty_gitleaks_report_is_no_findings_not_an_error():
    assert secrets.parse("[]", checkout="x") == []


@pytest.mark.parametrize("stdout", ["", "not json", '{"findings": []}'])
def test_anything_but_a_gitleaks_array_is_a_failure(stdout):
    with pytest.raises(ValueError):
        secrets.parse(stdout, checkout="x")


# ── trivy ────────────────────────────────────────────────────────────────────


def test_trivy_failures_become_observations_and_passes_do_not():
    observations, summary = misconfig.parse(TRIVY_REPORT)
    assert [o.rule_id for o in observations] == ["DS-0002", "DS-0029"]
    assert summary == {"files_checked": 1, "checks_passed": 24}
    root = observations[0]
    assert root.severity == "high" and root.path == "Dockerfile" and root.line is None
    assert "USER" in root.detail["resolution"]
    assert misconfig.version_of(TRIVY_REPORT) == "0.76.2"


def test_trivy_source_lines_are_not_kept():
    """A misconfigured file is where a credential sits beside the misconfiguration."""
    observations, _ = misconfig.parse(TRIVY_REPORT)
    assert "apt-get install" not in json.dumps([o.detail for o in observations])


@pytest.mark.parametrize("old", ["DS002", "AVD-DS-0002", "DS-0002", "ds-0002"])
def test_trivy_rule_ids_are_canonical_across_its_2026_rename(old):
    assert misconfig.canonical_rule(old) == "DS-0002"


def test_severity_words_fold_and_unknown_is_not_low():
    assert normalise_severity("HIGH") == "high"
    assert normalise_severity("WARNING") == "medium"
    assert normalise_severity("UNKNOWN") == "medium"


# ── recording ────────────────────────────────────────────────────────────────


@pytest.fixture
def repo(session):
    from athena.db.models import Asset

    asset = Asset(
        kind="repository",
        identity_key=f"github.com/acme/{uuid.uuid4()}",
        display_name="acme/api",
        tier="production",
        exposure="internal",
    )
    session.add(asset)
    session.flush()
    return asset


def _secret():
    return secrets.parse(GITLEAKS_REPORT, checkout="checkout-0123456789ab")


def test_a_scan_creates_then_recognises_its_findings(session, repo):
    first = record_code_scan(
        session,
        asset=repo,
        kind="secret",
        tool="gitleaks",
        tool_version="v8.30.1",
        status="succeeded",
        observations=_secret(),
    )
    second = record_code_scan(
        session,
        asset=repo,
        kind="secret",
        tool="gitleaks",
        tool_version="v8.30.1",
        status="succeeded",
        observations=_secret(),
    )
    assert first["new"] == 1 and second == {"new": 0, "seen": 1, "resolved": 0, "reopened": 0}


def test_only_a_successful_scan_resolves(session, repo):
    from athena.db.models import CodeFinding

    record_code_scan(
        session,
        asset=repo,
        kind="secret",
        tool="gitleaks",
        tool_version=None,
        status="succeeded",
        observations=_secret(),
    )
    failed = record_code_scan(
        session,
        asset=repo,
        kind="secret",
        tool="gitleaks",
        tool_version=None,
        status="failed",
        observations=None,
        error="gitleaks failed: timeout",
    )
    assert failed["resolved"] == 0
    finding = session.query(CodeFinding).filter_by(asset_id=repo.id).one()
    assert finding.resolved_at is None, "a failed scan is not evidence of absence"

    clean = record_code_scan(
        session,
        asset=repo,
        kind="secret",
        tool="gitleaks",
        tool_version=None,
        status="succeeded",
        observations=[],
    )
    assert clean["resolved"] == 1
    session.refresh(finding)
    assert finding.resolved_at is not None

    back = record_code_scan(
        session,
        asset=repo,
        kind="secret",
        tool="gitleaks",
        tool_version=None,
        status="succeeded",
        observations=_secret(),
    )
    assert back["reopened"] == 1
    session.refresh(finding)
    assert finding.resolved_at is None


def test_a_code_scan_does_not_refresh_inventory_freshness(session, repo):
    """A secrets scan says nothing about installed packages."""
    assert repo.last_inventoried_at is None
    record_code_scan(
        session,
        asset=repo,
        kind="misconfiguration",
        tool="trivy",
        tool_version="0.76.2",
        status="succeeded",
        observations=misconfig.parse(TRIVY_REPORT)[0],
    )
    session.refresh(repo)
    assert repo.last_inventoried_at is None


def test_one_kind_never_resolves_the_other(session, repo):
    record_code_scan(
        session,
        asset=repo,
        kind="secret",
        tool="gitleaks",
        tool_version=None,
        status="succeeded",
        observations=_secret(),
    )
    out = record_code_scan(
        session,
        asset=repo,
        kind="misconfiguration",
        tool="trivy",
        tool_version=None,
        status="succeeded",
        observations=[],
    )
    assert out["resolved"] == 0


def test_runs_are_recorded_with_their_counts(session, repo):
    from athena.db.models import ScanRun

    record_code_scan(
        session,
        asset=repo,
        kind="secret",
        tool="gitleaks",
        tool_version="v8.30.1",
        status="succeeded",
        observations=_secret(),
        stats={"scope": "working tree only; history not searched"},
    )
    run = session.query(ScanRun).filter_by(asset_id=repo.id, kind="secret").one()
    assert run.status == "succeeded" and run.finished_at <= datetime.now(UTC)
    assert run.stats["new"] == 1 and run.stats["scope"].startswith("working tree")
