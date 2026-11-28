from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from athena.db.models import (
    Asset,
    AssetComponent,
    Component,
    Finding,
    InvestigationRecord,
    ScanRun,
    Suppression,
    Vulnerability,
)
from athena.export import sbom_for, vex_document
from athena.export.openvex import product_id

pytestmark = pytest.mark.usefixtures("engine")


@pytest.fixture
def estate(session):
    image = Asset(
        kind="image",
        identity_key=f"sha256:{uuid.uuid4().hex}{uuid.uuid4().hex}",
        display_name="ghcr.io/acme/api:1.4",
        tier="production",
        exposure="internet",
        attributes={"repository": "ghcr.io/acme/api", "tag": "1.4"},
    )
    session.add(image)
    session.flush()
    run = ScanRun(
        asset_id=image.id,
        kind="image",
        tool="syft",
        tool_version="1.30.0",
        status="partial",
        finished_at=datetime.now(UTC),
    )
    session.add(run)
    session.flush()

    def component(name, version, eco="pypi"):
        c = Component(ecosystem=eco, name=f"{name}-{uuid.uuid4().hex[:6]}", version=version)
        session.add(c)
        session.flush()
        session.add(
            AssetComponent(
                asset_id=image.id,
                component_id=c.id,
                scope="direct",
                observed_at=datetime.now(UTC),
                scan_run_id=run.id,
            )
        )
        return c

    def finding(component_, *, verdict=None, malicious=False, state="discovered", withdrawn=False):
        vid = f"{'MAL' if malicious else 'CVE'}-2099-{uuid.uuid4().hex[:6]}"
        v = Vulnerability(
            id=vid,
            content_hash=f"h{vid}",
            malicious=malicious,
            aliases=["GHSA-xxxx-yyyy-zzzz"],
            withdrawn_at=datetime.now(UTC) if withdrawn else None,
        )
        session.add(v)
        session.flush()
        inv_id = None
        if verdict:
            inv = InvestigationRecord(
                fingerprint=uuid.uuid4().hex,
                vulnerability_id=vid,
                advisory_revision=1,
                verdict=verdict,
                verdict_confidence=0.9,
                model="test",
                prompt_hash="x",
            )
            session.add(inv)
            session.flush()
            inv_id = inv.id
        now = datetime.now(UTC)
        f = Finding(
            group_key=vid,
            vulnerability_id=vid,
            asset_id=image.id,
            component_id=component_.id,
            state=state,
            match_method="purl_exact_range",
            match_confidence=0.95,
            fixed_version="2.0",
            advisory_revision=1,
            first_seen=now,
            state_changed_at=now,
            investigation_id=inv_id,
        )
        session.add(f)
        session.flush()
        return f

    found = {
        "applicable": finding(component("requests", "2.0"), verdict="applicable"),
        "model_says_no": finding(component("flask", "1.0"), verdict="not_applicable"),
        "unlooked": finding(component("jinja2", "3.0")),
        "human_says_no": finding(component("pyyaml", "5.0"), verdict="applicable"),
        "accepted": finding(component("urllib3", "1.0")),
        "malware": finding(component("colourama", "0.1"), malicious=True),
        "resolved": finding(component("idna", "2.0"), state="resolved"),
        "withdrawn_malware": finding(
            component("colorama-lookalike", "0.2"), malicious=True, withdrawn=True
        ),
        "withdrawn_cve": finding(component("certifi", "1.0"), verdict="applicable", withdrawn=True),
    }
    for key, code, reason, expires in (
        (
            "human_says_no",
            "compensating_control",
            "WAF rule 42 blocks the vulnerable endpoint",
            None,
        ),
        (
            "accepted",
            "accepted_risk",
            "Internal tool, replaced next quarter",
            datetime.now(UTC) + timedelta(days=30),
        ),
    ):
        f = found[key]
        session.add(
            Suppression(
                vulnerability_id=f.vulnerability_id,
                asset_id=f.asset_id,
                component_id=f.component_id,
                reason_code=code,
                reason=reason,
                created_by="user:alice",
                expires_at=expires,
            )
        )
    session.flush()
    return image, found


def _statement(doc, finding):
    [s] = [s for s in doc["statements"] if s["vulnerability"]["name"] == finding.vulnerability_id]
    return s


def test_vex_statuses_follow_who_decided(session, estate):
    image, found = estate
    doc = vex_document(session, asset_id=str(image.id))
    assert doc["@context"] == "https://openvex.dev/ns/v0.2.0"

    assert _statement(doc, found["applicable"])["status"] == "affected"
    assert "action_statement" in _statement(doc, found["applicable"])

    human = _statement(doc, found["human_says_no"])
    assert human["status"] == "not_affected"
    assert human["justification"] == "inline_mitigations_already_exist"
    assert "WAF rule 42" in human["impact_statement"]

    model = _statement(doc, found["model_says_no"])
    assert model["status"] == "under_investigation", "the model may not assert not_affected"
    assert "No person has confirmed" in model["status_notes"]

    assert _statement(doc, found["unlooked"])["status"] == "under_investigation"

    accepted = _statement(doc, found["accepted"])
    assert accepted["status"] == "affected"
    assert accepted["action_statement"].startswith("Accepted risk until")

    malware = _statement(doc, found["malware"])
    assert malware["status"] == "affected"
    assert "rotate" in malware["action_statement"]

    assert _statement(doc, found["resolved"])["status"] == "fixed"


def test_withdrawn_advisories_are_not_exported(session, estate):
    image, found = estate
    withdrawn = {
        found["withdrawn_malware"].vulnerability_id,
        found["withdrawn_cve"].vulnerability_id,
    }
    for doc in (
        vex_document(session, asset_id=str(image.id)),
        vex_document(session),
        vex_document(session, vulnerability_id=found["withdrawn_malware"].vulnerability_id),
    ):
        assert not {s["vulnerability"]["name"] for s in doc["statements"]} & withdrawn
    live = _statement(vex_document(session, asset_id=str(image.id)), found["malware"])
    assert live["status"] == "affected"


def test_every_not_affected_carries_a_justification_or_impact_statement(session, estate):
    image, _ = estate
    for s in vex_document(session, asset_id=str(image.id))["statements"]:
        if s["status"] == "not_affected":
            assert s.get("justification") or s.get("impact_statement")
        if s["status"] == "affected":
            assert s.get("action_statement")


def test_image_products_are_oci_purls_on_the_digest(session, estate):
    image, found = estate
    pid = product_id(image)
    assert pid.startswith("pkg:oci/api@sha256%3A")
    assert "repository_url=ghcr.io%2Facme%2Fapi" in pid
    statement = _statement(vex_document(session, asset_id=str(image.id)), found["applicable"])
    assert statement["products"][0]["subcomponents"][0]["@id"].startswith("pkg:pypi/requests-")


def test_sbom_lists_components_and_admits_a_partial_scan(session, estate):
    image, found = estate
    bom = sbom_for(session, image)
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
    assert len(bom["components"]) == len(found)
    assert all(c["purl"].startswith("pkg:pypi/") for c in bom["components"])
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert props["athena:scan_status"] == "partial"
    assert "may be incomplete" in props["athena:completeness"]
    assert bom["metadata"]["component"]["type"] == "container"


def test_sbom_for_a_never_scanned_asset_says_so(session):
    host = Asset(kind="host", identity_key=f"machine-id:{uuid.uuid4()}", display_name="h")
    session.add(host)
    session.flush()
    bom = sbom_for(session, host)
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert bom["components"] == []
    assert "never scanned" in props["athena:completeness"]


@pytest.mark.parametrize(
    ("clone_url", "published"),
    [
        (
            "https://x-access-token:ghp_TOKENVALUE123@github.com/acme/api.git",
            "https://github.com/acme/api.git",
        ),
        (
            "https://user@git.example.com:8443/team/svc?token=abc#x",
            "https://git.example.com:8443/team/svc",
        ),
        ("git@github.com:acme/api.git", "ssh://github.com/acme/api.git"),
        (
            "https://bot:TOKEN@[fd00::5]:3000/acme/api.git",
            "https://[fd00::5]:3000/acme/api.git",
        ),
    ],
)
def test_a_repository_product_id_never_carries_credentials(clone_url, published):
    repo = Asset(
        id=uuid.uuid4(),
        kind="repository",
        identity_key="github.com/acme/api",
        display_name="acme/api",
        attributes={"clone_url": clone_url},
    )
    pid = product_id(repo)
    assert pid == published
    assert "TOKEN" not in pid and "token=" not in pid and "@" not in pid.split("//", 1)[-1]


def test_sbom_status_comes_from_the_inventory_run_not_a_later_code_scan(session, estate):
    image, _ = estate
    session.add(
        ScanRun(
            asset_id=image.id,
            kind="misconfiguration",
            tool="trivy",
            tool_version="0.76.2",
            status="succeeded",
            started_at=datetime.now(UTC) + timedelta(minutes=5),
            finished_at=datetime.now(UTC) + timedelta(minutes=6),
        )
    )
    session.flush()
    props = {p["name"]: p["value"] for p in sbom_for(session, image)["metadata"]["properties"]}
    assert props["athena:scan_status"] == "partial"
    assert "may be incomplete" in props["athena:completeness"]
