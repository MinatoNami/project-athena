from __future__ import annotations

import json
import pathlib
import re

import pytest
from sqlalchemy import select

FIXTURES = pathlib.Path(__file__).resolve().parents[2] / "deploy" / "fixtures"
REPO = FIXTURES / "repo"
GROUND_TRUTH = json.loads((FIXTURES / "ground_truth.json").read_text())
PROFILE = json.loads((FIXTURES / "host" / "profile.json").read_text())
COMPOSE = (FIXTURES / "compose.fixtures.yaml").read_text()


def _findings(*, asset: str | None = None, kind: str | None = None) -> list[dict]:
    return [
        f
        for f in GROUND_TRUTH["findings"]
        if (asset is None or f["asset"] == asset) and (kind is None or f["kind"] == kind)
    ]


def _pinned_requirements() -> set[tuple[str, str]]:
    pins = set()
    for line in (REPO / "requirements.txt").read_text().splitlines():
        name, _, version = line.partition("==")
        pins.add((re.sub(r"[-_.]+", "-", name.strip()).lower(), version.strip()))
    return pins


def _locked_npm() -> set[tuple[str, str]]:
    lock = json.loads((REPO / "package-lock.json").read_text())
    return {
        (key.removeprefix("node_modules/"), entry["version"])
        for key, entry in lock["packages"].items()
        if key.startswith("node_modules/")
    }


def test_the_manifests_scanner_reads_every_fixture_manifest():
    from athena.scanners.manifests import declarations

    found = {(d.path, d.ecosystem, d.declared) for d in declarations(REPO)}
    expected = {(m["path"], m["ecosystem"], m["declared"]) for m in GROUND_TRUTH["manifests"]}
    assert found == expected


def test_every_repository_component_in_ground_truth_is_pinned_in_a_manifest():
    pinned = {("pypi", *p) for p in _pinned_requirements()} | {("npm", *p) for p in _locked_npm()}
    wanted = {
        (c["ecosystem"], c["name"], c["version"])
        for f in _findings(asset="repo")
        if (c := f["component"])
    }
    assert wanted
    assert wanted <= pinned
    assert pinned <= wanted, "a pinned fixture package has no ground-truth entry"


def test_the_malicious_stand_in_is_a_name_and_version_only():
    malware = _findings(kind="malware")
    assert [f["id"] for f in malware] == ["MAL-2026-20101"]
    component = malware[0]["component"]
    assert (component["name"], component["version"]) == ("agent-framework", "1.26.1")
    assert not list(REPO.rglob("*agent_framework*"))
    assert not list(REPO.rglob("*.py"))


def test_planted_secrets_sit_where_ground_truth_says_and_are_obviously_fake():
    shapes = {
        "aws-access-token": re.compile(r"\bAKIA[A-Z2-7]{16}\b"),
        "github-pat": re.compile(r"\bghp_[0-9A-Za-z]{36}\b"),
    }
    for finding in _findings(kind="secret"):
        line = (REPO / finding["path"]).read_text().splitlines()[finding["line"] - 1]
        match = shapes[finding["id"]].search(line)
        assert match, finding
        assert "Fake" in match.group(0) or "FAKE" in match.group(0)


def test_pth_fixtures_split_into_one_benign_path_and_one_import_hook():
    by_class = {f["classification"]: f for f in _findings(kind="pth_hook")}
    assert set(by_class) == {"benign", "suspicious"}

    hook = (REPO / by_class["suspicious"]["path"]).read_text().splitlines()
    path_entry = (REPO / by_class["benign"]["path"]).read_text().splitlines()
    assert hook == ["import sys"]
    assert path_entry and not any(line.startswith("import") for line in path_entry)


def test_fixture_images_are_pinned_by_tag_and_digest_and_match_ground_truth():
    pinned = dict(re.findall(r"image:\s*(\S+?)@(sha256:[0-9a-f]{64})", COMPOSE))
    images = {
        a["reference"]: a["digest"] for a in GROUND_TRUTH["assets"].values() if a["kind"] == "image"
    }
    assert pinned == images
    assert COMPOSE.count('athena.fixture: "true"') >= len(images)
    for published in re.findall(r"ports:\s*\[([^\]]*)\]", COMPOSE):
        for mapping in re.findall(r'"([^"]+)"', published):
            assert mapping.startswith("127.0.0.1:"), mapping


def test_every_finding_names_a_known_asset():
    assets = set(GROUND_TRUTH["assets"])
    assert {f["asset"] for f in GROUND_TRUTH["findings"]} <= assets


def _replay_profile(session):
    from athena.inventory.identity import AssetKind
    from athena.inventory.service import finish_scan, register_asset, start_scan
    from athena.workers.node_ingest import _apply

    host, _ = register_asset(
        session,
        kind=AssetKind.HOST,
        identity_key=PROFILE["host"]["identity_key"],
        display_name=PROFILE["host"]["display_name"],
    )
    session.flush()
    for observation in PROFILE["observations"]:
        capability = observation["capability"]
        run = start_scan(session, asset=host, kind="host", tool=f"athena-node/{capability}")
        stats = _apply(
            session, asset=host, run=run, capability=capability, data=observation["data"]
        )
        finish_scan(session, run, status="succeeded", stats=stats)
        session.flush()
    return host


def test_the_host_profile_replays_through_node_ingest(session):
    from athena.db.models import Asset, AssetComponent, AssetEdge, Component
    from athena.inventory.identity import AssetKind

    host = _replay_profile(session)
    assert host.identity_key == GROUND_TRUTH["assets"]["host"]["identity_key"]
    assert host.attributes["distro"] == "ubuntu"
    assert host.attributes["distro_release"] == "20.04"

    recorded = {
        (c.ecosystem, c.name, c.version)
        for c in session.execute(
            select(Component)
            .join(AssetComponent, AssetComponent.component_id == Component.id)
            .where(AssetComponent.asset_id == host.id)
        ).scalars()
    }
    profile_packages = next(
        o["data"] for o in PROFILE["observations"] if o["capability"] == "list_packages"
    )
    assert len(recorded) == len(profile_packages)
    for finding in _findings(asset="host"):
        c = finding["component"]
        assert (c["ecosystem"], c["name"], c["version"]) in recorded, finding

    services = (
        session.execute(
            select(Asset)
            .join(AssetEdge, AssetEdge.src_id == Asset.id)
            .where(AssetEdge.dst_id == host.id, Asset.kind == AssetKind.SERVICE)
        )
        .scalars()
        .all()
    )
    observed = {(s.attributes["port"], s.attributes["process"], s.exposure) for s in services}
    expected = {
        (e["port"], e["process"], e["exposure"])
        for e in GROUND_TRUTH["host_expectations"]["listening"]
    }
    assert observed == expected

    containers = (
        session.execute(
            select(Asset)
            .join(AssetEdge, AssetEdge.src_id == Asset.id)
            .where(AssetEdge.dst_id == host.id, Asset.kind == AssetKind.CONTAINER)
        )
        .scalars()
        .all()
    )
    assert {c.display_name for c in containers} == set(
        GROUND_TRUTH["host_expectations"]["containers"]
    )

    for key in GROUND_TRUTH["host_expectations"]["images"]:
        digest = GROUND_TRUTH["assets"][key]["digest"]
        image = session.execute(
            select(Asset).where(
                Asset.kind == AssetKind.IMAGE, Asset.attributes["digest"].astext == digest
            )
        ).scalar_one()
        built_from = (
            session.execute(
                select(AssetEdge).where(
                    AssetEdge.dst_id == image.id, AssetEdge.relation == "built_from"
                )
            )
            .scalars()
            .all()
        )
        assert len(built_from) == 1, key


@pytest.mark.parametrize("classification", ["affected", "not_affected_backport"])
def test_host_ground_truth_covers_both_sides_of_the_backport_question(classification):
    assert any(f["classification"] == classification for f in _findings(asset="host"))
