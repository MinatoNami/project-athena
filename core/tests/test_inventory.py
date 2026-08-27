"""Inventory behaviour that the product's honesty rules depend on."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from athena.db.models import Asset, AssetComponent, AssetEdge, MergeCandidate
from athena.inventory.identity import AssetKind
from athena.inventory.service import (
    ObservedComponent,
    coverage,
    finish_scan,
    flag_merge_candidate,
    is_stale,
    link,
    record_components,
    register_asset,
    start_scan,
)


def _repo(session, name="repo-a"):
    asset, _ = register_asset(
        session,
        kind=AssetKind.REPOSITORY,
        identity_key=f"github.com/org/{name}",
        display_name=f"org/{name}",
    )
    return asset


def test_registering_the_same_identity_twice_does_not_duplicate(session):
    a = _repo(session)
    b, created_b = register_asset(
        session,
        kind=AssetKind.REPOSITORY,
        identity_key="github.com/org/repo-a",
        display_name="org/repo-a",
    )
    session.flush()
    assert a.id == b.id
    assert created_b is False


def test_a_new_asset_is_never_scanned_not_clean(session):
    asset = _repo(session, "fresh-repo")
    session.flush()
    assert asset.last_inventoried_at is None
    assert is_stale(asset) is True


def test_only_a_conclusive_scan_marks_an_asset_inventoried(session):
    """A partial or failed scan must leave the asset stale. Reporting it as clean
    would turn 'we could not look' into 'there is nothing there'."""
    for status in ("failed", "partial", "timeout"):
        asset = _repo(session, f"repo-{status}")
        run = start_scan(session, asset=asset, kind="repository", tool="syft")
        finish_scan(session, run, status=status, error="scanner died")
        session.flush()
        assert asset.last_inventoried_at is None, f"{status} must not mark the asset inventoried"

    asset = _repo(session, "repo-ok")
    run = start_scan(session, asset=asset, kind="repository", tool="syft")
    finish_scan(session, run, status="succeeded", stats={"components": 3})
    session.flush()
    assert asset.last_inventoried_at is not None


def test_components_are_recorded_with_their_scan_provenance(session):
    asset = _repo(session, "repo-components")
    run = start_scan(session, asset=asset, kind="repository", tool="syft", tool_version="1.0.0")
    count = record_components(
        session,
        asset=asset,
        run=run,
        components=[
            ObservedComponent(ecosystem="pypi", name="Requests", version="2.31.0"),
            ObservedComponent(
                ecosystem="npm", name="left-pad", version="1.3.0", scope="transitive"
            ),
        ],
    )
    finish_scan(session, run, status="succeeded")
    session.flush()

    assert count == 2
    rows = session.execute(
        select(AssetComponent).where(AssetComponent.asset_id == asset.id)
    ).scalars().all()
    assert {r.scan_run_id for r in rows} == {run.id}, "every row must name the run that saw it"


def test_a_removed_dependency_disappears_on_the_next_full_scan(session):
    asset = _repo(session, "repo-drift")

    first = start_scan(session, asset=asset, kind="repository", tool="syft")
    record_components(
        session,
        asset=asset,
        run=first,
        components=[
            ObservedComponent(ecosystem="pypi", name="requests", version="2.31.0"),
            ObservedComponent(ecosystem="pypi", name="urllib3", version="1.26.0"),
        ],
    )
    finish_scan(session, first, status="succeeded")
    session.flush()

    second = start_scan(session, asset=asset, kind="repository", tool="syft")
    record_components(
        session,
        asset=asset,
        run=second,
        components=[ObservedComponent(ecosystem="pypi", name="requests", version="2.31.0")],
    )
    finish_scan(session, second, status="succeeded")
    session.flush()

    remaining = session.execute(
        select(AssetComponent).where(AssetComponent.asset_id == asset.id)
    ).scalars().all()
    assert len(remaining) == 1


def test_ambiguous_identity_creates_a_candidate_and_never_a_silent_merge(session):
    a = _repo(session, "host-old")
    b = _repo(session, "host-reimaged")
    session.flush()

    flag_merge_candidate(session, asset=a, other=b, reason="same hardware UUID", confidence=0.8)
    flag_merge_candidate(session, asset=b, other=a, reason="same hardware UUID", confidence=0.8)
    session.flush()

    candidates = session.execute(select(MergeCandidate)).scalars().all()
    assert len(candidates) == 1, "the pair is recorded once, in a stable order"
    assert candidates[0].resolved_at is None

    both = session.execute(select(Asset).where(Asset.id.in_([a.id, b.id]))).scalars().all()
    assert len(both) == 2, "both assets still exist; nothing was merged"


def test_coverage_counts_never_scanned_assets_separately(session):
    scanned = _repo(session, "cov-scanned")
    run = start_scan(session, asset=scanned, kind="repository", tool="syft")
    finish_scan(session, run, status="succeeded")

    unscanned = _repo(session, "cov-unscanned")

    broken = _repo(session, "cov-broken")
    broken_run = start_scan(session, asset=broken, kind="repository", tool="syft")
    finish_scan(session, broken_run, status="failed", error="clone failed")
    session.flush()

    report = coverage(session)
    ids = {row["id"] for row in report["never_scanned"]}
    assert str(unscanned.id) in ids
    assert str(broken.id) in ids, "a failed scan leaves the asset unknown, not covered"
    assert str(scanned.id) not in ids
    assert report["inconclusive_scans_24h"] >= 1
    assert report["coverage_ratio"] < 1.0


def test_stale_assets_are_distinguished_from_fresh_ones(session):
    asset = _repo(session, "cov-stale")
    run = start_scan(session, asset=asset, kind="repository", tool="syft")
    finish_scan(session, run, status="succeeded")
    session.flush()

    assert is_stale(asset) is False
    assert is_stale(asset, now=datetime.now(UTC) + timedelta(days=30)) is True


def test_relationships_are_refreshed_not_duplicated(session):
    repo = _repo(session, "graph-repo")
    host, _ = register_asset(
        session, kind=AssetKind.HOST, identity_key="machine-id:abc", display_name="ubuntu-server"
    )
    session.flush()

    link(session, src=repo, dst=host, relation="runs_on")
    link(session, src=repo, dst=host, relation="runs_on", confidence=0.5)
    session.flush()

    edges = session.execute(
        select(AssetEdge).where(AssetEdge.src_id == repo.id, AssetEdge.dst_id == host.id)
    ).scalars().all()
    assert len(edges) == 1
    assert edges[0].confidence == 0.5


# ── classification ───────────────────────────────────────────────────────────


def test_literal_asset_routes_are_declared_before_the_parameterised_one():
    """`/assets/unclassified` must not be swallowed by `/assets/{asset_id}`.

    FastAPI matches in declaration order, so a literal path declared after a
    parameterised sibling is unreachable — and fails as a 404 for an asset named
    "unclassified" rather than as anything that looks like a routing mistake.
    """
    from athena.api.routers.assets import router

    paths = [r.path for r in router.routes]
    assert paths.index("/assets/unclassified") < paths.index("/assets/{asset_id}")


def test_family_groups_image_tags_together(session):
    from athena.api.routers.assets import _family
    from athena.db.models import Asset

    def image(name):
        return Asset(kind="image", identity_key=name, display_name=name)

    a = _family(image("storefront-web:20260819T063348Z-8583daf"))
    b = _family(image("storefront-web:latest"))
    c = _family(image("storefront-web@sha256:abc123"))
    d = _family(image("other-app:latest"))

    assert a[0] == b[0] == c[0], "tags and digests of one repository are one decision"
    assert a[1] == "storefront-web"
    assert d[0] != a[0]


def test_family_keeps_hosts_individual(session):
    from athena.api.routers.assets import _family
    from athena.db.models import Asset

    one = _family(Asset(kind="host", identity_key="h1", display_name="edge-proxy"))
    two = _family(Asset(kind="host", identity_key="h2", display_name="db-primary"))
    assert one[0] != two[0], "hosts carry their own consequence and are decided one by one"


# ── sandbox failure diagnosis ────────────────────────────────────────────────


def test_a_kill_is_reported_as_a_kill_not_a_number():
    """137 is SIGKILL, which from a memory-limited container means the OOM killer.

    It arrives with an empty stderr, so an unexplained "exit 137" is the least
    actionable failure this system can produce — two images failed on it every sweep
    for hours without anybody being able to tell why from the log line.
    """
    from athena.scanners.sandbox import SandboxResult

    assert "out of memory" in SandboxResult(exit_code=137, stdout="", stderr="").diagnosis
    assert SandboxResult(exit_code=0, stdout="", stderr="", timed_out=True).diagnosis == "timeout"
    assert "size limit" in SandboxResult(
        exit_code=0, stdout="", stderr="", truncated=True
    ).diagnosis
    assert SandboxResult(exit_code=2, stdout="", stderr="").diagnosis == "exit 2"


def test_image_scratch_removal_refuses_a_name_it_did_not_generate():
    """The removal runs `rm -rf` inside a container with the work volume mounted
    read-write. It only ever deletes names matching what this module creates."""
    from unittest.mock import patch

    from athena.scanners import syft

    with patch("athena.scanners.syft.run_sandboxed") as run:
        syft.remove_scratch("../../etc", work_volume="athena-work")
        syft.remove_scratch("imagescan-deadbeefcafe", work_volume="athena-work")

    assert run.call_count == 1, "a name outside the generated pattern was acted on"
    assert "imagescan-deadbeefcafe" in " ".join(run.call_args[0][0].command)
