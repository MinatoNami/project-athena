"""Deriving classification from the asset graph.

165 of 192 live assets carried neither a tier nor an exposure, so every finding on
them scored against a placeholder. Most of that is not a judgement anybody needs to
make — a container on the production host is production — and the property under test
is that the derivable part is derived without the guessable part being guessed.
"""

from __future__ import annotations

from athena.db.models import AssetEdge
from athena.inventory.classify import derive, mark_operator
from athena.inventory.identity import AssetKind
from athena.inventory.service import link, register_asset


def _asset(session, kind, name, **kw):
    a, _ = register_asset(
        session, kind=kind, identity_key=f"{kind}:{name}", display_name=name, **kw
    )
    return a


def _host(session, name="alena-server", tier="production"):
    return _asset(session, AssetKind.HOST, name, tier=tier)


# ── tier flows from where a thing runs ───────────────────────────────────────


def test_a_container_takes_the_tier_of_its_host(session):
    """An ownership fact, not a security opinion. Asking a person to confirm it 73
    times is how a classification queue stops being used."""
    host = _host(session)
    container = _asset(session, AssetKind.CONTAINER, "athena-api-1")
    link(session, src=container, dst=host, relation="runs_on")
    session.flush()

    derive(session)
    assert container.tier == "production"
    assert "alena-server" in container.attributes["classification"]["tier"]


def test_an_image_takes_the_tier_of_the_worst_place_it_runs(session):
    """The consequence of a flaw in an image is the consequence of the worst place
    that image runs, not the average of them."""
    prod, dev = _host(session), _host(session, "laptop", tier="development")
    image = _asset(session, AssetKind.IMAGE, "athena-core:dev")
    for name, host in (("c-prod", prod), ("c-dev", dev)):
        c = _asset(session, AssetKind.CONTAINER, name)
        link(session, src=c, dst=host, relation="runs_on")
        link(session, src=c, dst=image, relation="built_from")
    session.flush()

    derive(session)
    assert image.tier == "production"


def test_an_image_nothing_runs_stays_unknown(session):
    """Nothing is derived from absence. An image no container uses is unclassified,
    not safe."""
    image = _asset(session, AssetKind.IMAGE, "postgres:16-alpine")
    session.flush()
    derive(session)
    assert image.tier == "unknown"
    assert "tier" not in (image.attributes.get("classification") or {})


def test_an_unclassified_sibling_does_not_drag_a_classified_one_down(session):
    """Unknown sits at the bottom of the ordering so it can never win a comparison."""
    prod = _host(session)
    image = _asset(session, AssetKind.IMAGE, "web:1")
    known = _asset(session, AssetKind.CONTAINER, "known")
    link(session, src=known, dst=prod, relation="runs_on")
    link(session, src=known, dst=image, relation="built_from")
    orphan = _asset(session, AssetKind.CONTAINER, "orphan")   # no host, stays unknown
    link(session, src=orphan, dst=image, relation="built_from")
    session.flush()

    derive(session)
    assert image.tier == "production"


# ── exposure comes from observation, or not at all ───────────────────────────


def test_a_hosts_exposure_comes_from_the_sockets_it_was_seen_listening_on(session):
    """Direct evidence, not inference — the agent observed them."""
    host = _host(session)
    for name, exposure in (("sshd tcp/22", "internal"), ("pg tcp/5432", "isolated")):
        svc = _asset(session, AssetKind.SERVICE, name)
        svc.exposure = exposure
        link(session, src=svc, dst=host, relation="runs_on")
    session.flush()

    derive(session)
    assert host.exposure == "internal"
    assert "1 of 2" in host.attributes["classification"]["exposure"]


def test_a_host_with_only_loopback_services_is_isolated_on_the_evidence(session):
    host = _host(session)
    svc = _asset(session, AssetKind.SERVICE, "pg tcp/5432")
    svc.exposure = "isolated"
    link(session, src=svc, dst=host, relation="runs_on")
    session.flush()

    derive(session)
    assert host.exposure == "isolated"
    assert "loopback-only" in host.attributes["classification"]["exposure"]


def test_a_host_with_no_observed_services_stays_unknown(session):
    """Seeing nothing is not evidence of safety, and unknown is weighted above
    internal precisely so that this case is not quietly discounted."""
    host = _host(session)
    session.flush()
    derive(session)
    assert host.exposure == "unknown"


def test_exposure_is_never_derived_for_containers_or_images(session):
    """Left to a person on purpose. A container bound to loopback may still be
    reached through a reverse proxy on the same host, and this estate runs one — so
    inferring isolation from a bind address would be wrong in exactly the case that
    matters."""
    host = _host(session)
    image = _asset(session, AssetKind.IMAGE, "web:1")
    c = _asset(session, AssetKind.CONTAINER, "web-1")
    link(session, src=c, dst=host, relation="runs_on")
    link(session, src=c, dst=image, relation="built_from")
    svc = _asset(session, AssetKind.SERVICE, "tcp/443")
    svc.exposure = "internal"
    link(session, src=svc, dst=host, relation="runs_on")
    session.flush()

    derive(session)
    assert c.exposure == "unknown"
    assert image.exposure == "unknown"


# ── a person's decision is final ─────────────────────────────────────────────


def test_a_derivation_never_overwrites_what_a_person_decided(session):
    host = _host(session)
    container = _asset(session, AssetKind.CONTAINER, "scratch-box")
    link(session, src=container, dst=host, relation="runs_on")
    session.flush()

    container.tier = "development"
    mark_operator(container, "tier")
    derive(session)

    assert container.tier == "development"
    assert container.attributes["classification"]["tier"] == "operator"


def test_running_the_pass_twice_changes_nothing_the_second_time(session):
    host = _host(session)
    container = _asset(session, AssetKind.CONTAINER, "athena-api-1")
    link(session, src=container, dst=host, relation="runs_on")
    session.flush()

    first = derive(session)
    second = derive(session)
    assert first["container_tier"] == 1
    assert second == {"host_exposure": 0, "container_tier": 0, "image_tier": 0}


def test_a_retired_asset_takes_no_part(session):
    """A tombstoned container must not go on conferring a tier on an image."""
    from datetime import UTC, datetime

    host = _host(session)
    image = _asset(session, AssetKind.IMAGE, "web:1")
    c = _asset(session, AssetKind.CONTAINER, "gone")
    link(session, src=c, dst=host, relation="runs_on")
    link(session, src=c, dst=image, relation="built_from")
    session.flush()
    derive(session)
    assert image.tier == "production"

    c.tombstoned_at = datetime.now(UTC)
    image.tier = "unknown"
    image.attributes = {k: v for k, v in image.attributes.items() if k != "classification"}
    session.flush()
    derive(session)
    assert image.tier == "unknown"


def test_edges_are_read_but_never_written(session):
    """Classification reads the graph. Anything that changed it would be a second
    place edges come from."""
    host = _host(session)
    c = _asset(session, AssetKind.CONTAINER, "athena-api-1")
    link(session, src=c, dst=host, relation="runs_on")
    session.flush()
    before = session.query(AssetEdge).count()
    derive(session)
    assert session.query(AssetEdge).count() == before


# ── the evidence handed to whoever decides exposure ──────────────────────────


def test_the_evidence_names_what_runs_an_image_and_what_it_publishes(session):
    """The question left open is exposure, and answering it means knowing what runs
    the image, where, and what it publishes. Three joins the browser should not have
    to make to answer one question."""
    from athena.api.routers.assets import _exposure_evidence

    host = _host(session)
    image = _asset(session, AssetKind.IMAGE, "athena-web:dev")
    c = _asset(session, AssetKind.CONTAINER, "athena-web-1")
    c.attributes = {**c.attributes, "published_ports": "127.0.0.1:8099->3000/tcp"}
    link(session, src=c, dst=host, relation="runs_on")
    link(session, src=c, dst=image, relation="built_from")
    session.flush()

    line = _exposure_evidence(session, [image])[image.id][0]
    assert "athena-web-1 on alena-server" in line
    assert "publishing 127.0.0.1:8099->3000/tcp" in line


def test_an_agent_that_never_reported_ports_is_not_read_as_publishing_none(session):
    """"We did not ask" and "nothing is exposed" are different facts, and only one of
    them is a reason to relax."""
    from athena.api.routers.assets import _exposure_evidence

    host = _host(session)
    image = _asset(session, AssetKind.IMAGE, "old:1")
    c = _asset(session, AssetKind.CONTAINER, "old-1")     # no published_ports key
    link(session, src=c, dst=host, relation="runs_on")
    link(session, src=c, dst=image, relation="built_from")
    session.flush()

    line = _exposure_evidence(session, [image])[image.id][0]
    assert "not reported" in line
    assert "publishing no ports" not in line


def test_a_container_publishing_nothing_says_so_plainly(session):
    from athena.api.routers.assets import _exposure_evidence

    host = _host(session)
    image = _asset(session, AssetKind.IMAGE, "worker:1")
    c = _asset(session, AssetKind.CONTAINER, "worker-1")
    c.attributes = {**c.attributes, "published_ports": ""}
    link(session, src=c, dst=host, relation="runs_on")
    link(session, src=c, dst=image, relation="built_from")
    session.flush()

    assert "publishing no ports" in _exposure_evidence(session, [image])[image.id][0]


def test_a_host_speaks_for_itself(session):
    """Its own listening sockets were observed directly — no inference involved."""
    from athena.api.routers.assets import _exposure_evidence

    host = _host(session)
    for name, exposure in (("sshd tcp/22", "internal"), ("pg tcp/5432", "isolated")):
        svc = _asset(session, AssetKind.SERVICE, name)
        svc.exposure = exposure
        link(session, src=svc, dst=host, relation="runs_on")
    session.flush()

    line = _exposure_evidence(session, [host])[host.id][0]
    assert "1 of 2 listening services" in line and "sshd tcp/22" in line
