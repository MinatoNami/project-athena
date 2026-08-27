"""Host observation ingestion."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from athena.workers.node_ingest import _distro_release, _process_name


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        ({"os_id": "ubuntu", "os_version_id": "24.04"}, ("ubuntu", "24.04")),
        # An agent predating os_id/os_version_id reports only the pretty name.
        # Deriving both keeps it correlatable rather than leaving the distribution
        # unknown, which silently disables distro-specific matching.
        ({"os_version": "Ubuntu 24.04.4 LTS"}, ("ubuntu", "24.04")),
        ({"os_version": "Debian GNU/Linux 12 (bookworm)"}, ("debian", None)),
        ({}, (None, None)),
    ],
)
def test_distro_and_release_are_derived(data: dict, expected: tuple):
    assert _distro_release(data) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ('users:(("sshd",pid=123,fd=3))', "sshd"),
        ('users:(("navgraph_visual",pid=78092,fd=44))', "navgraph_visual"),
        # An unprivileged agent cannot see other users' socket owners. Unknown is
        # recorded rather than guessed at.
        (None, None),
        ("", None),
        ("users:(())", None),
    ],
)
def test_process_names_are_extracted_from_ss_output(raw, expected):
    assert _process_name(raw) == expected


# ── services that stop listening ─────────────────────────────────────────────


def _ports_payload(*ports):
    return [{"port": p, "protocol": "tcp", "address": "0.0.0.0"} for p in ports]


def _host_for_ports(session):
    from athena.inventory.identity import AssetKind
    from athena.inventory.service import register_asset

    host, _ = register_asset(
        session, kind=AssetKind.HOST, identity_key=f"host:{uuid.uuid4()}",
        display_name="box",
    )
    session.flush()
    return host


def _live_services(session, host):
    from athena.db.models import Asset, AssetEdge
    from athena.inventory.identity import AssetKind

    return session.execute(
        select(Asset)
        .join(AssetEdge, AssetEdge.src_id == Asset.id)
        .where(
            AssetEdge.dst_id == host.id,
            Asset.kind == AssetKind.SERVICE,
            Asset.tombstoned_at.is_(None),
        )
    ).scalars().all()


def test_a_service_that_stops_listening_is_retired(session):
    """The agent reports its whole listening set, so anything absent has gone.

    Without this every socket that ever existed stays forever: 190 of 227 services
    on the development host were ephemeral high ports seen once, six days earlier.
    """
    from athena.workers.node_ingest import _ports

    host = _host_for_ports(session)
    _ports(session, asset=host, data=_ports_payload(22, 443, 32769))
    session.flush()
    assert len(_live_services(session, host)) == 3

    # The ephemeral one is gone on the next collection.
    outcome = _ports(session, asset=host, data=_ports_payload(22, 443))
    session.flush()
    assert outcome["retired"] == 1
    assert {a.attributes["port"] for a in _live_services(session, host)} == {22, 443}


def test_an_empty_report_retires_nothing(session):
    """A host with nothing listening at all is far less likely than a collection
    that failed, and acting on it would retire the whole host in one pass."""
    from athena.workers.node_ingest import _ports

    host = _host_for_ports(session)
    _ports(session, asset=host, data=_ports_payload(22, 443))
    session.flush()

    outcome = _ports(session, asset=host, data=[])
    session.flush()
    assert outcome["retired"] == 0
    assert len(_live_services(session, host)) == 2


def test_a_service_that_comes_back_is_revived(session):
    """A restart is not a disappearance. Observing a tombstoned asset again clears
    the tombstone, or one blip would remove it permanently."""
    from athena.workers.node_ingest import _ports

    host = _host_for_ports(session)
    _ports(session, asset=host, data=_ports_payload(22, 5432))
    session.flush()
    _ports(session, asset=host, data=_ports_payload(22))
    session.flush()
    assert {a.attributes["port"] for a in _live_services(session, host)} == {22}

    _ports(session, asset=host, data=_ports_payload(22, 5432))
    session.flush()
    assert {a.attributes["port"] for a in _live_services(session, host)} == {22, 5432}


def test_retiring_one_host_leaves_another_alone(session):
    """Services are scoped to the host that reports them."""
    from athena.workers.node_ingest import _ports

    a, b = _host_for_ports(session), _host_for_ports(session)
    _ports(session, asset=a, data=_ports_payload(8080))
    _ports(session, asset=b, data=_ports_payload(8080))
    session.flush()

    _ports(session, asset=a, data=_ports_payload(22))
    session.flush()
    assert len(_live_services(session, b)) == 1, "another host's services were retired"


# ── container to image linking ───────────────────────────────────────────────


def test_a_bare_image_name_resolves_the_way_docker_resolves_it():
    """`docker ps` prints what the container was created with, so one started from
    `hello-world` reports that while the image is inventoried as `hello-world:latest`.
    Docker treats them as the same thing; without this the container looks like it
    came from nowhere and its packages go uncounted."""
    from athena.workers.node_ingest import _normalise_image_ref

    assert _normalise_image_ref("hello-world") == "hello-world:latest"
    assert _normalise_image_ref("ghcr.io/org/app") == "ghcr.io/org/app:latest"


def test_an_existing_tag_or_digest_is_left_alone():
    from athena.workers.node_ingest import _normalise_image_ref

    assert _normalise_image_ref("app:2026.3") == "app:2026.3"
    assert _normalise_image_ref("app@sha256:abc") == "app@sha256:abc"
    # A registry with a port is not a tag.
    assert _normalise_image_ref("registry:5000/app:1") == "registry:5000/app:1"


def test_an_image_id_is_not_given_a_tag():
    """Appending :latest to an ID would invent a repository that does not exist. A
    container reporting an ID genuinely has no tagged image to point at."""
    from athena.workers.node_ingest import _normalise_image_ref

    assert _normalise_image_ref("a2b225992301") == "a2b225992301"
    assert _normalise_image_ref("9e4b9e7517a6") == "9e4b9e7517a6"
    assert _normalise_image_ref("a" * 64) == "a" * 64


def test_an_empty_reference_stays_empty():
    from athena.workers.node_ingest import _normalise_image_ref

    assert _normalise_image_ref("") == ""
    assert _normalise_image_ref(None) == ""
