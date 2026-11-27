from __future__ import annotations

import pytest

from athena.api.routers.assets import _scan_offer
from athena.db.models import Asset, Node


class _Result:
    def __init__(self, node: Node | None) -> None:
        self._node = node

    def scalars(self) -> _Result:
        return self

    def first(self) -> Node | None:
        return self._node


class _Session:
    def __init__(self, node: Node | None = None) -> None:
        self._node = node

    def execute(self, _statement: object) -> _Result:
        return _Result(self._node)


def _asset(kind: str, **attributes: str) -> Asset:
    if kind == "image" and not attributes:
        attributes = {"repository": "ghcr.io/acme/api", "tag": "1.4"}
    return Asset(kind=kind, identity_key=f"{kind}:1", display_name=kind, attributes=attributes)


@pytest.mark.parametrize(
    "attributes",
    [
        {"repository": "<none>", "tag": "<none>", "digest": "sha256:abc"},
        {"repository": "ghcr.io/acme/api", "tag": "<none>"},
    ],
)
def test_an_image_the_worker_would_refuse_is_not_offered(attributes: dict[str, str]) -> None:
    offer = _scan_offer(_Session(), _asset("image", **attributes))
    assert offer.action is None
    assert offer.reason and "cannot locate it" in offer.reason


def test_an_image_known_only_by_digest_is_still_offered() -> None:
    offer = _scan_offer(
        _Session(), _asset("image", repository="ghcr.io/acme/api", digest="sha256:abc")
    )
    assert offer.action == "scan.image"


@pytest.mark.parametrize(
    ("kind", "action"),
    [("repository", "scan.repository"), ("image", "scan.image")],
)
def test_scannable_kinds_name_their_job(kind: str, action: str) -> None:
    offer = _scan_offer(_Session(), _asset(kind))
    assert offer.action == action
    assert offer.reason is None


def test_a_host_collects_from_its_node() -> None:
    node = Node(display_name="a-host", public_key=b"k")
    offer = _scan_offer(_Session(node), _asset("host"))
    assert offer.action == "collect"
    assert offer.node is node


def test_a_host_with_no_node_says_so_rather_than_offering() -> None:
    offer = _scan_offer(_Session(None), _asset("host"))
    assert offer.action is None
    assert "no node is enrolled" in (offer.reason or "").lower()


@pytest.mark.parametrize("kind", ["container", "service", "network_host"])
def test_kinds_without_a_scan_give_a_reason(kind: str) -> None:
    offer = _scan_offer(_Session(), _asset(kind))
    assert offer.action is None
    assert offer.reason
    assert offer.as_json() == {"supported": False, "action": None, "reason": offer.reason}
