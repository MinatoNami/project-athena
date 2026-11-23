"""What the Rescan button is allowed to promise.

The page and the endpoint both read `_scan_offer`: one decides whether to offer the
button, the other decides what pressing it runs. The failure this guards against is
not a crash — it is the button being offered for an asset nothing can scan, which is
how it behaved for every kind except `repository`, silently swallowing the 422.
"""

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
    """Enough session to answer "is a node enrolled for this host?".

    The rule under test is a decision, not a query, and the suite's real sessions
    need Postgres — which would make this skip on the machines where the button is
    actually being changed.
    """

    def __init__(self, node: Node | None = None) -> None:
        self._node = node

    def execute(self, _statement: object) -> _Result:
        return _Result(self._node)


def _asset(kind: str) -> Asset:
    return Asset(kind=kind, identity_key=f"{kind}:1", display_name=kind, attributes={})


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
    """Silence reads as a broken button; these are covered another way, or not at all."""
    offer = _scan_offer(_Session(), _asset(kind))
    assert offer.action is None
    assert offer.reason
    assert offer.as_json() == {"supported": False, "action": None, "reason": offer.reason}
