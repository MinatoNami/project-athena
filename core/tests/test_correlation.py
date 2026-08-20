"""Correlation behaviour.

M2's checkpoint calls the backport case "the single most important assertion in this
milestone": an Ubuntu package carrying a distro-patched version must not be reported
vulnerable because an upstream range says so. Getting it wrong produces a false
positive on every Ubuntu host in the estate.
"""

from __future__ import annotations

import pytest

from athena.correlation import MATCH_CONFIDENCE, evaluate
from athena.intel.authority import Authority


class FakeRange:
    """A stand-in for an AffectedRange row, so these stay pure unit tests."""

    def __init__(self, *, source, authority, introduced=None, fixed=None,
                 last_affected=None, range_id=1, distro_release=None):
        self.id = range_id
        self.source = source
        self.authority = int(authority)
        self.introduced = introduced
        self.fixed = fixed
        self.last_affected = last_affected
        self.distro_release = distro_release


# ── the backport rule ────────────────────────────────────────────────────────

def test_upstream_range_alone_cannot_condemn_a_distro_package():
    """Ubuntu ships the openssl fix as 3.0.13-0ubuntu3.12 while upstream's fixed
    version is 3.2.0. The upstream range says every 3.0.x is vulnerable; believing
    it would flag every patched Ubuntu host."""
    upstream_only = [
        FakeRange(source="osv", authority=Authority.UPSTREAM_ADVISORY,
                  introduced="0", fixed="3.2.0")
    ]
    affected, method, confidence, matched, rationale, conflicts = evaluate(
        ecosystem="deb", package="openssl", version="3.0.13-0ubuntu3.12",
        ranges=upstream_only,
    )

    assert affected is False, "an upstream range must not condemn a distro package"
    assert method == "none"
    assert confidence == 0.0
    assert "backport" in rationale.lower()
    # The disagreement is recorded, not discarded — an operator can still see it.
    assert conflicts and conflicts[0]["source"] == "osv"
    assert conflicts[0]["says"] == "affected"


def test_distro_tracker_decides_for_a_distro_package():
    ranges = [
        FakeRange(source="osv", authority=Authority.UPSTREAM_ADVISORY,
                  introduced="0", fixed="3.2.0"),
        FakeRange(source="ubuntu", authority=Authority.DISTRO_TRACKER,
                  introduced="0", fixed="3.0.13-0ubuntu3.12", range_id=2),
    ]

    patched = evaluate(ecosystem="deb", package="openssl",
                       version="3.0.13-0ubuntu3.12", ranges=ranges)
    assert patched[0] is False, "the distro says this revision carries the fix"

    vulnerable = evaluate(ecosystem="deb", package="openssl",
                          version="3.0.13-0ubuntu3.11", ranges=ranges)
    assert vulnerable[0] is True, "one revision earlier is genuinely affected"
    assert vulnerable[1] == "distro_advisory"
    assert vulnerable[2] == MATCH_CONFIDENCE["distro_advisory"]
    assert vulnerable[3].source == "ubuntu"


def test_ecosystem_packages_still_use_upstream_advisories():
    """The authority rule is about distributions. A PyPI package has no distro
    tracker, and an upstream advisory is exactly the right source."""
    ranges = [FakeRange(source="osv", authority=Authority.UPSTREAM_ADVISORY,
                        introduced="2.0.0", fixed="2.31.0")]
    affected, method, confidence, *_ = evaluate(
        ecosystem="pypi", package="requests", version="2.19.1", ranges=ranges
    )
    assert affected is True
    assert method == "purl_exact_range"
    assert confidence == MATCH_CONFIDENCE["purl_exact_range"]


# ── confidence ───────────────────────────────────────────────────────────────

def test_cpe_ranges_carry_lower_confidence_than_ecosystem_advisories():
    """CPE matching is coarse and frequently over-broad, so it must not look as
    trustworthy as an exact ecosystem match."""
    cpe = evaluate(
        ecosystem="pypi", package="requests", version="2.19.1",
        ranges=[FakeRange(source="nvd", authority=Authority.NVD_CPE,
                          introduced="0", fixed="2.31.0")],
    )
    assert cpe[0] is True
    assert cpe[1] == "cpe_range"
    assert cpe[2] < MATCH_CONFIDENCE["purl_exact_range"]


def test_heuristic_ecosystems_are_capped():
    ranges = [FakeRange(source="osv", authority=Authority.UPSTREAM_ADVISORY,
                        introduced="0", fixed="2.0")]
    affected, method, confidence, *_ = evaluate(
        ecosystem="maven", package="org.example:thing", version="1.5", ranges=ranges
    )
    assert affected is True
    assert method == "heuristic_range"
    assert confidence == MATCH_CONFIDENCE["heuristic_range"]


# ── uncertainty ──────────────────────────────────────────────────────────────

def test_an_uncomparable_version_is_uncertain_not_unaffected():
    """"We could not tell" must never be reported as "you are fine"."""
    ranges = [FakeRange(source="osv", authority=Authority.UPSTREAM_ADVISORY,
                        introduced="0", fixed="2.31.0")]
    affected, method, confidence, matched, rationale, _ = evaluate(
        ecosystem="pypi", package="requests", version="not-a-version", ranges=ranges
    )
    assert affected is False
    assert method == "uncomparable"
    assert confidence == MATCH_CONFIDENCE["uncomparable"]
    assert "uncertain" in rationale.lower()


def test_no_ranges_at_all_produces_no_match():
    affected, method, *_ = evaluate(
        ecosystem="pypi", package="requests", version="2.19.1", ranges=[]
    )
    assert affected is False
    assert method == "none"


# ── boundaries ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("version", "expected"),
    [("2.30.0", True), ("2.31.0", False), ("2.31.1", False), ("1.9.0", False)],
)
def test_fixed_version_boundary(version: str, expected: bool):
    ranges = [FakeRange(source="osv", authority=Authority.UPSTREAM_ADVISORY,
                        introduced="2.0.0", fixed="2.31.0")]
    affected, *_ = evaluate(
        ecosystem="pypi", package="requests", version=version, ranges=ranges
    )
    assert affected is expected


def test_package_name_normalisation_is_applied_in_the_rationale():
    ranges = [FakeRange(source="osv", authority=Authority.UPSTREAM_ADVISORY,
                        introduced="0", fixed="3.0.0")]
    _, _, _, _, rationale, _ = evaluate(
        ecosystem="pypi", package="Flask_SQLAlchemy", version="2.5.1", ranges=ranges
    )
    assert "flask-sqlalchemy" in rationale


# ── distribution release ─────────────────────────────────────────────────────

def test_a_fix_in_another_release_does_not_clear_this_host():
    """OSV returns ranges for every supported Ubuntu release under one package.
    Ubuntu 22.04 fixed openssl in 3.0.2-0ubuntu1.12 and 24.04 in 3.0.13-0ubuntu3.12.
    Comparing a 24.04 host against the 22.04 range makes a vulnerable host look
    patched, because 3.0.13 sorts above 3.0.2."""
    ranges = [
        FakeRange(source="ubuntu", authority=Authority.DISTRO_TRACKER,
                  introduced="0", fixed="3.0.2-0ubuntu1.12"),
        FakeRange(source="ubuntu", authority=Authority.DISTRO_TRACKER,
                  introduced="0", fixed="3.0.13-0ubuntu3.12", range_id=2),
    ]
    ranges[0].distro_release = "22.04"
    ranges[1].distro_release = "24.04"

    affected, method, _, matched, *_ = evaluate(
        ecosystem="deb", package="openssl", version="3.0.13-0ubuntu3.11",
        ranges=ranges, distro_release="24.04",
    )
    assert affected is True, "the 24.04 host is behind the 24.04 fix"
    assert matched.distro_release == "24.04", "the wrong release must not be used"


def test_the_matching_release_can_clear_a_host():
    ranges = [
        FakeRange(source="ubuntu", authority=Authority.DISTRO_TRACKER,
                  introduced="0", fixed="3.0.13-0ubuntu3.12"),
    ]
    ranges[0].distro_release = "24.04"
    affected, *_ = evaluate(
        ecosystem="deb", package="openssl", version="3.0.13-0ubuntu3.12",
        ranges=ranges, distro_release="24.04",
    )
    assert affected is False


def test_an_unknown_release_is_a_gap_not_a_guess():
    """Matching a host of unknown release against release-specific ranges would be
    guessing. The gap is recorded instead."""
    ranges = [
        FakeRange(source="ubuntu", authority=Authority.DISTRO_TRACKER,
                  introduced="0", fixed="3.0.13-0ubuntu3.12"),
    ]
    ranges[0].distro_release = "24.04"
    affected, method, _, _, _, conflicts = evaluate(
        ecosystem="deb", package="openssl", version="3.0.13-0ubuntu3.11",
        ranges=ranges, distro_release=None,
    )
    assert affected is False
    assert any(c.get("says") == "unknown" for c in conflicts)


def test_release_agnostic_ranges_still_apply():
    ranges = [
        FakeRange(source="ubuntu", authority=Authority.DISTRO_TRACKER,
                  introduced="0", fixed="3.0.13-0ubuntu3.12"),
    ]
    ranges[0].distro_release = None
    affected, *_ = evaluate(
        ecosystem="deb", package="openssl", version="3.0.13-0ubuntu3.11",
        ranges=ranges, distro_release=None,
    )
    assert affected is True
