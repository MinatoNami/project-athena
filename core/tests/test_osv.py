"""OSV record translation."""

from __future__ import annotations

from athena.intel.osv import parse


def test_distribution_records_converge_on_the_cve():
    """Ubuntu puts the CVE in `upstream`, not `aliases`. Without reading it, the
    Ubuntu record and the upstream advisory for the same flaw stay two separate
    rows — and the authority rule never gets to compare their ranges."""
    advisory = parse(
        {
            "id": "UBUNTU-CVE-2014-3613",
            "upstream": ["CVE-2014-3613"],
            "related": ["USN-2346-1"],
            "severity": [{"type": "Ubuntu", "score": "medium"}],
            "affected": [
                {
                    "package": {"name": "curl", "ecosystem": "Ubuntu:24.04:LTS"},
                    "ranges": [{"type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}, {"fixed": "8.5.0-2ubuntu10.1"}]}],
                }
            ],
        }
    )
    assert advisory is not None
    assert advisory.id == "CVE-2014-3613"
    assert "UBUNTU-CVE-2014-3613" in advisory.aliases
    assert "USN-2346-1" in advisory.aliases


def test_distribution_severity_words_are_read():
    """Distro trackers ship a word, not a CVSS vector. Reading only the vector left
    every Ubuntu finding unlabelled."""
    advisory = parse(
        {
            "id": "UBUNTU-CVE-1",
            "severity": [{"type": "Ubuntu", "score": "medium"}],
            "affected": [{"package": {"name": "curl", "ecosystem": "Ubuntu:24.04"},
                          "ranges": [{"type": "ECOSYSTEM",
                                      "events": [{"introduced": "0"}, {"fixed": "1.0"}]}]}],
        }
    )
    assert advisory.severity == "medium"


def test_moderate_is_normalised_to_medium():
    advisory = parse(
        {
            "id": "X-1",
            "severity": [{"type": "Red Hat", "score": "moderate"}],
            "affected": [{"package": {"name": "curl", "ecosystem": "Red Hat:9"},
                          "ranges": [{"type": "ECOSYSTEM",
                                      "events": [{"introduced": "0"}, {"fixed": "1.0"}]}]}],
        }
    )
    assert advisory.severity == "medium"


def test_cvss_vector_is_preferred_over_a_word():
    advisory = parse(
        {
            "id": "GHSA-x",
            "aliases": ["CVE-2026-1"],
            "severity": [
                {"type": "Ubuntu", "score": "low"},
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            ],
            "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"},
                          "ranges": [{"type": "ECOSYSTEM",
                                      "events": [{"introduced": "0"}, {"fixed": "2.31.0"}]}]}],
        }
    )
    assert advisory.cvss_vector.startswith("CVSS:3.1/")
    assert advisory.severity == "low"


def test_the_distribution_release_is_kept():
    """A fix in 22.04 says nothing about 24.04, so the release must survive parsing."""
    advisory = parse(
        {
            "id": "UBUNTU-CVE-2",
            "affected": [{"package": {"name": "openssl", "ecosystem": "Ubuntu:22.04:LTS"},
                          "ranges": [{"type": "ECOSYSTEM",
                                      "events": [{"introduced": "0"},
                                                 {"fixed": "3.0.2-0ubuntu1.12"}]}]}],
        }
    )
    assert advisory.ranges[0].distro == "ubuntu"
    assert advisory.ranges[0].distro_release == "22.04"
    assert advisory.ranges[0].ecosystem == "deb"


def test_git_ranges_are_skipped():
    """A commit range cannot be compared against an installed package version."""
    advisory = parse(
        {
            "id": "GHSA-y",
            "affected": [{"package": {"name": "thing", "ecosystem": "Go"},
                          "ranges": [{"type": "GIT",
                                      "events": [{"introduced": "abc123"}]}]}],
        }
    )
    assert advisory is None, "an advisory with no comparable range yields nothing"


def test_esm_ecosystems_still_yield_a_release():
    """Ubuntu ESM advisories arrive as "Ubuntu:Pro:18.04:LTS". Taking the second
    segment yielded a release of "Pro", which matched no host — so every ESM range
    was silently inert."""
    advisory = parse(
        {
            "id": "UBUNTU-CVE-3",
            "affected": [{"package": {"name": "openssl", "ecosystem": "Ubuntu:Pro:18.04:LTS"},
                          "ranges": [{"type": "ECOSYSTEM",
                                      "events": [{"introduced": "0"},
                                                 {"fixed": "1.1.1-1ubuntu2.1~18.04.23+esm9"}]}]}],
        }
    )
    assert advisory.ranges[0].distro_release == "18.04"


def test_an_ecosystem_with_no_release_keeps_none():
    advisory = parse(
        {
            "id": "GHSA-z",
            "aliases": ["CVE-2026-9"],
            "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"},
                          "ranges": [{"type": "ECOSYSTEM",
                                      "events": [{"introduced": "0"}, {"fixed": "2.31.0"}]}]}],
        }
    )
    assert advisory.ranges[0].distro_release is None
