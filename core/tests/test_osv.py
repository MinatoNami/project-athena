from __future__ import annotations

from athena.intel.osv import parse


def test_distribution_records_converge_on_the_cve():
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


def test_ubuntu_pro_ecosystems_are_marked_esm():
    advisory = parse(
        {
            "id": "UBUNTU-CVE-10",
            "affected": [{"package": {"name": "openssl", "ecosystem": "Ubuntu:Pro:18.04:LTS"},
                          "ranges": [{"type": "ECOSYSTEM",
                                      "events": [{"introduced": "0"},
                                                 {"fixed": "1.1.1-1ubuntu2.1~18.04.23+esm9"}]}]}],
        }
    )
    assert advisory.ranges[0].channel == "esm"


def test_an_esm_version_is_detected_without_a_pro_ecosystem():
    advisory = parse(
        {
            "id": "UBUNTU-CVE-11",
            "affected": [{"package": {"name": "7zip", "ecosystem": "Ubuntu:24.04:LTS"},
                          "ranges": [{"type": "ECOSYSTEM",
                                      "events": [{"introduced": "0"},
                                                 {"fixed": "23.01+dfsg-11ubuntu0.1~esm1"}]}]}],
        }
    )
    assert advisory.ranges[0].channel == "esm"
    assert advisory.ranges[0].distro_release == "24.04"


def test_an_ordinary_fix_is_the_standard_channel():
    advisory = parse(
        {
            "id": "UBUNTU-CVE-12",
            "affected": [{"package": {"name": "openssl", "ecosystem": "Ubuntu:24.04:LTS"},
                          "ranges": [{"type": "ECOSYSTEM",
                                      "events": [{"introduced": "0"},
                                                 {"fixed": "3.0.13-0ubuntu3.12"}]}]}],
        }
    )
    assert advisory.ranges[0].channel == "standard"


def test_two_records_for_one_cve_do_not_collide():
    shared = {
        "upstream": ["CVE-2013-6393"],
        "affected": [{"package": {"name": "libyaml", "ecosystem": "Ubuntu:24.04:LTS"},
                      "ranges": [{"type": "ECOSYSTEM",
                                  "events": [{"introduced": "0"}, {"fixed": "1.0"}]}]}],
    }
    first = parse({"id": "UBUNTU-CVE-2013-6393", **shared})
    second = parse({"id": "DEBIAN-CVE-2013-6393", **shared})
    assert first.id == second.id == "CVE-2013-6393"


def test_each_source_record_is_identified_separately():
    ubuntu = parse({
        "id": "UBUNTU-CVE-2014-3613",
        "upstream": ["CVE-2014-3613"],
        "affected": [{"package": {"name": "curl", "ecosystem": "Ubuntu:24.04:LTS"},
                      "ranges": [{"type": "ECOSYSTEM",
                                  "events": [{"introduced": "0"}, {"fixed": "8.5.0-1"}]}]}],
    })
    debian = parse({
        "id": "DEBIAN-CVE-2014-3613",
        "upstream": ["CVE-2014-3613"],
        "affected": [{"package": {"name": "curl", "ecosystem": "Debian:12"},
                      "ranges": [{"type": "ECOSYSTEM",
                                  "events": [{"introduced": "0"}, {"fixed": "7.88.1-1"}]}]}],
    })
    assert ubuntu.id == debian.id == "CVE-2014-3613"
    assert ubuntu.source_record == "UBUNTU-CVE-2014-3613"
    assert debian.source_record == "DEBIAN-CVE-2014-3613"
    from athena.intel.model import content_hash

    assert content_hash(ubuntu) != content_hash(debian)
