from __future__ import annotations

import pytest

from athena.inventory.purl import build_purl, normalise_name, parse_purl


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Flask_SQLAlchemy", "flask-sqlalchemy"),
        ("flask.sqlalchemy", "flask-sqlalchemy"),
        ("Flask--SQLAlchemy", "flask-sqlalchemy"),
        ("zope.interface", "zope-interface"),
    ],
)
def test_pypi_names_follow_pep503(raw: str, expected: str) -> None:
    """PyPI treats -, _, and . as equivalent. Missing this silently loses matches."""
    assert normalise_name("pypi", raw) == expected


def test_go_module_paths_stay_case_sensitive() -> None:
    assert normalise_name("golang", "github.com/Masterminds/semver") == (
        "github.com/Masterminds/semver"
    )


def test_purl_round_trips() -> None:
    purl = build_purl("pypi", "Requests", "2.31.0")
    assert purl == "pkg:pypi/requests@2.31.0"
    assert parse_purl(purl) == {"ecosystem": "pypi", "name": "requests", "version": "2.31.0"}


def test_npm_scope_becomes_a_namespace() -> None:
    assert build_purl("npm", "@nuxt/kit", "4.0.0") == "pkg:npm/@nuxt/kit@4.0.0"


def test_qualifiers_are_ordered_so_the_purl_is_stable() -> None:
    """The PURL is a lookup key; an unstable rendering would fragment the index."""
    a = build_purl(
        "deb", "openssl", "3.0.2", qualifiers={"distro": "ubuntu-24.04", "arch": "amd64"}
    )
    b = build_purl(
        "deb", "openssl", "3.0.2", qualifiers={"arch": "amd64", "distro": "ubuntu-24.04"}
    )
    assert a == b
    assert a == "pkg:deb/openssl@3.0.2?arch=amd64&distro=ubuntu-24.04"


def test_version_is_never_dropped() -> None:
    assert parse_purl("pkg:npm/left-pad") is None
