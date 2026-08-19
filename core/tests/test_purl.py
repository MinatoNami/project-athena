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


# --- Syft output shapes ------------------------------------------------------


def test_syft_cpes_are_accepted_as_strings_or_objects() -> None:
    """Syft has emitted both shapes across versions. Assuming one of them put a dict
    into a SQL parameter and failed every repository scan."""
    from athena.scanners.syft import _first_cpe

    cpe = "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"
    assert _first_cpe({"cpes": [cpe]}) == cpe
    assert _first_cpe({"cpes": [{"cpe": cpe, "source": "nvd"}]}) == cpe
    assert _first_cpe({"cpes": []}) is None
    assert _first_cpe({}) is None
    assert _first_cpe({"cpes": [{"unexpected": "shape"}, 42]}) is None


def test_unmapped_ecosystems_are_a_note_not_an_incomplete_scan() -> None:
    """An ecosystem Athena cannot map is a known limitation. Recording it as a gap
    would leave every repository with GitHub Actions permanently stale."""
    from athena.scanners.syft import parse

    components, warnings, notes = parse(
        {
            "artifacts": [
                {"id": "a", "name": "actions/checkout", "version": "v4", "type": "github-action"},
                {"id": "b", "name": "weird", "version": "1.0", "type": "not-a-real-type"},
            ],
            "artifactRelationships": [],
        }
    )
    assert len(components) == 2
    assert warnings == [], "a fully-resolved component is not a gap"
    assert any("not-a-real-type" in n for n in notes)


def test_syft_artifacts_without_a_version_are_reported_not_silently_kept() -> None:
    """A component with no version cannot be matched against an advisory range, so
    recording it as usable would overstate what we know."""
    from athena.scanners.syft import parse

    components, warnings, _notes = parse(
        {
            "artifacts": [
                {"id": "a", "name": "requests", "version": "2.31.0", "type": "python"},
                {"id": "b", "name": "mystery", "version": "", "type": "python"},
            ],
            "artifactRelationships": [],
        }
    )
    assert [c.name for c in components] == ["requests"]
    assert any("mystery" in w for w in warnings)


def test_scope_is_unknown_when_the_sbom_carries_no_dependency_edges() -> None:
    """Guessing direct-vs-transitive is worse than admitting we do not know: the
    distinction decides whether a fix is even possible where the finding appears."""
    from athena.scanners.syft import parse

    components, warnings, notes = parse(
        {
            "artifacts": [
                {"id": "a", "name": "requests", "version": "2.19.1", "type": "python"},
                {"id": "b", "name": "urllib3", "version": "1.24.1", "type": "python"},
            ],
            # Syft emits `contains` for file locations. It is not a dependency edge,
            # and treating it as one marked every declared package transitive.
            "artifactRelationships": [
                {"parent": "src", "child": "a", "type": "contains"},
                {"parent": "src", "child": "b", "type": "contains"},
            ],
        }
    )
    assert {c.scope for c in components} == {"unknown"}
    assert any("cannot be distinguished" in n for n in notes)
    assert warnings == []


def test_direct_and_transitive_are_distinguished_when_the_sbom_says_so() -> None:
    from athena.scanners.syft import parse

    components, _, _ = parse(
        {
            "artifacts": [
                {"id": "app", "name": "requests", "version": "2.31.0", "type": "python"},
                {"id": "dep", "name": "urllib3", "version": "2.0.0", "type": "python"},
            ],
            "artifactRelationships": [
                {"parent": "app", "child": "dep", "type": "dependency-of"},
            ],
        }
    )
    scopes = {c.name: c.scope for c in components}
    assert scopes == {"requests": "direct", "urllib3": "transitive"}
