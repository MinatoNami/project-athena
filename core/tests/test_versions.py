"""Version ordering.

A comparator bug produces confident nonsense at scale: every "you are affected" and
every "you are patched" rests on these functions. Vectors are taken from each
ecosystem's own specification rather than invented.
"""

from __future__ import annotations

import pytest

from athena.versions import compare, in_affected_range
from athena.versions.compare import UncomparableVersions, UnknownEcosystem

# ── PEP 440 (PyPI) ───────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("1.0", "1.1"),
        ("1.9", "1.10"),                 # numeric, not lexical
        ("1.0.dev1", "1.0a1"),           # dev sorts below every pre-release
        ("1.0a1", "1.0b1"),
        ("1.0b1", "1.0rc1"),
        ("1.0rc1", "1.0"),               # pre-release sorts below the release
        ("1.0", "1.0.post1"),            # post sorts above the release
        ("1.0.post1", "1.1"),
        ("1.0", "1!0.1"),                # epoch dominates everything
        ("2.0", "10.0"),
        ("1.0.dev1", "1.0.dev2"),
    ],
)
def test_pep440_ordering(lower: str, higher: str) -> None:
    assert compare("pypi", lower, higher) == -1, f"{lower} should sort below {higher}"
    assert compare("pypi", higher, lower) == 1


@pytest.mark.parametrize(
    ("a", "b"),
    [("1.0", "1.0.0"), ("1.0", "1.0.0.0"), ("1.0rc1", "1.0.rc1"), ("1.0", "v1.0")],
)
def test_pep440_equivalent_spellings(a: str, b: str) -> None:
    """Trailing zeros and separator style are not significant. Treating them as
    different would fragment the component index."""
    assert compare("pypi", a, b) == 0


# ── Debian / Ubuntu ──────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("1.0", "1.1"),
        ("1.9", "1.10"),
        ("1.0~rc1", "1.0"),                       # tilde sorts below the empty string
        ("1.0~beta1", "1.0~rc1"),
        ("1.0", "1.0-1"),                         # a revision outranks none
        ("1.0-1", "1.0-2"),
        ("1.0-1", "1:0.9"),                       # epoch dominates
        ("1:1.0", "2:0.1"),
        ("3.0.13-0ubuntu3.11", "3.0.13-0ubuntu3.12"),   # the Ubuntu security bump
        ("1.9.15p5-3ubuntu5", "1.9.15p5-3ubuntu5.24.04.2"),
        ("2.39-0ubuntu8.7", "2.39-0ubuntu8.8"),
        ("1.0a", "1.0+"),                         # letters sort below non-letters
    ],
)
def test_debian_ordering(lower: str, higher: str) -> None:
    assert compare("deb", lower, higher) == -1, f"{lower} should sort below {higher}"
    assert compare("deb", higher, lower) == 1


@pytest.mark.parametrize(("a", "b"), [("1.0", "1.0"), ("0:1.0", "1.0"), ("1.0-0", "1.0-0")])
def test_debian_equality(a: str, b: str) -> None:
    assert compare("deb", a, b) == 0


# ── SemVer (npm, Go, Cargo) ──────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("1.0.0", "1.0.1"),
        ("1.0.9", "1.0.10"),
        ("1.0.0-alpha", "1.0.0-alpha.1"),         # a longer chain outranks its prefix
        ("1.0.0-alpha.1", "1.0.0-alpha.beta"),    # numeric ranks below alphanumeric
        ("1.0.0-alpha.beta", "1.0.0-beta"),
        ("1.0.0-beta.2", "1.0.0-beta.11"),        # numeric identifiers compare as numbers
        ("1.0.0-rc.1", "1.0.0"),
        ("1.9.0", "1.10.0"),
    ],
)
def test_semver_ordering(lower: str, higher: str) -> None:
    assert compare("npm", lower, higher) == -1, f"{lower} should sort below {higher}"
    assert compare("npm", higher, lower) == 1


def test_semver_ignores_build_metadata() -> None:
    """SemVer §10: build metadata has no bearing on precedence."""
    assert compare("npm", "1.0.0+build.1", "1.0.0+build.2") == 0
    assert compare("npm", "1.0.0", "1.0.0+anything") == 0


# ── RPM ──────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("1.0", "1.1"),
        ("1.0-1", "1.0-2"),
        ("1.0~rc1", "1.0"),
        ("1.0", "1.0^post"),      # caret sorts above, unlike tilde
        ("1.0", "2:0.9"),
        ("1.a", "1.1"),           # numeric outranks alphabetic
    ],
)
def test_rpm_ordering(lower: str, higher: str) -> None:
    assert compare("rpm", lower, higher) == -1, f"{lower} should sort below {higher}"


# ── range evaluation ─────────────────────────────────────────────────────────

def test_fixed_bound_is_exclusive() -> None:
    """The version that carries the fix is not itself vulnerable."""
    assert in_affected_range("pypi", "2.30.0", introduced="2.0.0", fixed="2.31.0") is True
    assert in_affected_range("pypi", "2.31.0", introduced="2.0.0", fixed="2.31.0") is False
    assert in_affected_range("pypi", "2.32.0", introduced="2.0.0", fixed="2.31.0") is False


def test_last_affected_bound_is_inclusive() -> None:
    assert in_affected_range("npm", "1.2.3", last_affected="1.2.3") is True
    assert in_affected_range("npm", "1.2.4", last_affected="1.2.3") is False


def test_versions_below_introduced_are_unaffected() -> None:
    assert in_affected_range("pypi", "1.9.0", introduced="2.0.0", fixed="2.5.0") is False


def test_introduced_zero_means_all_earlier_versions() -> None:
    assert in_affected_range("npm", "0.0.1", introduced="0", fixed="1.0.0") is True


def test_a_range_with_no_upper_bound_affects_everything_after_introduced() -> None:
    assert in_affected_range("pypi", "99.0", introduced="1.0") is True


def test_ubuntu_security_update_takes_a_package_out_of_range() -> None:
    """The distro case that matters: the fix ships as a revision bump, not an
    upstream version change. Comparing only the upstream part would report every
    patched Ubuntu host as still vulnerable."""
    assert in_affected_range(
        "deb", "3.0.13-0ubuntu3.11", introduced="0", fixed="3.0.13-0ubuntu3.12"
    ) is True
    assert in_affected_range(
        "deb", "3.0.13-0ubuntu3.12", introduced="0", fixed="3.0.13-0ubuntu3.12"
    ) is False


# ── failure behaviour ────────────────────────────────────────────────────────

def test_an_unparseable_version_raises_rather_than_reporting_not_affected() -> None:
    """"We could not tell" and "not affected" are different answers. Collapsing them
    would silently under-report."""
    with pytest.raises(UncomparableVersions):
        compare("pypi", "not-a-version", "1.0")


def test_an_unknown_ecosystem_is_an_error_not_a_guess() -> None:
    with pytest.raises(UnknownEcosystem):
        compare("cobol", "1", "2")


def test_generic_comparator_beats_lexical_ordering() -> None:
    """The fallback is a heuristic, and correlation caps its confidence — but it
    should still get the obvious case right."""
    assert compare("generic", "1.9", "1.10") == -1
