from __future__ import annotations

import pytest

from athena.versions import compare, in_affected_range
from athena.versions.compare import UncomparableVersions, UnknownEcosystem


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("1.0", "1.1"),
        ("1.9", "1.10"),
        ("1.0.dev1", "1.0a1"),
        ("1.0a1", "1.0b1"),
        ("1.0b1", "1.0rc1"),
        ("1.0rc1", "1.0"),
        ("1.0", "1.0.post1"),
        ("1.0.post1", "1.1"),
        ("1.0", "1!0.1"),
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
    assert compare("pypi", a, b) == 0


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("1.0", "1.1"),
        ("1.9", "1.10"),
        ("1.0~rc1", "1.0"),
        ("1.0~beta1", "1.0~rc1"),
        ("1.0", "1.0-1"),
        ("1.0-1", "1.0-2"),
        ("1.0-1", "1:0.9"),
        ("1:1.0", "2:0.1"),
        ("3.0.13-0ubuntu3.11", "3.0.13-0ubuntu3.12"),
        ("1.9.15p5-3ubuntu5", "1.9.15p5-3ubuntu5.24.04.2"),
        ("2.39-0ubuntu8.7", "2.39-0ubuntu8.8"),
        ("1.0a", "1.0+"),
    ],
)
def test_debian_ordering(lower: str, higher: str) -> None:
    assert compare("deb", lower, higher) == -1, f"{lower} should sort below {higher}"
    assert compare("deb", higher, lower) == 1


@pytest.mark.parametrize(("a", "b"), [("1.0", "1.0"), ("0:1.0", "1.0"), ("1.0-0", "1.0-0")])
def test_debian_equality(a: str, b: str) -> None:
    assert compare("deb", a, b) == 0


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("1.0.0", "1.0.1"),
        ("1.0.9", "1.0.10"),
        ("1.0.0-alpha", "1.0.0-alpha.1"),
        ("1.0.0-alpha.1", "1.0.0-alpha.beta"),
        ("1.0.0-alpha.beta", "1.0.0-beta"),
        ("1.0.0-beta.2", "1.0.0-beta.11"),
        ("1.0.0-rc.1", "1.0.0"),
        ("1.9.0", "1.10.0"),
    ],
)
def test_semver_ordering(lower: str, higher: str) -> None:
    assert compare("npm", lower, higher) == -1, f"{lower} should sort below {higher}"
    assert compare("npm", higher, lower) == 1


def test_semver_ignores_build_metadata() -> None:
    assert compare("npm", "1.0.0+build.1", "1.0.0+build.2") == 0
    assert compare("npm", "1.0.0", "1.0.0+anything") == 0


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("1.0", "1.1"),
        ("1.0-1", "1.0-2"),
        ("1.0~rc1", "1.0"),
        ("1.0", "1.0^post"),
        ("1.0", "2:0.9"),
        ("1.a", "1.1"),
    ],
)
def test_rpm_ordering(lower: str, higher: str) -> None:
    assert compare("rpm", lower, higher) == -1, f"{lower} should sort below {higher}"


def test_fixed_bound_is_exclusive() -> None:
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
    assert in_affected_range(
        "deb", "3.0.13-0ubuntu3.11", introduced="0", fixed="3.0.13-0ubuntu3.12"
    ) is True
    assert in_affected_range(
        "deb", "3.0.13-0ubuntu3.12", introduced="0", fixed="3.0.13-0ubuntu3.12"
    ) is False


def test_an_unparseable_version_raises_rather_than_reporting_not_affected() -> None:
    with pytest.raises(UncomparableVersions):
        compare("pypi", "not-a-version", "1.0")


def test_an_unknown_ecosystem_is_an_error_not_a_guess() -> None:
    with pytest.raises(UnknownEcosystem):
        compare("cobol", "1", "2")


def test_generic_comparator_beats_lexical_ordering() -> None:
    assert compare("generic", "1.9", "1.10") == -1


RPMVERCMP_VECTORS = [
    ("1.0", "1.0", 0),
    ("1.0", "2.0", -1),
    ("2.0", "1.0", 1),
    ("2.0.1", "2.0.1", 0),
    ("2.0", "2.0.1", -1),
    ("2.0.1a", "2.0.1a", 0),
    ("2.0.1a", "2.0.1", 1),
    ("5.5p1", "5.5p1", 0),
    ("5.5p1", "5.5p2", -1),
    ("5.5p10", "5.5p10", 0),
    ("5.5p1", "5.5p10", -1),
    ("10xyz", "10.1xyz", -1),
    ("xyz10", "xyz10", 0),
    ("xyz10", "xyz10.1", -1),
    ("xyz.4", "xyz.4", 0),
    ("xyz.4", "8", -1),
    ("xyz.4", "2", -1),
    ("5.5p2", "5.6p1", -1),
    ("5.6p1", "6.5p1", -1),
    ("6.0.rc1", "6.0", 1),
    ("10b2", "10a1", 1),
    ("1.0aa", "1.0aa", 0),
    ("1.0a", "1.0aa", -1),
    ("10.0001", "10.0001", 0),
    ("10.0001", "10.1", 0),
    ("10.0001", "10.0039", -1),
    ("4.999.9", "5.0", -1),
    ("20101121", "20101121", 0),
    ("20101121", "20101122", -1),
    ("2_0", "2_0", 0),
    ("2.0", "2_0", 0),
    ("a", "a", 0),
    ("a+", "a+", 0),
    ("a+", "a_", 0),
    ("+a", "+a", 0),
    ("+a", "_a", 0),
    ("+_", "+_", 0),
    ("_+", "+_", 0),
    ("_+", "_", 0),
    ("+", "_", 0),
    ("1.0~rc1", "1.0~rc1", 0),
    ("1.0~rc1", "1.0", -1),
    ("1.0~rc1", "1.0~rc2", -1),
    ("1.0~rc1~git123", "1.0~rc1~git123", 0),
    ("1.0~rc1~git123", "1.0~rc1", -1),
    ("1.0^", "1.0^", 0),
    ("1.0^", "1.0", 1),
    ("1.0", "1.0^", -1),
    ("1.0^git1", "1.0^git1", 0),
    ("1.0^git1", "1.0", 1),
    ("1.0^git1", "1.0^git2", -1),
    ("1.0^git1", "1.01", -1),
    ("1.0^git1", "1.0.1", -1),
    ("1.0^20160101", "1.0^20160101", 0),
    ("1.0^20160101", "1.0.1", -1),
    ("1.0^20160101^git1", "1.0^20160101^git1", 0),
    ("1.0^20160102", "1.0^20160101^git1", 1),
    ("1.0~rc1^git1", "1.0~rc1^git1", 0),
    ("1.0~rc1^git1", "1.0~rc1", 1),
    ("1.0^git1~pre", "1.0^git1~pre", 0),
    ("1.0^git1", "1.0^git1~pre", 1),
    ("1.0^git1~pre", "1.0", 1),
]


@pytest.mark.parametrize(("a", "b", "expected"), RPMVERCMP_VECTORS)
def test_rpm_matches_rpmvercmp(a: str, b: str, expected: int) -> None:
    assert compare("rpm", a, b) == expected
    assert compare("rpm", b, a) == -expected


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("0:1.0-1", "1.0-1", 0),
        ("1:1.0-1", "2.0-1", 1),
        ("1.0-1", "1.0-2", -1),
        ("1.0-1.el9", "1.0-1.el9_2", -1),
        ("1.0^git1-1", "1.0.1-1", -1),
        ("1.0~rc1-5", "1.0-1", -1),
    ],
)
def test_rpm_epoch_version_release(a: str, b: str, expected: int) -> None:
    assert compare("rpm", a, b) == expected
    assert compare("rpm", b, a) == -expected


DEBIAN_POLICY_TILDE_ORDER = ["1.0~~", "1.0~~a", "1.0~", "1.0", "1.0a"]


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        *zip(DEBIAN_POLICY_TILDE_ORDER, DEBIAN_POLICY_TILDE_ORDER[1:], strict=False),
        ("1.0z", "1.0+"),
        ("1.0z", "1.0."),
        ("9.9", "1:0.1"),
        ("1.0-1", "1.0-1.1"),
        ("1.0-1ubuntu1", "1.0-1+deb12u1"),
        ("1.2-3-4", "1.2-3-5"),
        ("1.2-3-9", "1.2-4-1"),
        ("1:2.3-4-5", "1:2.3-4-6"),
    ],
)
def test_debian_matches_dpkg(lower: str, higher: str) -> None:
    assert compare("deb", lower, higher) == -1, f"{lower} should sort below {higher}"
    assert compare("deb", higher, lower) == 1


@pytest.mark.parametrize(("a", "b"), [("1.01", "1.1"), ("1.0", "1.0-0"), ("1.2-3-4", "0:1.2-3-4")])
def test_debian_equal_under_dpkg(a: str, b: str) -> None:
    assert compare("deb", a, b) == 0


PEP440_SPEC_ORDER = [
    "1.dev0",
    "1.0.dev456",
    "1.0a1",
    "1.0a2.dev456",
    "1.0a12.dev456",
    "1.0a12",
    "1.0b1.dev456",
    "1.0b2",
    "1.0b2.post345.dev456",
    "1.0b2.post345",
    "1.0rc1.dev456",
    "1.0rc1",
    "1.0",
    "1.0+abc.5",
    "1.0+abc.7",
    "1.0+5",
    "1.0.post456.dev34",
    "1.0.post456",
    "1.0.15",
    "1.1.dev1",
]


def test_pep440_spec_order_table_agrees_with_packaging() -> None:
    reference = pytest.importorskip("packaging.version")
    assert sorted(PEP440_SPEC_ORDER, key=reference.Version) == PEP440_SPEC_ORDER


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        (PEP440_SPEC_ORDER[i], PEP440_SPEC_ORDER[j])
        for i in range(len(PEP440_SPEC_ORDER))
        for j in range(i + 1, len(PEP440_SPEC_ORDER))
    ],
)
def test_pep440_matches_spec_order(lower: str, higher: str) -> None:
    assert compare("pypi", lower, higher) == -1, f"{lower} should sort below {higher}"
    assert compare("pypi", higher, lower) == 1


@pytest.mark.parametrize(
    ("a", "b"),
    [("1.0+ABC", "1.0+abc"), ("1!1.0", "1!1.0.0"), ("1.0-1", "1.0.post1")],
)
def test_pep440_equal_under_packaging(a: str, b: str) -> None:
    assert compare("pypi", a, b) == 0


SEMVER_SPEC_ORDER = [
    "1.0.0-alpha",
    "1.0.0-alpha.1",
    "1.0.0-alpha.beta",
    "1.0.0-beta",
    "1.0.0-beta.2",
    "1.0.0-beta.11",
    "1.0.0-rc.1",
    "1.0.0",
    "2.0.0",
    "2.1.0",
    "2.1.1",
]


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        *zip(SEMVER_SPEC_ORDER, SEMVER_SPEC_ORDER[1:], strict=False),
        ("1.0.0-1", "1.0.0-alpha"),
        ("1.0.0-2", "1.0.0-10"),
    ],
)
def test_semver_matches_spec_precedence(lower: str, higher: str) -> None:
    assert compare("npm", lower, higher) == -1, f"{lower} should sort below {higher}"
    assert compare("npm", higher, lower) == 1


HEURISTIC_COMPARATOR_GAP = pytest.mark.xfail(
    strict=True, reason="heuristic comparator does not implement this ordering"
)


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("1.9", "1.10"),
        ("1.0", "1.0.1"),
        ("1.0-alpha1", "1.0-beta1"),
        ("1.0", "1.0-sp1"),
        pytest.param("1.0-alpha-1", "1.0", marks=HEURISTIC_COMPARATOR_GAP),
        pytest.param("1.0-SNAPSHOT", "1.0", marks=HEURISTIC_COMPARATOR_GAP),
        pytest.param("1.0-RC1", "1.0", marks=HEURISTIC_COMPARATOR_GAP),
        pytest.param("1.0-beta1", "1.0-RC1", marks=HEURISTIC_COMPARATOR_GAP),
    ],
)
def test_maven_common_orderings(lower: str, higher: str) -> None:
    assert compare("maven", lower, higher) == -1, f"{lower} should sort below {higher}"
    assert compare("maven", higher, lower) == 1


@pytest.mark.xfail(strict=True, reason="heuristic comparator does not drop trailing zeros")
def test_maven_trailing_zero_is_equal() -> None:
    assert compare("maven", "1.0", "1.0.0") == 0


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("1.2.3", "1.2.10"),
        ("1.0-r0", "1.0-r1"),
        ("1.0-r9", "1.0.1-r0"),
        ("1.0_beta1", "1.0_rc1"),
        ("1.0", "1.0_p1"),
        pytest.param("1.0_alpha1", "1.0", marks=HEURISTIC_COMPARATOR_GAP),
        pytest.param("1.0_rc1", "1.0", marks=HEURISTIC_COMPARATOR_GAP),
    ],
)
def test_apk_common_orderings(lower: str, higher: str) -> None:
    assert compare("apk", lower, higher) == -1, f"{lower} should sort below {higher}"
    assert compare("apk", higher, lower) == 1
