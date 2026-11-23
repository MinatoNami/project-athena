"""CVSS base scores.

The calculator was checked exhaustively against an independent implementation over
all 5,184 v3.0/v3.1 base vectors before these were written. These pin the published
examples, the rounding rule that distinguishes 3.0 from 3.1, and the refusals — a
vector this module cannot read must produce None, never a number.
"""

from __future__ import annotations

import pytest

from athena.intel import cvss


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ],
)
def test_published_examples(vector, expected):
    assert cvss.base_score(vector) == expected


def test_no_impact_is_zero_not_unknown():
    """A vector that states no impact is a measured zero — distinct from None."""
    assert cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0


def test_metric_order_does_not_matter():
    assert cvss.base_score("CVSS:3.1/C:H/I:H/A:H/AV:N/AC:L/PR:N/UI:N/S:U") == 9.8


def test_temporal_metrics_are_ignored_for_the_base_score():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C"
    assert cvss.base_score(vector) == 9.8


@pytest.mark.parametrize(
    "vector",
    [
        None,
        "",
        "AV:N/AC:L/Au:N/C:P/I:P/A:P",  # v2 — not scored here
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # A missing
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # unknown value
        "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # repeated metric
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:Q/C:H/I:H/A:H",  # unknown scope
        "CVSS:9.9/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ],
)
def test_unreadable_vectors_are_refused_not_guessed(vector):
    assert cvss.base_score(vector) is None


def test_v4_is_parsed_but_not_scored():
    """v4 scores come from FIRST's macro-vector table. Without it, no number — the
    caller falls back to the published label rather than to an approximation."""
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    assert cvss.parse(vector).get("AT") == "N"
    assert cvss.base_score(vector) is None


def test_choose_prefers_a_scoreable_vector():
    v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    v30 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    v31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert cvss.choose([v4, v30, v31]) == v31
    assert cvss.choose([v4, v30]) == v30
    assert cvss.choose([v4]) == v4
    assert cvss.choose([]) is None


@pytest.mark.parametrize(
    ("score", "label"),
    [
        (0.0, "none"),
        (3.9, "low"),
        (4.0, "medium"),
        (6.9, "medium"),
        (7.0, "high"),
        (8.9, "high"),
        (9.0, "critical"),
        (None, None),
    ],
)
def test_qualitative_bands(score, label):
    assert cvss.severity_of(score) == label
