"""The investigation floor.

A budget buys a finite number of investigations and something has to choose. The
property under test is that choosing never turns into concluding: a finding the floor
did not select is unexamined, not dismissed, and comes back the moment the floor moves.
"""

from __future__ import annotations

import pytest

from athena.investigation.priority import Severity, decide, rank


def _facts(**advisory):
    base = dict(severity="medium", cvss=None, epss=None, known_exploited=False)
    return {"advisory": {**base, **advisory}, "asset": {"tier": "unknown", "exposure": "unknown"}}


# ── the floor itself ─────────────────────────────────────────────────────────


def test_the_default_floor_selects_everything():
    """An upgrade must not quietly stop investigating what a deployment was already
    looking at. Narrowing is something an operator does on purpose."""
    assert decide(_facts(severity="low"), floor="all").investigate


@pytest.mark.parametrize(
    ("severity", "floor", "expected"),
    [
        ("critical", "high", True),
        ("high", "high", True),
        ("medium", "high", False),
        ("low", "medium", False),
        ("medium", "medium", True),
    ],
)
def test_severity_is_compared_against_the_floor(severity, floor, expected):
    assert decide(_facts(severity=severity), floor=floor).investigate is expected


# ── what absence is allowed to mean ──────────────────────────────────────────


def test_an_unrated_advisory_ranks_as_medium_not_as_low():
    """528 of the findings awaiting investigation carry no CVSS at all. Ranking an
    absent severity at the bottom would push exactly the unmeasured ones out of view,
    which is the failure this codebase keeps having to fix."""
    assert rank(None) is Severity.MEDIUM
    assert rank("") is Severity.MEDIUM
    assert rank("not-a-severity") is Severity.MEDIUM
    assert decide(_facts(severity=None), floor="medium").investigate


def test_a_deferral_says_it_ranked_an_unrated_advisory():
    """Stating the assumption, since it is the reason the finding was judged at all."""
    reason = decide(_facts(severity=None), floor="high").reason
    assert "unrated" in reason and "ranked as medium" in reason


# ── the gates outrank the floor ──────────────────────────────────────────────


@pytest.mark.parametrize(
    "advisory",
    [
        {"known_exploited": True},
        {"cvss": 9.4},
        {"epss": 0.22},
    ],
)
def test_a_gate_overrides_any_floor(advisory):
    """A floor set in a hurry must not be able to skip a known-exploited entry."""
    d = decide(_facts(severity="low", **advisory), floor="critical")
    assert d.investigate and d.forced


def test_an_internet_facing_production_finding_is_always_investigated():
    facts = _facts(severity="low")
    facts["asset"] = {"tier": "production", "exposure": "internet"}
    assert decide(facts, floor="critical").investigate


def test_triage_and_the_scheduler_share_one_definition_of_the_gates():
    """Two copies of "never skip a KEV entry" is one copy too many — the gap between
    them is where one falls through."""
    from athena.investigation.priority import always_investigate
    from athena.investigation.triage import _hard_gates

    assert _hard_gates is always_investigate


# ── deferral is not a verdict ────────────────────────────────────────────────


def test_a_deferral_is_phrased_as_unexamined_rather_than_unimportant():
    """The only claim being made is about the floor. Nothing has checked whether the
    vulnerability applies, and the wording must not imply otherwise."""
    reason = decide(_facts(severity="low"), floor="high").reason
    assert "Nothing has checked whether it applies" in reason
    assert "unexamined, not dismissed" in reason
    assert "floor is lowered" in reason


def test_an_unrecognised_floor_selects_everything_rather_than_nothing():
    """A typo in configuration must fail towards looking, not towards silence."""
    assert decide(_facts(severity="low"), floor="hihg").investigate
    assert decide(_facts(severity="low"), floor="").investigate
