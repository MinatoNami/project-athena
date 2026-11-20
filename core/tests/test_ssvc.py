"""SSVC deployer decisions.

The outcome table is CISA's, so the interesting assertions are about Athena's side of
it: that every decision point says where it came from, that a missing fact is taken
at its worse value *and admitted*, and that a forecast (EPSS) never stands in for
the fact of exploitation.
"""

from __future__ import annotations

import itertools

import pytest

from athena.risk import ssvc

CRITICAL_NET = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
LOCAL_PARTIAL = "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"


def _decide(**kw):
    base = dict(
        kev=False, exploit_public=False, vector=CRITICAL_NET, tier="production", criticality=3
    )
    return ssvc.decide(**{**base, **kw})


def test_the_table_is_complete():
    for key in itertools.product(("none", "poc", "active"), ("no", "yes"), ("partial", "total")):
        assert key in ssvc._TABLE, key


def test_outcomes_never_fall_as_any_point_worsens():
    """Monotonicity: worse facts can never earn a milder outcome."""
    order = {o: i for i, o in enumerate(ssvc.OUTCOME_ORDER)}
    axes = [("none", "poc", "active"), ("no", "yes"), ("partial", "total")]
    for e, a, t in itertools.product(*axes):
        row = [order[o] for o in ssvc._TABLE[(e, a, t)]]
        assert row == sorted(row), (e, a, t)
        for i, values in enumerate(axes):
            current = (e, a, t)[i]
            idx = values.index(current)
            if idx + 1 < len(values):
                worse = list((e, a, t))
                worse[i] = values[idx + 1]
                worse_row = [order[o] for o in ssvc._TABLE[tuple(worse)]]
                assert all(w >= c for w, c in zip(worse_row, row, strict=True)), (
                    (e, a, t),
                    tuple(worse),
                )


def test_known_exploited_worm_shaped_flaw_on_critical_production_is_act():
    decision = _decide(kev=True, criticality=4)
    assert decision.outcome == ssvc.ACT
    assert decision.points["exploitation"].value == "active"
    assert decision.points["automatable"].value == "yes"
    assert decision.points["technical_impact"].value == "total"
    assert decision.points["mission_wellbeing"].value == "high"
    assert decision.assumed == []


def test_unexploited_local_partial_flaw_is_track():
    assert _decide(vector=LOCAL_PARTIAL).outcome == ssvc.TRACK


def test_public_exploit_is_poc_not_active():
    point = _decide(exploit_public=True).points["exploitation"]
    assert point.value == "poc"


def test_epss_is_not_an_input():
    """A forecast is not the fact of exploitation: the signature does not take it."""
    with pytest.raises(TypeError):
        ssvc.decide(
            kev=False,
            exploit_public=False,
            vector=CRITICAL_NET,
            tier="production",
            criticality=3,
            epss=0.97,
        )


def test_a_missing_vector_is_assumed_worst_and_says_so():
    decision = _decide(vector=None, kev=True)
    assert decision.points["automatable"].value == "yes"
    assert decision.points["technical_impact"].value == "total"
    assert set(decision.assumed) == {"automatable", "technical_impact"}
    assert any("worse value" in n for n in decision.notes)


def test_an_unclassified_asset_is_medium_and_assumed():
    point = ssvc.mission_wellbeing(tier="unknown", criticality=None)
    assert point.value == "medium" and point.assumed


@pytest.mark.parametrize(
    ("tier", "criticality", "expected"),
    [
        ("production", 5, "high"),
        ("production", 4, "high"),
        ("production", None, "medium"),
        ("staging", 2, "medium"),
        ("development", 5, "high"),
        ("development", 3, "medium"),
        ("development", None, "low"),
        ("personal", 1, "low"),
    ],
)
def test_mission_wellbeing_follows_what_the_operator_said(tier, criticality, expected):
    assert ssvc.mission_wellbeing(tier=tier, criticality=criticality).value == expected


def test_v4_vectors_are_read_for_decision_points():
    v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    decision = _decide(vector=v4)
    assert decision.points["automatable"].value == "yes"
    assert decision.points["technical_impact"].value == "total"
    v4_attack_requirements = v4.replace("AT:N", "AT:P")
    assert _decide(vector=v4_attack_requirements).points["automatable"].value == "no"


def test_malware_is_decided_as_actively_exploited():
    decision = _decide(malicious=True, vector=LOCAL_PARTIAL, tier="development", criticality=None)
    assert decision.points["exploitation"].value == "active"
    assert any("Malicious" in n for n in decision.notes)


def test_every_point_states_its_basis():
    for point in _decide().points.values():
        assert point.basis


def test_as_dict_carries_the_meaning_for_the_page():
    out = _decide(kev=True, criticality=5).as_dict()
    assert out["outcome"] == ssvc.ACT
    assert "immediately" in out["meaning"]
    assert out["framework"].startswith("CISA SSVC")


def test_cisa_vulnrichment_outranks_the_vector_mapping():
    cisa = {
        "exploitation": "poc",
        "automatable": "no",
        "technical_impact": "partial",
        "timestamp": "2026-10-02T00:00:00Z",
    }
    decision = _decide(cisa=cisa)
    assert decision.points["exploitation"].value == "poc"
    assert decision.points["automatable"].value == "no"
    assert decision.points["technical_impact"].value == "partial"
    assert "Vulnrichment assessment (2026-10-02)" in decision.points["automatable"].basis


def test_kev_outranks_a_stale_cisa_exploitation_value():
    """CVEs exist that are in KEV while their ADP record still says 'none'."""
    decision = _decide(kev=True, cisa={"exploitation": "none"})
    assert decision.points["exploitation"].value == "active"


def test_the_reference_spelling_public_poc_is_normalised():
    decision = _decide(cisa={"exploitation": "public poc"})
    assert decision.points["exploitation"].value == "poc"
