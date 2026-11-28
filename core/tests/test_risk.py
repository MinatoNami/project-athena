from __future__ import annotations

import pytest

from athena.risk import Band, Signals, component_role, score
from athena.risk.scoring import BAND_ORDER


def sig(**kwargs) -> Signals:
    defaults = dict(
        cvss_score=7.5, exposure="internal", service_running=True, tier="production",
        criticality=3, reachable_in_code="unknown", match_confidence=0.95,
        verdict_confidence=0.9, verdict="applicable",
    )
    return Signals(**{**defaults, **kwargs})


def test_scoring_is_deterministic():
    a, b = score(sig()), score(sig())
    assert (a.value, a.band, a.factors) == (b.value, b.band, b.factors)


def test_every_score_carries_its_arithmetic():
    explained = score(sig()).explain()
    assert set(explained["factors"]) >= {
        "base", "exploitation", "exposure", "running", "importance", "reachability",
    }
    assert 0 <= explained["score"] <= 100


def test_exposure_changes_the_answer():
    internet = score(sig(exposure="internet")).value
    internal = score(sig(exposure="internal")).value
    isolated = score(sig(exposure="isolated")).value
    assert internet > internal > isolated


def test_tier_changes_the_answer():
    assert score(sig(tier="production")).value > score(sig(tier="development")).value


def test_a_component_that_is_not_running_scores_lower():
    assert score(sig(service_running=False)).value < score(sig(service_running=True)).value


def test_unknown_running_state_does_not_earn_the_discount():
    assert score(sig(service_running=None)).value == score(sig(service_running=True)).value


@pytest.mark.parametrize("field_name", ["exposure", "tier"])
def test_unknown_classification_is_not_treated_as_low_value(field_name: str):
    unknown = score(sig(**{field_name: "unknown"})).value
    floor = "isolated" if field_name == "exposure" else "personal"
    lowest = score(sig(**{field_name: floor})).value
    assert unknown > lowest


def test_known_exploitation_dominates_a_middling_cvss():
    quiet = score(sig(cvss_score=7.5))
    exploited = score(sig(cvss_score=7.5, kev=True))
    assert exploited.value > quiet.value


def test_epss_raises_the_score():
    assert score(sig(epss=0.9)).value > score(sig(epss=0.01)).value


def test_kev_internet_facing_and_running_is_never_below_high():
    result = score(
        sig(cvss_score=3.0, kev=True, exposure="internet", service_running=True,
            tier="development", criticality=1, reachable_in_code="unlikely")
    )
    assert result.band in (Band.HIGH, Band.CRITICAL)
    assert any("floored at high" in o for o in result.overrides)


def test_production_with_active_exploitation_escalates():
    result = score(sig(kev=True, tier="production", exposure="internal"))
    assert any("escalated" in o for o in result.overrides)


def test_a_not_applicable_verdict_is_informational_whatever_the_score():
    result = score(sig(cvss_score=10.0, kev=True, exposure="internet", verdict="not_applicable"))
    assert result.band is Band.INFORMATIONAL
    assert any("not_applicable" in o for o in result.overrides)


def test_low_confidence_is_capped_until_investigated():
    result = score(
        sig(cvss_score=10.0, kev=True, exposure="internet", service_running=True,
            criticality=5, reachable_in_code="confirmed",
            match_confidence=0.4, verdict_confidence=0.5)
    )
    assert result.band in (Band.MEDIUM, Band.LOW, Band.INFORMATIONAL)
    assert any("capped at medium" in o for o in result.overrides)


def test_the_confidence_cap_outranks_the_known_exploitation_floor():
    result = score(
        sig(cvss_score=10.0, kev=True, exposure="internet", service_running=True,
            match_confidence=0.3, verdict_confidence=0.5)
    )
    assert result.band is Band.MEDIUM
    assert any("capped at medium" in o for o in result.overrides)


def test_reachability_matters_when_it_is_known():
    assert score(sig(reachable_in_code="confirmed")).value > score(
        sig(reachable_in_code="no")
    ).value


def test_a_qualitative_severity_is_used_when_there_is_no_cvss():
    high = score(sig(cvss_score=None, severity="high"))
    low = score(sig(cvss_score=None, severity="low"))
    assert high.value > low.value > 0


def test_an_unrated_advisory_is_not_scored_as_harmless():
    assert score(sig(cvss_score=None, severity=None)).value > 0


def test_an_entitlement_gated_fix_is_flagged_in_the_overrides():
    result = score(sig(fix_requires_entitlement=True))
    assert any("entitlement" in o for o in result.overrides)


def test_no_fix_available_is_recorded():
    result = score(sig(fix_available=False))
    assert any("no fix published" in o for o in result.overrides)


def test_bands_are_ordered_consistently_with_scores():
    seen: list[tuple[int, Band]] = []
    for cvss in (1.0, 4.0, 7.0, 9.9):
        for exposure in ("isolated", "internal", "internet"):
            for tier in ("personal", "staging", "production"):
                r = score(sig(cvss_score=cvss, exposure=exposure, tier=tier))
                seen.append((r.value, r.band))

    from athena.risk.scoring import BAND_ORDER

    for value, band in seen:
        for other_value, other_band in seen:
            if BAND_ORDER.index(band) > BAND_ORDER.index(other_band):
                assert value >= other_value or "floored" in "".join(
                    score(sig()).overrides
                ), f"{band} at {value} ranked above {other_band} at {other_value}"


def test_a_library_never_earns_the_stopped_discount():
    common = dict(
        cvss_score=8.1, exposure="internal", tier="production", criticality=4,
        verdict="applicable", verdict_confidence=0.85, reachable_in_code="confirmed",
    )
    library = score(Signals(**common, service_running=False, component_role="library"))
    unknown_role = score(Signals(**common, service_running=False))

    assert library.value > unknown_role.value
    assert library.value == score(Signals(**common, service_running=None)).value


def test_transitive_dependencies_are_libraries_whatever_the_ecosystem():
    assert component_role("deb", "transitive") == "library"
    assert component_role("npm", "direct") == "library"
    assert component_role("deb", "os") == "unknown"


def test_component_role_never_claims_service():
    roles = {component_role(eco, scope)
             for eco in ("deb", "rpm", "apk", "npm", "generic", None)
             for scope in ("os", "direct", "transitive", None)}
    assert roles == {"library", "unknown"}


def test_known_exploited_floor_holds_when_running_state_is_unknown():
    signals = Signals(
        cvss_score=9.8, kev=True, epss=0.85, exposure="internet", tier="production",
        criticality=5, verdict="applicable", verdict_confidence=0.9,
        service_running=None,
    )
    assert BAND_ORDER.index(score(signals).band) >= BAND_ORDER.index(Band.HIGH)


def test_the_floor_still_yields_to_evidence_that_the_service_is_stopped():
    stopped = Signals(
        cvss_score=9.8, kev=True, epss=0.85, exposure="internet", tier="production",
        criticality=5, verdict="applicable", verdict_confidence=0.9,
        service_running=False,
    )
    assert BAND_ORDER.index(score(stopped).band) < BAND_ORDER.index(Band.HIGH)
    assert score(stopped).value < score(
        Signals(**{**stopped.__dict__, "service_running": None})
    ).value


def test_not_applicable_still_outranks_the_floor():
    signals = Signals(
        cvss_score=9.8, kev=True, epss=0.85, exposure="internet", tier="production",
        criticality=5, verdict="not_applicable", verdict_confidence=0.9,
    )
    assert score(signals).band == Band.INFORMATIONAL


def test_missing_epss_outranks_an_epss_of_zero():
    base = dict(
        cvss_score=9.1, exposure="internal", tier="production", criticality=4,
        verdict="applicable", verdict_confidence=0.9, reachable_in_code="confirmed",
    )
    assert score(Signals(**base, epss=None)).value > score(Signals(**base, epss=0.0)).value


def test_missing_epss_still_ranks_below_measured_exploitation():
    base = dict(
        cvss_score=9.1, exposure="internal", tier="production", criticality=4,
        verdict="applicable", verdict_confidence=0.9, reachable_in_code="confirmed",
    )
    unknown = score(Signals(**base, epss=None)).value
    assert score(Signals(**base, epss=0.0)).value < unknown
    assert unknown < score(Signals(**base, epss=0.7)).value


def _kev_internet(**overrides):
    return Signals(**{
        "cvss_score": 9.8, "kev": True, "epss": 0.85, "exposure": "internet",
        "tier": "production", "criticality": 5, "verdict": "applicable",
        "verdict_confidence": 0.9, "service_running": None, **overrides,
    })


def test_an_uncertain_verdict_does_not_undercut_the_known_exploitation_floor():
    uncertain = score(_kev_internet(verdict_confidence=0.30))
    assert BAND_ORDER.index(uncertain.band) >= BAND_ORDER.index(Band.HIGH)
    assert any("confidence" in o and "low" in o for o in uncertain.overrides)
    assert any("floored at high" in o for o in uncertain.overrides)


def test_a_doubtful_match_still_caps_everything():
    capped = score(_kev_internet(match_confidence=0.2))
    assert BAND_ORDER.index(capped.band) <= BAND_ORDER.index(Band.MEDIUM)
    assert any("wrong package" in o for o in capped.overrides)


def test_a_low_verdict_confidence_still_caps_without_a_floor():
    signals = Signals(
        cvss_score=9.5, exposure="internal", tier="production", criticality=5,
        verdict="applicable", verdict_confidence=0.2, reachable_in_code="confirmed",
    )
    assert BAND_ORDER.index(score(signals).band) <= BAND_ORDER.index(Band.MEDIUM)


def test_override_precedence_is_ordered_not_incidental():
    both = score(_kev_internet(verdict_confidence=0.2, match_confidence=0.2))
    assert BAND_ORDER.index(both.band) <= BAND_ORDER.index(Band.MEDIUM)
    floor_only = score(_kev_internet(verdict_confidence=0.2))
    assert BAND_ORDER.index(floor_only.band) > BAND_ORDER.index(both.band)


def test_not_applicable_still_reports_its_arithmetic():
    dismissed = score(_kev_internet(verdict="not_applicable"))
    assert dismissed.band == Band.INFORMATIONAL
    assert dismissed.factors["raw"] > 0
