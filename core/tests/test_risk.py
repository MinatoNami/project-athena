"""Risk scoring.

The whole point of this function is that it is deterministic and explainable, so the
tests assert the properties that make it trustworthy rather than exact numbers where
a number is not the interesting part.
"""

from __future__ import annotations

import pytest

from athena.risk import Band, Signals, score


def sig(**kwargs) -> Signals:
    """An applicable finding with everything known, as a baseline to vary."""
    defaults = dict(
        cvss_score=7.5, exposure="internal", service_running=True, tier="production",
        criticality=3, reachable_in_code="unknown", match_confidence=0.95,
        verdict_confidence=0.9, verdict="applicable",
    )
    return Signals(**{**defaults, **kwargs})


# ── determinism and explainability ───────────────────────────────────────────

def test_scoring_is_deterministic():
    a, b = score(sig()), score(sig())
    assert (a.value, a.band, a.factors) == (b.value, b.band, b.factors)


def test_every_score_carries_its_arithmetic():
    """"Why is this critical?" must be answerable without reading code."""
    explained = score(sig()).explain()
    assert set(explained["factors"]) >= {
        "base", "exploitation", "exposure", "running", "importance", "reachability",
    }
    assert 0 <= explained["score"] <= 100


# ── the same CVE scores differently per instance ─────────────────────────────

def test_exposure_changes_the_answer():
    """Scored per instance, never per vulnerability: identical software is not
    identical risk."""
    internet = score(sig(exposure="internet")).value
    internal = score(sig(exposure="internal")).value
    isolated = score(sig(exposure="isolated")).value
    assert internet > internal > isolated


def test_tier_changes_the_answer():
    assert score(sig(tier="production")).value > score(sig(tier="development")).value


def test_a_component_that_is_not_running_scores_lower():
    assert score(sig(service_running=False)).value < score(sig(service_running=True)).value


def test_unknown_running_state_does_not_earn_the_discount():
    """"We do not know" must not be treated as "it is not running"."""
    assert score(sig(service_running=None)).value == score(sig(service_running=True)).value


@pytest.mark.parametrize("field_name", ["exposure", "tier"])
def test_unknown_classification_is_not_treated_as_low_value(field_name: str):
    """An unclassified asset is not a low-value one. Defaulting it low would quietly
    discount everything nobody has got round to labelling."""
    unknown = score(sig(**{field_name: "unknown"})).value
    floor = "isolated" if field_name == "exposure" else "personal"
    lowest = score(sig(**{field_name: floor})).value
    assert unknown > lowest


# ── exploitation ─────────────────────────────────────────────────────────────

def test_known_exploitation_dominates_a_middling_cvss():
    quiet = score(sig(cvss_score=7.5))
    exploited = score(sig(cvss_score=7.5, kev=True))
    assert exploited.value > quiet.value


def test_epss_raises_the_score():
    assert score(sig(epss=0.9)).value > score(sig(epss=0.01)).value


def test_kev_internet_facing_and_running_is_never_below_high():
    """The one combination that must never be buried, whatever the arithmetic says."""
    result = score(
        sig(cvss_score=3.0, kev=True, exposure="internet", service_running=True,
            tier="development", criticality=1, reachable_in_code="unlikely")
    )
    assert result.band in (Band.HIGH, Band.CRITICAL)
    assert any("floored at high" in o for o in result.overrides)


def test_production_with_active_exploitation_escalates():
    result = score(sig(kev=True, tier="production", exposure="internal"))
    assert any("escalated" in o for o in result.overrides)


# ── uncertainty ──────────────────────────────────────────────────────────────

def test_a_not_applicable_verdict_is_informational_whatever_the_score():
    result = score(sig(cvss_score=10.0, kev=True, exposure="internet", verdict="not_applicable"))
    assert result.band is Band.INFORMATIONAL
    assert any("not_applicable" in o for o in result.overrides)


def test_low_confidence_is_capped_until_investigated():
    """A shaky match must not present as critical on the strength of a CVSS score."""
    result = score(
        sig(cvss_score=10.0, kev=True, exposure="internet", service_running=True,
            criticality=5, reachable_in_code="confirmed",
            match_confidence=0.4, verdict_confidence=0.5)
    )
    assert result.band in (Band.MEDIUM, Band.LOW, Band.INFORMATIONAL)
    assert any("capped at medium" in o for o in result.overrides)


def test_the_confidence_cap_outranks_the_known_exploitation_floor():
    """Deliberate precedence: a floor applied to a finding we may have matched
    against the wrong package manufactures urgency from an uncertain match. Both
    overrides are recorded so the disagreement is visible."""
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


# ── severity fallbacks ───────────────────────────────────────────────────────

def test_a_qualitative_severity_is_used_when_there_is_no_cvss():
    """Distribution advisories usually carry a word rather than a vector. Ignoring
    those scored most distro findings at zero."""
    high = score(sig(cvss_score=None, severity="high"))
    low = score(sig(cvss_score=None, severity="low"))
    assert high.value > low.value > 0


def test_an_unrated_advisory_is_not_scored_as_harmless():
    assert score(sig(cvss_score=None, severity=None)).value > 0


# ── fix availability ─────────────────────────────────────────────────────────

def test_an_entitlement_gated_fix_is_flagged_in_the_overrides():
    """Recommending a fix the operator cannot install is advice they cannot follow."""
    result = score(sig(fix_requires_entitlement=True))
    assert any("entitlement" in o for o in result.overrides)


def test_no_fix_available_is_recorded():
    result = score(sig(fix_available=False))
    assert any("no fix published" in o for o in result.overrides)


def test_bands_are_ordered_consistently_with_scores():
    """A higher band must never carry a lower score than a lower band, across a
    sweep of plausible inputs."""
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
