from __future__ import annotations

import pytest

from athena.investigation.verdict import (
    SIGNAL_NAMES,
    MalformedVerdict,
    parse_verdict,
)


def payload(signals: dict, verdict="applicable", confidence=0.9):
    full = {
        name: {"value": "unknown", "confidence": 0.0, "evidence": []}
        for name in SIGNAL_NAMES
    }
    full.update(signals)
    return {
        "signals": full,
        "verdict": verdict,
        "verdict_confidence": confidence,
        "rationale": "because",
        "uncertainties": [],
    }


def test_a_grounded_signal_survives():
    v = parse_verdict(
        payload({"component_present": {"value": True, "confidence": 0.95,
                                       "evidence": ["get_component"]}}),
        tools_called={"get_component"},
    )
    assert v.signals["component_present"].value is True
    assert v.signals["component_present"].confidence == 0.95
    assert v.corrections == []


def test_a_confident_signal_with_no_evidence_is_downgraded():
    v = parse_verdict(
        payload({"network_reachable": {"value": True, "confidence": 0.95, "evidence": []}}),
        tools_called={"get_asset"},
    )
    assert v.signals["network_reachable"].value == "unknown"
    assert v.signals["network_reachable"].confidence == 0.0
    assert any("no supporting tool output" in c for c in v.corrections)


def test_a_signal_citing_an_uncalled_tool_is_downgraded():
    v = parse_verdict(
        payload({"service_running": {"value": True, "confidence": 0.9,
                                     "evidence": ["list_processes"]}}),
        tools_called={"get_asset"},
    )
    assert v.signals["service_running"].value == "unknown"
    assert any("never called" in c for c in v.corrections)


def test_a_low_confidence_guess_is_left_alone():
    v = parse_verdict(
        payload({"vulnerable_feature_enabled": {"value": "unknown", "confidence": 0.3,
                                                "evidence": []}}),
        tools_called=set(),
    )
    assert v.signals["vulnerable_feature_enabled"].confidence == 0.3
    assert v.corrections == []


def test_a_verdict_resting_on_unfounded_signals_is_forced_to_uncertain():
    bad = {
        name: {"value": True, "confidence": 0.9, "evidence": []}
        for name in SIGNAL_NAMES[:5]
    }
    v = parse_verdict(payload(bad, verdict="applicable", confidence=0.95),
                      tools_called=set())
    assert v.verdict == "uncertain"
    assert v.verdict_confidence <= 0.3
    assert any("forced to uncertain" in c for c in v.corrections)


def test_uncertain_is_a_first_class_answer():
    v = parse_verdict(payload({}, verdict="uncertain", confidence=0.2), tools_called=set())
    assert v.verdict == "uncertain"
    assert v.corrections == []


def test_an_unknown_verdict_is_rejected():
    with pytest.raises(MalformedVerdict):
        parse_verdict(payload({}, verdict="definitely_exploitable"), tools_called=set())


def test_confidence_is_clamped():
    v = parse_verdict(
        payload({"component_present": {"value": True, "confidence": 42.0,
                                       "evidence": ["get_component"]}}, confidence=-3),
        tools_called={"get_component"},
    )
    assert v.signals["component_present"].confidence == 1.0
    assert v.verdict_confidence == 0.0


def _reply(**overrides):
    signals = {
        name: {"value": "unknown", "confidence": 0.0, "evidence": []}
        for name in SIGNAL_NAMES
    }
    signals.update(overrides.pop("signals", {}))
    return {
        "signals": signals,
        "verdict": overrides.pop("verdict", "uncertain"),
        "verdict_confidence": overrides.pop("verdict_confidence", 0.8),
        "rationale": "because",
        "uncertainties": overrides.pop("uncertainties", []),
    }


def _cited(value, confidence=0.9, tool="get_advisory"):
    return {"value": value, "confidence": confidence, "evidence": [tool]}


def test_an_established_fact_replaces_a_contradicting_signal():
    verdict = parse_verdict(
        _reply(signals={"version_in_range": _cited(False)}),
        tools_called={"get_advisory"},
        established={"version_in_range": True, "component_present": True},
    )
    assert verdict.signals["version_in_range"].value is True
    assert verdict.signals["version_in_range"].downgraded
    assert any("not its question to answer" in c for c in verdict.corrections)


def test_an_established_fact_agreed_with_is_not_a_correction():
    verdict = parse_verdict(
        _reply(signals={"component_present": _cited(True)}),
        tools_called={"get_advisory"},
        established={"component_present": True},
    )
    assert verdict.signals["component_present"].value is True
    assert not verdict.signals["component_present"].downgraded
    assert verdict.corrections == []


def test_mechanism_claims_are_downgraded_when_the_advisory_says_nothing():
    verdict = parse_verdict(
        _reply(signals={
            "vulnerable_feature_enabled": _cited(False),
            "reachable_in_code": _cited("no"),
            "authentication_required": _cited(True),
        }),
        tools_called={"get_advisory"},
        advisory_describes_flaw=False,
    )
    for name in ("vulnerable_feature_enabled", "reachable_in_code", "authentication_required"):
        assert verdict.signals[name].value == "unknown", name
        assert verdict.signals[name].downgraded, name


def test_mechanism_claims_survive_when_the_advisory_does_describe_the_flaw():
    verdict = parse_verdict(
        _reply(signals={"reachable_in_code": _cited("confirmed")}),
        tools_called={"get_advisory"},
        advisory_describes_flaw=True,
    )
    assert verdict.signals["reachable_in_code"].value == "confirmed"
    assert not verdict.signals["reachable_in_code"].downgraded


def test_not_applicable_without_a_surviving_reason_becomes_uncertain():
    verdict = parse_verdict(
        _reply(verdict="not_applicable", verdict_confidence=0.85),
        tools_called={"get_advisory"},
        established={"component_present": True, "version_in_range": True},
    )
    assert verdict.verdict == "uncertain"
    assert verdict.verdict_confidence <= 0.3
    assert verdict.uncertainties, "must say what it could not determine"
    assert any("no signal survived" in c for c in verdict.corrections)


def test_a_grounded_dismissal_is_left_alone():
    verdict = parse_verdict(
        _reply(
            verdict="not_applicable", verdict_confidence=0.9,
            signals={"reachable_in_code": _cited("no", tool="get_component")},
        ),
        tools_called={"get_component"},
        established={"component_present": True, "version_in_range": True},
        advisory_describes_flaw=True,
    )
    assert verdict.verdict == "not_applicable"
    assert verdict.verdict_confidence == 0.9


def test_the_established_facts_cannot_themselves_justify_dismissal():
    verdict = parse_verdict(
        _reply(verdict="not_applicable"),
        tools_called=set(),
        established={"component_present": True, "version_in_range": True},
    )
    assert verdict.verdict == "uncertain"
