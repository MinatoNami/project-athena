"""Triage.

Triage decides where the expensive loop is spent. It must never decide whether a
vulnerability applies — it has no tools and no evidence, only a summary.
"""

from __future__ import annotations

import pytest

from athena.investigation.triage import (
    DEPRIORITISE_THRESHOLD,
    _hard_gates,
    triage,
)


def facts(**overrides):
    base = {
        "asset": {"name": "host", "kind": "host", "tier": "development",
                  "exposure": "internal", "os": "Ubuntu 24.04"},
        "component": {"name": "bluez", "version": "5.72", "ecosystem": "deb"},
        "advisory": {"id": "CVE-2026-1", "summary": "Bluetooth stack issue",
                     "severity": "low", "cvss": None, "epss": None,
                     "known_exploited": False},
        "fix": {"fixed_version": None, "channel": None},
    }
    for key, value in overrides.items():
        base.setdefault(key, {}).update(value)
    return base


# ── gates that the model cannot override ─────────────────────────────────────

@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"advisory": {"known_exploited": True}}, "exploited"),
        ({"advisory": {"cvss": 9.8}}, "CVSS"),
        ({"advisory": {"epss": 0.4}}, "EPSS"),
        ({"asset": {"exposure": "internet", "tier": "production"}}, "internet-facing"),
    ],
)
def test_some_findings_are_always_investigated(overrides, expected):
    """In code, not in the prompt. A model asked nicely not to skip known-exploited
    vulnerabilities will still occasionally skip one."""
    reason = _hard_gates(facts(**overrides))
    assert reason is not None and expected in reason


def test_an_ordinary_finding_has_no_hard_gate():
    assert _hard_gates(facts()) is None


def test_a_gated_finding_never_reaches_the_model(monkeypatch):
    import athena.investigation.triage as t

    def explode(**kwargs):
        raise AssertionError("the model must not be consulted for a gated finding")

    monkeypatch.setattr(t, "complete_json", explode)
    result = triage(facts(advisory={"known_exploited": True}))
    assert result.disposition == "investigate"
    assert result.forced is True


# ── the asymmetry ────────────────────────────────────────────────────────────

def test_a_low_confidence_deprioritise_becomes_an_investigate(monkeypatch):
    """Doubt is information, not a decision. Investigating something irrelevant costs
    seconds; overlooking something real costs much more."""
    import athena.investigation.triage as t

    monkeypatch.setattr(
        t, "complete_json",
        lambda **kw: (
            {"disposition": "deprioritise", "confidence": 0.5, "reason": "probably fine"},
            type("C", (), {"prompt_tokens": 10, "completion_tokens": 10, "duration_ms": 5})(),
        ),
    )
    result = triage(facts())
    assert result.disposition == "investigate"
    assert result.forced is True
    assert "below the" in result.reason


def test_a_confident_deprioritise_is_honoured(monkeypatch):
    import athena.investigation.triage as t

    monkeypatch.setattr(
        t, "complete_json",
        lambda **kw: (
            {"disposition": "deprioritise", "confidence": 0.9,
             "reason": "firmware for hardware this host does not have"},
            type("C", (), {"prompt_tokens": 10, "completion_tokens": 10, "duration_ms": 5})(),
        ),
    )
    result = triage(facts())
    assert result.disposition == "deprioritise"
    assert result.forced is False


def test_the_threshold_is_conservative():
    assert DEPRIORITISE_THRESHOLD >= 0.7


def test_a_model_failure_queues_rather_than_drops(monkeypatch):
    """A triage outage must not silently discard findings."""
    import athena.investigation.triage as t

    def fail(**kwargs):
        raise RuntimeError("model down")

    monkeypatch.setattr(t, "complete_json", fail)
    result = triage(facts())
    assert result.disposition == "investigate"
    assert "could not run" in result.reason


def test_triage_is_cheap_by_construction():
    """It exists to avoid the expensive loop; a large budget would defeat it."""
    from athena.investigation.loop import MAX_TOOL_CALLS
    from athena.investigation.triage import MAX_TOKENS

    assert MAX_TOKENS <= 2000
    assert MAX_TOOL_CALLS >= 1, "triage has no tool loop at all"
