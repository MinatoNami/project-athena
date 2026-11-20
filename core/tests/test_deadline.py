"""BOD 26-04 remediation deadlines.

Every row of the directive's Table 1 is pinned, because the table is the rule and
the function is only a transcription of it. The rest asserts the two places the
directive is easy to misread: when the clock starts, and what to assume when CISA
has published nothing.
"""

from __future__ import annotations

from datetime import date

import pytest

from athena.risk.deadline import deadline

NET_TOTAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # automatable, total
NET_PARTIAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"  # automatable, partial
LOCAL_TOTAL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"  # not automatable, total
LOCAL_PARTIAL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"  # not automatable, partial

SEEN = date(2026, 11, 1)


def _due(*, exposed, kev, vector, cisa=None, kev_added=None):
    return deadline(
        exposure="internet" if exposed else "internal",
        kev=kev,
        kev_date_added=kev_added,
        vector=vector,
        cisa_ssvc=cisa,
        first_seen=SEEN,
    )


@pytest.mark.parametrize(
    ("exposed", "kev", "vector", "days", "triage"),
    [
        (True, True, NET_TOTAL, 3, True),
        (True, True, NET_PARTIAL, 3, False),
        (True, True, LOCAL_TOTAL, 3, True),
        (True, True, LOCAL_PARTIAL, 14, False),
        (True, False, NET_TOTAL, 3, False),
        (True, False, NET_PARTIAL, 14, False),
        (True, False, LOCAL_TOTAL, 14, False),
        (True, False, LOCAL_PARTIAL, 60, False),
        (False, True, NET_TOTAL, 3, True),
        (False, True, NET_PARTIAL, 14, False),
        (False, True, LOCAL_TOTAL, 14, False),
        (False, True, LOCAL_PARTIAL, 14, False),
        (False, False, NET_TOTAL, 60, False),
        (False, False, NET_PARTIAL, 60, False),
        (False, False, LOCAL_TOTAL, None, False),
        (False, False, LOCAL_PARTIAL, None, False),
    ],
)
def test_table_one(exposed, kev, vector, days, triage):
    d = _due(exposed=exposed, kev=kev, vector=vector)
    assert (d.days, d.forensic_triage) == (days, triage)


def test_fix_on_upgrade_has_no_date_and_says_so():
    d = _due(exposed=False, kev=False, vector=LOCAL_TOTAL)
    assert d.due is None
    assert any("upgrade" in n for n in d.notes)


def test_clock_starts_at_detection_when_that_is_earlier():
    d = _due(exposed=True, kev=True, vector=NET_TOTAL, kev_added=date(2026, 11, 10))
    assert d.clock_start == SEEN and d.due == date(2026, 11, 4)


def test_clock_starts_at_kev_addition_when_that_is_earlier():
    d = _due(exposed=True, kev=True, vector=NET_TOTAL, kev_added=date(2026, 10, 20))
    assert d.clock_start == date(2026, 10, 20) and d.due == date(2026, 10, 23)


def test_cisa_assessment_outranks_the_vector():
    """The vector says automatable and total; CISA says neither."""
    cisa = {"automatable": "no", "technical_impact": "partial"}
    d = _due(exposed=True, kev=False, vector=NET_TOTAL, cisa=cisa)
    assert d.days == 60
    assert "Vulnrichment" in d.inputs["automatable"].basis


def test_no_assessment_and_no_vector_takes_cisas_defaults():
    """Implementation guidance: Automatable no, Technical Impact total."""
    d = _due(exposed=True, kev=False, vector=None)
    assert d.inputs["automatable"].value is False
    assert d.inputs["total_impact"].value is True
    assert d.days == 14
    assert {"automatable", "total_impact"} <= {k for k, v in d.inputs.items() if v.assumed}


def test_unclassified_exposure_is_treated_as_exposed_and_marked():
    d = deadline(
        exposure="unknown",
        kev=False,
        kev_date_added=None,
        vector=NET_TOTAL,
        cisa_ssvc=None,
        first_seen=SEEN,
    )
    assert d.inputs["exposed"].value is True and d.inputs["exposed"].assumed
    assert d.days == 3


def test_as_dict_counts_days_left():
    d = _due(exposed=True, kev=True, vector=NET_TOTAL)
    out = d.as_dict(today=date(2026, 11, 6))
    assert out["days_left"] == -2
    assert out["framework"].startswith("CISA BOD 26-04")
