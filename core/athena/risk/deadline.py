"""Remediation deadlines under CISA BOD 26-04 (June 2026), as a benchmark.

BOD 26-04 replaced BOD 22-01 with a deadline read from four facts: whether the asset
is publicly exposed, whether the flaw is in KEV, whether exploitation is automatable,
and whether its technical impact is total. Athena holds or derives all four, so the
deadline is a pure function here — the same discipline as the score — and every
input reports where it came from.

It binds US federal agencies only. For everyone else it is the most widely
recognised external yardstick for "how long is too long", which is why it is shown
as a benchmark beside Athena's own band rather than as a rule Athena enforces.

Two rules from the directive's implementation guidance are followed as written, even
where Athena's own instinct differs:

* With no CISA assessment and no readable vector, Automatable is taken as **no** and
  Technical Impact as **total** — CISA's stated default. (The SSVC decision on the
  same page takes the conservative branch instead; the difference is labelled.)
* The clock starts at whichever is earlier: the flaw's addition to KEV, or Athena
  first finding it on this asset.

Exposure follows Athena's own rule: an asset nobody has classified is treated as
exposed and marked assumed, because the directive's whole first column turns on it
and "unknown" must not quietly earn the longer deadline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Any

from athena.risk import ssvc

UPGRADE = None  # "fix on system upgrade": no calendar deadline

# (exposed, kev, automatable) → (days if total, days if partial), with forensic
# triage required where the tuple's flag says so. BOD 26-04 Table 1.
_TABLE: dict[tuple[bool, bool, bool], tuple[tuple[int | None, bool], tuple[int | None, bool]]] = {
    (True, True, True): ((3, True), (3, False)),
    (True, True, False): ((3, True), (14, False)),
    (True, False, True): ((3, False), (14, False)),
    (True, False, False): ((14, False), (60, False)),
    (False, True, True): ((3, True), (14, False)),
    (False, True, False): ((14, False), (14, False)),
    (False, False, True): ((60, False), (60, False)),
    (False, False, False): ((UPGRADE, False), (UPGRADE, False)),
}


@dataclass
class Input:
    value: bool
    basis: str
    assumed: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {"value": self.value, "basis": self.basis, "assumed": self.assumed}


@dataclass
class Deadline:
    days: int | None
    forensic_triage: bool
    clock_start: date
    due: date | None
    inputs: dict[str, Input]
    notes: list[str] = field(default_factory=list)

    def as_dict(self, *, today: date) -> dict[str, Any]:
        return {
            "framework": "CISA BOD 26-04 (benchmark)",
            "days": self.days,
            "on_upgrade": self.days is None,
            "forensic_triage": self.forensic_triage,
            "clock_start": self.clock_start,
            "due": self.due,
            "days_left": (self.due - today).days if self.due else None,
            "inputs": {k: v.as_dict() for k, v in self.inputs.items()},
            "assumed": [k for k, v in self.inputs.items() if v.assumed],
            "notes": self.notes,
        }


def _exposed(exposure: str | None) -> Input:
    exposure = (exposure or "unknown").lower()
    if exposure == "internet":
        return Input(True, "the asset is classified internet-facing")
    if exposure == "unknown":
        return Input(True, "exposure is unclassified; treated as exposed", assumed=True)
    return Input(False, f"the asset is classified {exposure}")


def _from_cisa_or_vector(name: str, cisa: dict[str, Any] | None, vector: str | None) -> Input:
    """Automatable / technical impact: CISA's own assessment first, then the vector."""
    key = {"automatable": "automatable", "technical_impact": "technical_impact"}[name]
    if cisa and cisa.get(key) in ("yes", "no", "partial", "total"):
        value = cisa[key] in ("yes", "total")
        return Input(value, f"CISA Vulnrichment assessment ({cisa[key]})")
    try:
        ssvc_point = (
            ssvc.automatable(vector) if name == "automatable" else ssvc.technical_impact(vector)
        )
    except Exception:  # noqa: BLE001 - a malformed vector falls to the default below
        ssvc_point = None
    if ssvc_point is not None and not ssvc_point.assumed:
        return Input(ssvc_point.value in ("yes", "total"), ssvc_point.basis)
    if name == "automatable":
        return Input(False, "no assessment and no vector: CISA's default is no", True)
    return Input(True, "no assessment and no vector: CISA's default is total", True)


def deadline(
    *,
    exposure: str | None,
    kev: bool,
    kev_date_added: date | None,
    vector: str | None,
    cisa_ssvc: dict[str, Any] | None,
    first_seen: date,
) -> Deadline:
    """The BOD 26-04 deadline for one finding on one asset."""
    inputs = {
        "exposed": _exposed(exposure),
        "kev": Input(kev, "listed in CISA KEV" if kev else "not in CISA KEV"),
        "automatable": _from_cisa_or_vector("automatable", cisa_ssvc, vector),
        "total_impact": _from_cisa_or_vector("technical_impact", cisa_ssvc, vector),
    }
    total, partial = _TABLE[(inputs["exposed"].value, kev, inputs["automatable"].value)]
    days, triage = total if inputs["total_impact"].value else partial

    start = first_seen
    if kev and kev_date_added is not None and kev_date_added < first_seen:
        start = kev_date_added
    due = start + timedelta(days=days) if days is not None else None

    notes: list[str] = []
    if days is None:
        notes.append("No calendar deadline: remediate in the next system upgrade.")
    if triage:
        notes.append(
            "Forensic triage required: establish whether the asset was compromised "
            "before the fix, not only that it is now patched."
        )
    return Deadline(
        days=days, forensic_triage=triage, clock_start=start, due=due, inputs=inputs, notes=notes
    )
