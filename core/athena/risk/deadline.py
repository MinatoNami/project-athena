from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Any

from athena.risk import ssvc

UPGRADE = None

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
    key = {"automatable": "automatable", "technical_impact": "technical_impact"}[name]
    if cisa and cisa.get(key) in ("yes", "no", "partial", "total"):
        value = cisa[key] in ("yes", "total")
        return Input(value, f"CISA Vulnrichment assessment ({cisa[key]})")
    try:
        ssvc_point = (
            ssvc.automatable(vector) if name == "automatable" else ssvc.technical_impact(vector)
        )
    except Exception:  # noqa: BLE001
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
