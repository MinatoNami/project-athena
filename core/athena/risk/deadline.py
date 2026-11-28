from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Any

from athena.risk import ssvc

UPGRADE = None
SHORT = "short"
MEDIUM = "medium"
LONG = "long"

RULE_TABLE = "bod_table"
RULE_KEV_DUE_DATE = "kev_due_date"

_TABLE: dict[tuple[bool, bool, bool], tuple[tuple[str | None, bool], tuple[str | None, bool]]] = {
    (True, True, True): ((SHORT, True), (SHORT, False)),
    (True, True, False): ((SHORT, True), (MEDIUM, False)),
    (True, False, True): ((SHORT, False), (MEDIUM, False)),
    (True, False, False): ((MEDIUM, False), (LONG, False)),
    (False, True, True): ((SHORT, True), (MEDIUM, False)),
    (False, True, False): ((MEDIUM, False), (MEDIUM, False)),
    (False, False, True): ((LONG, False), (LONG, False)),
    (False, False, False): ((UPGRADE, False), (UPGRADE, False)),
}


@dataclass(frozen=True)
class Windows:
    short: int = 3
    medium: int = 14
    long: int = 60

    def __post_init__(self) -> None:
        for name in (SHORT, MEDIUM, LONG):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(
                    f"the {name} deadline window must be a positive whole number of days"
                )
        if not self.short <= self.medium <= self.long:
            raise ValueError(
                "deadline windows must be ordered short <= medium <= long "
                f"(got {self.short}, {self.medium}, {self.long})"
            )

    def days(self, window: str | None) -> int | None:
        return None if window is None else getattr(self, window)


def configured_windows() -> Windows:
    from athena.config import get_settings

    settings = get_settings()
    return Windows(
        short=settings.deadline_window_short_days,
        medium=settings.deadline_window_medium_days,
        long=settings.deadline_window_long_days,
    )


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
    computed_due: date | None = None
    kev_due_date: date | None = None
    due_rule: str = RULE_TABLE

    def as_dict(self, *, today: date) -> dict[str, Any]:
        return {
            "framework": "CISA BOD 26-04 (benchmark)",
            "days": self.days,
            "on_upgrade": self.days is None and self.due is None,
            "forensic_triage": self.forensic_triage,
            "clock_start": self.clock_start,
            "due": self.due,
            "due_rule": self.due_rule,
            "computed_due": self.computed_due,
            "kev_due_date": self.kev_due_date,
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
    kev_due_date: date | None = None,
    windows: Windows | None = None,
) -> Deadline:
    windows = windows or configured_windows()
    inputs = {
        "exposed": _exposed(exposure),
        "kev": Input(kev, "listed in CISA KEV" if kev else "not in CISA KEV"),
        "automatable": _from_cisa_or_vector("automatable", cisa_ssvc, vector),
        "total_impact": _from_cisa_or_vector("technical_impact", cisa_ssvc, vector),
    }
    total, partial = _TABLE[(inputs["exposed"].value, kev, inputs["automatable"].value)]
    window, triage = total if inputs["total_impact"].value else partial
    days = windows.days(window)

    start = first_seen
    if kev and kev_date_added is not None and kev_date_added < first_seen:
        start = kev_date_added
    computed_due = start + timedelta(days=days) if days is not None else None

    feed_due = kev_due_date if kev else None
    due, rule = computed_due, RULE_TABLE
    if feed_due is not None and (computed_due is None or feed_due < computed_due):
        due, rule = feed_due, RULE_KEV_DUE_DATE

    notes: list[str] = []
    if rule == RULE_KEV_DUE_DATE:
        notes.append(
            f"CISA's KEV due date ({feed_due}) is earlier than the table's deadline, "
            "so it sets the due date."
        )
    elif days is None:
        notes.append("No calendar deadline: remediate in the next system upgrade.")
    if triage:
        notes.append(
            "Forensic triage required: establish whether the asset was compromised "
            "before the fix, not only that it is now patched."
        )
    return Deadline(
        days=days,
        forensic_triage=triage,
        clock_start=start,
        due=due,
        inputs=inputs,
        notes=notes,
        computed_due=computed_due,
        kev_due_date=feed_due,
        due_rule=rule,
    )
