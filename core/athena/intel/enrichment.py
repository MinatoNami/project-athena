"""Which CVEs are worth one request each to CISA's Vulnrichment.

One predicate, used twice: by the enrichment job to choose what to look up, and by
/intel/sources to state its coverage. Written apart, the two drifted — the job
skipped withdrawn CVEs and the coverage figure still counted them, so the figure
could never reach its own total. Only "when was it last asked" belongs to the job
alone.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import exists

from athena.db.models import Finding, Vulnerability

# A finding in one of these states is no reason to ask CISA about its CVE.
SKIP_STATES = ("resolved", "false_positive", "unmatched")


def eligible() -> list[Any]:
    """Conditions on `Vulnerability`: a CVE, not withdrawn, with a finding still open."""
    return [
        Vulnerability.id.like("CVE-%"),
        Vulnerability.withdrawn_at.is_(None),
        exists().where(
            Finding.vulnerability_id == Vulnerability.id,
            Finding.state.notin_(SKIP_STATES),
        ),
    ]
