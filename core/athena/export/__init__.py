"""Machine-readable exports: what Athena knows, in formats other tools read.

Two documents, two different claims.

* An **SBOM** (CycloneDX) states what was *observed* on an asset. It is a record of
  inventory, carries the scan that produced it, and says so when that scan was
  partial.

* A **VEX** (OpenVEX) states, per vulnerability, whether a product is affected. That
  is an assertion other tools will act on — Trivy and Grype both drop findings a VEX
  marks `not_affected` — so it is held to a stricter rule than anything on a page:
  only a person's recorded decision can produce `not_affected`. An automated verdict
  of "not applicable" is exported as `under_investigation` with a note, because the
  model does not hold authority here any more than it does over a change.
"""

from athena.export.cyclonedx import sbom_for
from athena.export.openvex import vex_document

__all__ = ["sbom_for", "vex_document"]
