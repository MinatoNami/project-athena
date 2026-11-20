"""Findings in a repository's tree that are not package versions: secrets and
misconfigurations.

See `CodeFinding` for why they live in a table of their own.
"""

from athena.codefindings.model import CodeObservation, normalise_severity
from athena.codefindings.service import GUIDANCE, record_code_scan

__all__ = ["GUIDANCE", "CodeObservation", "normalise_severity", "record_code_scan"]
