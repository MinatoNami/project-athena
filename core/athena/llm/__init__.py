"""AI layer.

Every outbound call goes through athena.llm.gateway. There is deliberately no
provider client anywhere else in the codebase, so the egress policy cannot be
bypassed by accident.
"""

from athena.llm.gateway import (
    Completion,
    ModelUnavailable,
    complete,
    complete_json,
    health,
)
from athena.llm.budget import BudgetExhausted
from athena.llm.policy import DataClass, EgressBlocked

__all__ = [
    "complete",
    "complete_json",
    "health",
    "Completion",
    "ModelUnavailable",
    "BudgetExhausted",
    "EgressBlocked",
    "DataClass",
]
