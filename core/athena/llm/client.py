"""Placeholder for the model provider abstraction (M3).

Every outbound model call will pass through the egress gateway, never directly
through a provider SDK.
"""

from __future__ import annotations


class ModelClient:
    def __init__(self) -> None:
        raise NotImplementedError("The AI layer lands in M3.")
