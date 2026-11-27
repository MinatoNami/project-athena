from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()
