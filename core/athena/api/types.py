from __future__ import annotations

import re
from typing import Annotated

from pydantic import AfterValidator

_LOCAL_PART = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_DOMAIN = rf"{_LABEL}(?:\.{_LABEL})+"
_EMAIL_RE = re.compile(rf"^{_LOCAL_PART}@{_DOMAIN}$")

MAX_EMAIL_LENGTH = 320


def _validate_email(value: str) -> str:
    value = value.strip()
    if len(value) > MAX_EMAIL_LENGTH or not _EMAIL_RE.match(value):
        raise ValueError("Not a valid email address")
    return value.lower()


AccountEmail = Annotated[str, AfterValidator(_validate_email)]
