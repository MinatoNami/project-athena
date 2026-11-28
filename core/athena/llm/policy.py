from __future__ import annotations

import re
from enum import StrEnum


class DataClass(StrEnum):
    PACKAGE_METADATA = "package_metadata"
    ADVISORY_TEXT = "advisory_text"
    CONFIG_SHAPE = "config_shape"
    FILE_PATHS = "file_paths"
    HOSTNAMES = "hostnames"
    CONFIG_VALUES = "config_values"
    SOURCE_CODE = "source_code"
    SECRETS = "secrets"


NEVER_SEND = {DataClass.SECRETS}

LOCAL_ALLOWED = {c for c in DataClass if c not in NEVER_SEND}

HOSTED_DEFAULT_ALLOWED = {
    DataClass.PACKAGE_METADATA,
    DataClass.ADVISORY_TEXT,
    DataClass.CONFIG_SHAPE,
}


class EgressBlocked(RuntimeError):
    pass


_LOOPBACK = re.compile(r"^https?://(127\.0\.0\.1|localhost|\[::1\]|host\.docker\.internal)(:|/|$)")
_PRIVATE = re.compile(
    r"^https?://("
    r"10\.\d+\.\d+\.\d+|"
    r"192\.168\.\d+\.\d+|"
    r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|"
    r"100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d+\.\d+|"
    r"(?:[a-z0-9-]+\.)+ts\.net|"
    r"[a-z0-9-]+"
    r")(:|/|$)"
)


def is_local_endpoint(base_url: str) -> bool:
    url = (base_url or "").strip().lower()
    return bool(_LOOPBACK.match(url) or _PRIVATE.match(url))


def allowed_classes(
    *, base_url: str, mode: str, extra: set[DataClass] | None = None
) -> set[DataClass]:
    if mode == "local_only" and not is_local_endpoint(base_url):
        raise EgressBlocked(
            f"AI mode is local_only but {base_url!r} is not a local endpoint. "
            "Refusing to send anything rather than silently downgrading the policy."
        )
    base = LOCAL_ALLOWED if is_local_endpoint(base_url) else HOSTED_DEFAULT_ALLOWED
    return (base | (extra or set())) - NEVER_SEND
