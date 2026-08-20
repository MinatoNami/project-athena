"""What may leave the network, and to whom.

Athena holds a structured map of every weakness in an estate. The question "what
has left my network?" must be answerable exactly, so every outbound model call passes
through this module — there is no direct provider client anywhere else.
"""

from __future__ import annotations

import re
from enum import StrEnum


class DataClass(StrEnum):
    """Categories of content, ordered roughly by sensitivity."""

    PACKAGE_METADATA = "package_metadata"   # names, versions, PURLs
    ADVISORY_TEXT = "advisory_text"         # published CVE text
    CONFIG_SHAPE = "config_shape"           # which settings exist, not their values
    FILE_PATHS = "file_paths"
    HOSTNAMES = "hostnames"
    CONFIG_VALUES = "config_values"
    SOURCE_CODE = "source_code"
    SECRETS = "secrets"


# Never sent anywhere, including to a local model: a credential in a prompt ends up
# in logs, caches, and model context for no benefit whatsoever.
NEVER_SEND = {DataClass.SECRETS}

# A local provider keeps everything inside the network, so the policy is permissive —
# but not unbounded, because "local" is a claim about the endpoint that has to be
# verified (see is_local_endpoint).
LOCAL_ALLOWED = {c for c in DataClass if c not in NEVER_SEND}

# A hosted provider gets only what is already public or non-identifying, unless the
# operator widens it deliberately.
HOSTED_DEFAULT_ALLOWED = {
    DataClass.PACKAGE_METADATA,
    DataClass.ADVISORY_TEXT,
    DataClass.CONFIG_SHAPE,
}


class EgressBlocked(RuntimeError):
    """Raised when a payload may not be sent. Never downgraded to a warning."""


_LOOPBACK = re.compile(r"^https?://(127\.0\.0\.1|localhost|\[::1\]|host\.docker\.internal)(:|/|$)")
_PRIVATE = re.compile(
    r"^https?://("
    r"10\.\d+\.\d+\.\d+|"
    r"192\.168\.\d+\.\d+|"
    r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|"
    r"100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d+\.\d+|"   # tailnet CGNAT range
    r"(?:[a-z0-9-]+\.)+ts\.net|"          # tailnet MagicDNS, any depth
    r"[a-z0-9-]+"                                          # bare container hostname
    r")(:|/|$)"
)


def is_local_endpoint(base_url: str) -> bool:
    """Whether an endpoint is inside the operator's own network.

    Deliberately conservative: anything not recognisably loopback, RFC1918, or a
    tailnet address is treated as hosted, so a misconfiguration errs towards the
    stricter policy rather than the looser one.
    """
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
