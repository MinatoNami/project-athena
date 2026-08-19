"""Package URL construction and name normalisation.

Correlation (M2) matches advisories to components by identifier, so a name that is
normalised inconsistently is a silent miss. Each ecosystem's rules are applied here,
once, rather than at every call site.
"""

from __future__ import annotations

from urllib.parse import quote

# Ecosystems whose package names are case-insensitive, so the canonical form is lower.
_CASE_INSENSITIVE = {"pypi", "npm", "deb", "rpm", "apk", "nuget", "hex", "cran"}


def normalise_name(ecosystem: str, name: str) -> str:
    """Canonical package name for an ecosystem.

    PyPI in particular treats runs of `-`, `_`, and `.` as equivalent (PEP 503), so
    `Flask_SQLAlchemy` and `flask-sqlalchemy` are the same package and must produce
    the same identifier.
    """
    eco = ecosystem.lower()
    name = name.strip()

    if eco == "pypi":
        out, prev_sep = [], False
        for ch in name.lower():
            if ch in "-_.":
                if not prev_sep:
                    out.append("-")
                prev_sep = True
            else:
                out.append(ch)
                prev_sep = False
        return "".join(out).strip("-")

    if eco == "golang":
        return name  # module paths are case-sensitive

    if eco in _CASE_INSENSITIVE:
        return name.lower()
    return name


def build_purl(
    ecosystem: str,
    name: str,
    version: str,
    *,
    namespace: str | None = None,
    qualifiers: dict[str, str] | None = None,
) -> str:
    """A Package URL, e.g. `pkg:pypi/requests@2.31.0`.

    Qualifiers are sorted so the same component always yields a byte-identical PURL —
    the value is used as a lookup key, so instability would fragment the index.
    """
    eco = ecosystem.lower()
    name = normalise_name(eco, name)

    # npm carries its scope in the namespace: @scope/pkg -> namespace=@scope
    if eco == "npm" and namespace is None and name.startswith("@") and "/" in name:
        namespace, name = name.split("/", 1)

    parts = [f"pkg:{quote(eco, safe='')}"]
    if namespace:
        parts.append(quote(namespace, safe="@"))
    parts.append(quote(name, safe="@"))

    purl = "/".join(parts) + f"@{quote(version.strip(), safe='')}"

    if qualifiers:
        encoded = "&".join(
            f"{k}={quote(str(v), safe='')}" for k, v in sorted(qualifiers.items()) if v
        )
        if encoded:
            purl += f"?{encoded}"
    return purl


def parse_purl(purl: str) -> dict[str, str] | None:
    """Minimal PURL parse: enough to recover ecosystem, name, and version."""
    if not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("?", 1)[0]
    if "@" not in body:
        return None
    path, _, version = body.rpartition("@")
    segments = [s for s in path.split("/") if s]
    if len(segments) < 2:
        return None
    ecosystem, name = segments[0], "/".join(segments[1:])
    return {"ecosystem": ecosystem, "name": name, "version": version}
