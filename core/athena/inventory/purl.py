from __future__ import annotations

from urllib.parse import quote

_CASE_INSENSITIVE = {"pypi", "npm", "deb", "rpm", "apk", "nuget", "hex", "cran"}


def normalise_name(ecosystem: str, name: str) -> str:
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
        return name

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
    eco = ecosystem.lower()
    name = normalise_name(eco, name)

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
