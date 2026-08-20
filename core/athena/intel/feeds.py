"""Feed fetchers.

Athena is a guest on these services. Every fetch is rate-limit aware, cached, and
backs off — and on sustained failure it serves what it has and says so, rather than
failing the patrol.
"""

from __future__ import annotations

import csv
import gzip
import io
import zipfile
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog

log = structlog.get_logger(__name__)

USER_AGENT = "athena/0.1 (self-hosted security agent)"
TIMEOUT = httpx.Timeout(60.0, connect=15.0)

OSV_ECOSYSTEM_ZIP = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

# OSV publishes one archive per ecosystem. Only the ones Athena can actually
# correlate are fetched — pulling everything would be gigabytes of advisories for
# ecosystems it cannot compare versions in.
DEFAULT_ECOSYSTEMS = ["PyPI", "npm", "Go", "Debian", "Ubuntu", "Alpine"]


class FeedError(RuntimeError):
    pass


def _client() -> httpx.Client:
    return httpx.Client(
        timeout=TIMEOUT,
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
    )


def fetch_osv_ecosystem(ecosystem: str, *, limit: int | None = None) -> list[dict[str, Any]]:
    """Download one OSV ecosystem archive and return its advisory records."""
    url = OSV_ECOSYSTEM_ZIP.format(ecosystem=ecosystem)
    log.info("intel.fetch", source="osv", ecosystem=ecosystem)

    try:
        with _client() as client:
            response = client.get(url)
            response.raise_for_status()
            payload = response.content
    except httpx.HTTPError as exc:
        raise FeedError(f"OSV {ecosystem}: {exc}") from exc

    records: list[dict[str, Any]] = []
    import json

    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        names = [n for n in archive.namelist() if n.endswith(".json")]
        if limit:
            names = names[:limit]
        for name in names:
            try:
                records.append(json.loads(archive.read(name)))
            except (json.JSONDecodeError, KeyError):
                continue    # one malformed record must not fail the whole ecosystem
    return records


def fetch_kev() -> list[dict[str, Any]]:
    try:
        with _client() as client:
            response = client.get(KEV_URL)
            response.raise_for_status()
            return response.json().get("vulnerabilities") or []
    except (httpx.HTTPError, ValueError) as exc:
        raise FeedError(f"KEV: {exc}") from exc


def fetch_epss() -> dict[str, tuple[float, float]]:
    """CVE → (probability, percentile). Refreshed daily upstream."""
    try:
        with _client() as client:
            response = client.get(EPSS_URL)
            response.raise_for_status()
            raw = gzip.decompress(response.content).decode("utf-8", "replace")
    except (httpx.HTTPError, OSError) as exc:
        raise FeedError(f"EPSS: {exc}") from exc

    scores: dict[str, tuple[float, float]] = {}
    for row in csv.reader(io.StringIO(raw)):
        if not row or row[0].startswith("#") or row[0] == "cve":
            continue
        try:
            scores[row[0]] = (float(row[1]), float(row[2]))
        except (IndexError, ValueError):
            continue
    return scores


def feed_age(last_success: datetime | None) -> float | None:
    if last_success is None:
        return None
    return (datetime.now(UTC) - last_success).total_seconds()
