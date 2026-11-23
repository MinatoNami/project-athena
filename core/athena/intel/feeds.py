"""Feed fetchers.

Athena is a guest on these services. Every fetch is rate-limit aware, cached, and
backs off — and on sustained failure it serves what it has and says so, rather than
failing the patrol.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import re
import tempfile
import zipfile
from collections.abc import Iterator
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


def _client(timeout: float | None = None) -> httpx.Client:
    return httpx.Client(
        timeout=httpx.Timeout(timeout, connect=15.0) if timeout else TIMEOUT,
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
    )


def http_client(timeout: float | None = None) -> httpx.Client:
    """A client with Athena's identity and timeouts, for callers that batch requests."""
    return _client(timeout)


def fetch_osv_ecosystem(
    ecosystem: str, *, limit: int | None = None, timeout: float = 1800.0
) -> Iterator[dict[str, Any]]:
    """Stream one OSV ecosystem archive, yielding advisory records.

    Streamed to a temporary file and yielded lazily rather than held in memory: the
    Ubuntu archive is hundreds of megabytes and tens of thousands of advisories, and
    buffering it defeats the batching the caller does downstream.
    """
    url = OSV_ECOSYSTEM_ZIP.format(ecosystem=ecosystem)
    log.info("intel.fetch", source="osv", ecosystem=ecosystem)

    with tempfile.NamedTemporaryFile(suffix=".zip") as spool:
        try:
            with _client(timeout) as client, client.stream("GET", url) as response:
                response.raise_for_status()
                for chunk in response.iter_bytes(chunk_size=1 << 20):
                    spool.write(chunk)
        except httpx.HTTPError as exc:
            raise FeedError(f"OSV {ecosystem}: {exc}") from exc

        spool.flush()
        size_mb = round(spool.tell() / (1 << 20), 1)
        log.info("intel.fetched", source="osv", ecosystem=ecosystem, size_mb=size_mb)

        with zipfile.ZipFile(spool.name) as archive:
            names = [n for n in archive.namelist() if n.endswith(".json")]
            if limit:
                names = names[:limit]
            for name in names:
                try:
                    yield json.loads(archive.read(name))
                except (json.JSONDecodeError, KeyError, zipfile.BadZipFile):
                    continue    # one malformed record must not fail the ecosystem


def fetch_kev() -> list[dict[str, Any]]:
    try:
        with _client() as client:
            response = client.get(KEV_URL)
            response.raise_for_status()
            return response.json().get("vulnerabilities") or []
    except (httpx.HTTPError, ValueError) as exc:
        raise FeedError(f"KEV: {exc}") from exc


def fetch_epss() -> tuple[dict[str, tuple[float, float]], dict[str, str]]:
    """CVE → (probability, percentile), and the file's model metadata.

    Refreshed daily upstream.
    """
    try:
        with _client() as client:
            response = client.get(EPSS_URL)
            response.raise_for_status()
            raw = gzip.decompress(response.content).decode("utf-8", "replace")
    except (httpx.HTTPError, OSError) as exc:
        raise FeedError(f"EPSS: {exc}") from exc
    return parse_epss_csv(raw)


def parse_epss_csv(raw: str) -> tuple[dict[str, tuple[float, float]], dict[str, str]]:
    """Scores, plus the `#model_version:…,score_date:…` header as a dict.

    The model version is kept because scores jump at a version boundary — EPSS v5
    replaced v4 on 2026-06-15 and moved Log4Shell from 0.94 to 0.99999 overnight —
    and a score without its model is a number nobody can compare with last month's.
    """
    scores: dict[str, tuple[float, float]] = {}
    meta: dict[str, str] = {}
    for row in csv.reader(io.StringIO(raw)):
        if not row:
            continue
        if row[0].startswith("#"):
            for cell in row:
                key, sep, value = cell.lstrip("#").partition(":")
                if sep and key.strip():
                    meta[key.strip()] = value.strip()
            continue
        if row[0] == "cve":
            continue
        try:
            scores[row[0]] = (float(row[1]), float(row[2]))
        except (IndexError, ValueError):
            continue
    return scores, meta


# CISA's Vulnrichment repository: one CVE JSON 5.x record per file, carrying CISA's
# ADP container with its SSVC assessment. Raw GitHub is used rather than the CVE
# Services API because it is a static file host with no per-client rate limit
# worth negotiating, and the repository is CISA's own publication of the data.
VULNRICHMENT_URL = (
    "https://raw.githubusercontent.com/cisagov/vulnrichment/develop/{year}/{bucket}xxx/{cve}.json"
)
_CVE = re.compile(r"^CVE-(\d{4})-(\d{4,19})$")


def vulnrichment_url(cve: str) -> str | None:
    """The file for one CVE, or None if the id is not a CVE this layout can hold."""
    match = _CVE.match(cve or "")
    if not match:
        return None
    year, number = match.group(1), int(match.group(2))
    return VULNRICHMENT_URL.format(year=year, bucket=number // 1000, cve=cve)


def fetch_vulnrichment(client: httpx.Client, cve: str) -> dict[str, Any] | None:
    """CISA's record for one CVE, or None when CISA has published none (404)."""
    url = vulnrichment_url(cve)
    if url is None:
        return None
    try:
        response = client.get(url)
    except httpx.HTTPError as exc:
        raise FeedError(f"Vulnrichment {cve}: {exc}") from exc
    if response.status_code == 404:
        return None
    if response.status_code != 200:
        raise FeedError(f"Vulnrichment {cve}: HTTP {response.status_code}")
    try:
        return response.json()
    except ValueError as exc:
        raise FeedError(f"Vulnrichment {cve}: not JSON") from exc


CISA_ADP = "CISA-ADP"
_SSVC_KEYS = {
    "exploitation": "exploitation",
    "automatable": "automatable",
    "technical impact": "technical_impact",
    "technicalimpact": "technical_impact",
}


def parse_vulnrichment(record: dict[str, Any]) -> dict[str, Any] | None:
    """CISA's SSVC decision points from a CVE JSON 5.x record, or None.

    `options` is a list of one-key objects (`[{"Exploitation": "poc"}, …]`), so it is
    flattened. Only the container CISA signs as `CISA-ADP` is read: the record holds
    other providers' containers too, and their opinions are not CISA's.
    """
    containers = (record.get("containers") or {}).get("adp") or []
    for container in containers:
        provider = (container.get("providerMetadata") or {}).get("shortName")
        if provider != CISA_ADP:
            continue
        for metric in container.get("metrics") or []:
            other = metric.get("other") or {}
            if (other.get("type") or "").lower() != "ssvc":
                continue
            content = other.get("content") or {}
            out: dict[str, Any] = {}
            for option in content.get("options") or []:
                if not isinstance(option, dict):
                    continue
                for key, value in option.items():
                    name = _SSVC_KEYS.get(str(key).strip().lower())
                    if name and isinstance(value, str):
                        out[name] = value.strip().lower()
            if not out:
                continue
            out["timestamp"] = content.get("timestamp")
            out["version"] = content.get("version")
            out["role"] = content.get("role")
            return out
    return None


def feed_age(last_success: datetime | None) -> float | None:
    if last_success is None:
        return None
    return (datetime.now(UTC) - last_success).total_seconds()
