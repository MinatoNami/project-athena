from __future__ import annotations

import re

from athena.llm.policy import DataClass

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws access key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer token", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{24,}={0,2}")),
    ("basic auth in url", re.compile(r"https?://[^/\s:@]+:[^/\s@]+@")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("generic api key", re.compile(
        r"(?i)\b(api[_-]?key|secret|passwd|password|token)\b\s*[:=]\s*['\"]?[A-Za-z0-9/+=_-]{16,}")),
]

_HOSTNAME = re.compile(
    r"\b(?:[a-z0-9-]+\.)+(?:internal|local|lan|ts\.net)\b"
    r"|\b\d+\.\d+\.\d+\.\d+\b"
)
_PATH = re.compile(r"/(?:etc|var|home|root|usr|opt|srv)/[\w./-]+")
_CODE = re.compile(r"^\s*(?:def |class |function |import |from \w+ import|#include|package )", re.M)


def find_secrets(text: str) -> list[str]:
    return [name for name, pattern in SECRET_PATTERNS if pattern.search(text)]


def classify(text: str) -> set[DataClass]:
    classes = {DataClass.PACKAGE_METADATA}

    if find_secrets(text):
        classes.add(DataClass.SECRETS)
    if _HOSTNAME.search(text):
        classes.add(DataClass.HOSTNAMES)
    if _PATH.search(text):
        classes.add(DataClass.FILE_PATHS)
    if _CODE.search(text):
        classes.add(DataClass.SOURCE_CODE)
    if len(text) > 400 and ("CVE-" in text or "advisory" in text.lower()):
        classes.add(DataClass.ADVISORY_TEXT)
    return classes


def redact(text: str) -> str:
    for _, pattern in SECRET_PATTERNS:
        text = pattern.sub("[redacted]", text)
    return text
