"""Repository checkout.

Cloning is the one step that needs network, so it is isolated from analysis: the
clone container reaches the git host and nothing else touches it, then every
subsequent scanner runs over the checkout with no network at all.
"""

from __future__ import annotations

import re
import uuid

import structlog

from athena.scanners.sandbox import Mount, SandboxSpec, run_sandboxed

log = structlog.get_logger(__name__)

GIT_IMAGE = "alpine/git:latest"
CLONE_TIMEOUT = 600

_SAFE_URL = re.compile(r"^(https://|git@|ssh://)[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$")


class CheckoutError(RuntimeError):
    pass


def _validate(url: str) -> None:
    """Reject anything that is not plainly a remote URL.

    The URL reaches a command line, so `--upload-pack=...`, `ext::sh -c ...`, and
    local `file://` paths are all refused rather than escaped.
    """
    if not _SAFE_URL.match(url):
        raise CheckoutError(f"Refusing to clone an unsupported or unsafe URL: {url!r}")
    lowered = url.lower()
    for scheme in ("ext::", "file://", "--upload-pack", "--config"):
        if scheme in lowered:
            raise CheckoutError(f"Refusing to clone a URL containing {scheme!r}")


def clone(
    url: str,
    *,
    work_volume: str,
    ref: str | None = None,
    depth: int = 1,
) -> tuple[str, str]:
    """Shallow-clone into the shared work volume. Returns (checkout path, commit sha).

    Returns a path relative to the volume root, since the worker and the scanner
    containers see it at different mount points.
    """
    _validate(url)
    checkout = f"checkout-{uuid.uuid4().hex[:12]}"

    command = ["clone", "--depth", str(depth), "--single-branch"]
    if ref:
        command += ["--branch", ref]
    # `--` terminates option parsing so a URL can never be read as a flag.
    command += ["--", url, f"/work/{checkout}"]

    result = run_sandboxed(
        SandboxSpec(
            image=GIT_IMAGE,
            command=command,
            mounts=[Mount(volume=work_volume, target="/work", read_only=False)],
            network="bridge",          # the only step that needs egress
            timeout=CLONE_TIMEOUT,
            env={"GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1"},
        )
    )
    if not result.ok:
        raise CheckoutError(
            f"Clone failed ({'timeout' if result.timed_out else result.exit_code}): "
            f"{result.stderr.strip()[-400:]}"
        )

    head = run_sandboxed(
        SandboxSpec(
            image=GIT_IMAGE,
            command=["-C", f"/work/{checkout}", "rev-parse", "HEAD"],
            mounts=[Mount(volume=work_volume, target="/work", read_only=True)],
            network="none",
            timeout=60,
        )
    )
    commit = head.stdout.strip() if head.ok else ""
    return checkout, commit


def remove_checkout(checkout: str, *, work_volume: str) -> None:
    """Delete a checkout. Never fatal — a leaked directory is cleaned by the sweeper."""
    if not re.fullmatch(r"checkout-[0-9a-f]{12}", checkout):
        log.warning("checkout.refused_removal", checkout=checkout)
        return
    run_sandboxed(
        SandboxSpec(
            image=GIT_IMAGE,
            command=["sh", "-c", f"rm -rf /work/{checkout}"],
            mounts=[Mount(volume=work_volume, target="/work", read_only=False)],
            network="none",
            timeout=120,
        )
    )
