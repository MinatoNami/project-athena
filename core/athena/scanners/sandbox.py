"""Ephemeral container sandbox for scanner execution.

Scanners parse deeply untrusted input — crafted archives, adversarial manifests,
hostile container layers. They never run in the worker process.

Containers are launched as siblings through the Docker socket, so any path shared
with them must live on a named volume both can see, not a path that exists only
inside the worker's filesystem.
"""

from __future__ import annotations

import json
import shlex
import subprocess
from dataclasses import dataclass, field

import structlog

log = structlog.get_logger(__name__)

DEFAULT_TIMEOUT = 300
DEFAULT_MEMORY = "1g"
DEFAULT_PIDS = 512
MAX_OUTPUT_BYTES = 64 * 1024 * 1024


class SandboxError(RuntimeError):
    pass


@dataclass
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.truncated

    @property
    def diagnosis(self) -> str:
        """What went wrong, in words rather than a number.

        137 is SIGKILL, which from a memory-limited container means the kernel's OOM
        killer. It arrives with an empty stderr — the process is not given the chance
        to say anything — so an unexplained "exit 137" is the least actionable
        failure this system can produce, and it went unnoticed for exactly that
        reason.
        """
        if self.timed_out:
            return "timeout"
        if self.truncated:
            return "output exceeded the size limit"
        if self.exit_code == 137:
            return "killed (exit 137) — out of memory against the sandbox limit"
        if self.exit_code == 143:
            return "terminated (exit 143)"
        return f"exit {self.exit_code}"

    def json(self) -> dict:
        try:
            return json.loads(self.stdout)
        except json.JSONDecodeError as exc:
            raise SandboxError(f"Scanner did not emit valid JSON: {exc}") from exc


@dataclass
class Mount:
    volume: str          # named volume, or a host path
    target: str
    read_only: bool = True

    def as_arg(self) -> str:
        return f"{self.volume}:{self.target}:{'ro' if self.read_only else 'rw'}"


@dataclass
class SandboxSpec:
    image: str
    command: list[str]
    mounts: list[Mount] = field(default_factory=list)
    # No network by default. A scanner that needs one must say so explicitly, and the
    # reason should be obvious at the call site.
    network: str = "none"
    timeout: int = DEFAULT_TIMEOUT
    memory: str = DEFAULT_MEMORY
    pids: int = DEFAULT_PIDS
    workdir: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    # Scratch space inside the sandbox. An image scan exports whole layers, so it
    # needs far more than a filesystem scan does.
    tmpfs_size: str = "256m"


def ensure_image(image: str, *, timeout: int = 600) -> None:
    """Pull the scanner image up front.

    Pulling implicitly during `docker run` interleaves progress output with the
    scanner's own stderr, which buries the actual failure when something goes wrong.
    """
    inspect = subprocess.run(  # noqa: S603
        ["docker", "image", "inspect", image],  # noqa: S607
        capture_output=True, timeout=60, check=False,
    )
    if inspect.returncode == 0:
        return
    log.info("sandbox.pull", image=image)
    pull = subprocess.run(  # noqa: S603
        ["docker", "pull", "--quiet", image],  # noqa: S607
        capture_output=True, timeout=timeout, check=False,
    )
    if pull.returncode != 0:
        raise SandboxError(
            f"Could not pull scanner image {image}: "
            f"{pull.stderr.decode('utf-8', 'replace').strip()[-300:]}"
        )


def run_sandboxed(spec: SandboxSpec) -> SandboxResult:
    """Run one scanner invocation under confinement.

    Confinement is not defence-in-depth garnish here: the input is chosen by whoever
    controls the repository or image being scanned.
    """
    args = [
        "docker", "run", "--rm",
        "--network", spec.network,
        "--memory", spec.memory,
        "--pids-limit", str(spec.pids),
        "--cpus", "1.0",
        "--security-opt", "no-new-privileges",
        "--cap-drop", "ALL",
        "--read-only",
        # The sandbox container's own scratch space: nosuid, size-capped, and
        # destroyed with the container.
        # mode=1777 matters: Docker mounts a tmpfs root-owned by default, and the
        # sandbox runs unprivileged with a read-only root — so without it the
        # scanner has nowhere at all to write and fails with a bare permission error.
        "--tmpfs", f"/tmp:rw,nosuid,mode=1777,size={spec.tmpfs_size}",  # noqa: S108
        "--user", "10001:10001",
    ]
    for mount in spec.mounts:
        args += ["-v", mount.as_arg()]
    for key, value in spec.env.items():
        args += ["-e", f"{key}={value}"]
    if spec.workdir:
        args += ["-w", spec.workdir]
    args.append(spec.image)
    args += spec.command

    ensure_image(spec.image)

    log.info("sandbox.run", image=spec.image, command=shlex.join(spec.command),
             network=spec.network, timeout=spec.timeout)

    try:
        proc = subprocess.run(  # noqa: S603, S607 - fixed argv, no shell
            args, capture_output=True, timeout=spec.timeout, check=False
        )
    except subprocess.TimeoutExpired:
        log.warning("sandbox.timeout", image=spec.image, timeout=spec.timeout)
        return SandboxResult(exit_code=-1, stdout="", stderr="timed out", timed_out=True)
    except FileNotFoundError as exc:
        raise SandboxError(
            "docker is not available to the worker; the scanner sandbox cannot start"
        ) from exc

    truncated = len(proc.stdout) > MAX_OUTPUT_BYTES
    stdout = proc.stdout[:MAX_OUTPUT_BYTES].decode("utf-8", "replace")
    stderr = proc.stderr[-8192:].decode("utf-8", "replace")

    if truncated:
        log.warning("sandbox.output_truncated", image=spec.image, limit=MAX_OUTPUT_BYTES)

    return SandboxResult(
        exit_code=proc.returncode, stdout=stdout, stderr=stderr, truncated=truncated
    )


def sandbox_available() -> bool:
    """Whether the worker can launch sandboxed scanners at all."""
    try:
        proc = subprocess.run(  # noqa: S603
            ["docker", "version", "--format", "{{.Server.Version}}"],  # noqa: S607
            capture_output=True, timeout=10, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0
