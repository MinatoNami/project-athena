"""Runtime configuration.

Every secret is read from a file path rather than an inline value, so secrets never
appear in `docker inspect`, process listings, or shell history.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _read_secret_file(path: str | None) -> str | None:
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    return p.read_text(encoding="utf-8").strip()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ATHENA_", extra="ignore")

    # --- database -----------------------------------------------------------
    db_host: str = "db"
    db_port: int = 5432
    db_name: str = "athena"
    db_user: str = "athena"
    db_password_file: str | None = None
    db_password: str | None = None

    # Executor connects with a restricted role (see migration 0002).
    db_role: str = "app"  # app | executor

    # --- crypto -------------------------------------------------------------
    master_key_file: str | None = None
    master_key: str | None = None
    # Signs task envelopes sent to nodes. Distinct from the executor's grant key:
    # they authorise different things, and one compromise must not confer the other.
    node_signing_key_file: str | None = None

    # --- api ----------------------------------------------------------------
    bind_host: str = "0.0.0.0"  # noqa: S104 - bound to the compose private network
    bind_port: int = 8000
    session_ttl_hours: int = 12
    # Session cookies are Secure by default, so a browser will only send them over
    # HTTPS. Serving the dashboard over plain HTTP therefore breaks login silently.
    # Turning this off is a real downgrade and `athena doctor` reports it as one.
    cookie_secure: bool = True
    session_idle_minutes: int = 30
    step_up_ttl_seconds: int = 300

    # --- workers ------------------------------------------------------------
    worker_concurrency: int = 4
    job_lease_seconds: int = 300
    poll_interval_seconds: float = 1.0

    # Named volume shared between the worker and the sandbox containers it launches.
    # Sibling containers cannot see a path that exists only inside the worker.
    work_volume: str = "athena-work"
    # Network the scanner sandbox joins when it needs to reach the read-only Docker
    # proxy, and the address of that proxy. Both are explicit names rather than
    # compose-prefixed ones, so a sibling container can find them.
    sandbox_network: str = "athena-nodechannel"
    docker_proxy_host: str = "tcp://docker-proxy:2375"

    # ─── AI layer ───────────────────────────────────────────────────────────
    # local_only refuses any endpoint that is not demonstrably inside the operator's
    # own network, so a misconfiguration cannot quietly start shipping inventory to
    # a hosted provider.
    ai_mode: str = "local_only"

    # --- notifications ------------------------------------------------------
    # Sends allowed per window before the rest are held for the digest. The point is
    # not to save bandwidth: it is that a person who receives forty messages in an
    # afternoon stops reading any of them, and the fortieth is as likely to matter as
    # the first.
    notify_max_per_window: int = 10
    notify_window_minutes: int = 60
    # Local hours during which only urgent notifications send; everything else waits
    # for the digest. Empty disables it. Format "22:00-07:00", crossing midnight.
    notify_quiet_hours: str = ""

    # --- service levels -----------------------------------------------------
    # Days a finding of each band may stay open before it is late. These are
    # defaults chosen to be argued with, not derived from the PRD — it sets targets
    # for detection and accuracy but says nothing about how long a confirmed finding
    # may sit. Change them rather than quietly ignoring them.
    sla_days_critical: int = 7
    sla_days_high: int = 30
    sla_days_medium: int = 90
    # Point this at a MagicDNS name rather than a tailnet IP where the model lives on
    # another machine: tailnet addresses are reassigned on reconnect, and a stale one
    # presents as an unreachable model rather than as a configuration error.
    llm_base_url: str = "http://127.0.0.1:1234"
    llm_model: str = "qwen/qwen3.6-35b-a3b"
    llm_timeout: float = 300.0
    # A local model has no invoice but does have wall-clock. Capped on calls rather
    # than tokens because that is what an operator can reason about. On exhaustion
    # work queues rather than being dropped.
    #
    # 500/day against a measured steady state of roughly 80 leaves ample headroom
    # while still being low enough to catch a runaway. The previous 2,000 was a
    # guess made before there was anything to measure, and 25x headroom is not a
    # limit — it is a number that only ever fires on something already pathological.
    ai_budget_calls: int = 500
    ai_budget_window_hours: int = 24
    # How many findings each sweep hands to triage. Small enough that the queue stays
    # legible and other work keeps moving.
    triage_batch: int = 40

    log_level: str = "INFO"
    environment: str = Field(default="production")

    @model_validator(mode="after")
    def _resolve_secret_files(self) -> Settings:
        self.db_password = self.db_password or _read_secret_file(self.db_password_file)
        self.master_key = self.master_key or _read_secret_file(self.master_key_file)
        return self

    @property
    def database_url(self) -> str:
        if not self.db_password:
            raise RuntimeError(
                "No database password. Set ATHENA_DB_PASSWORD_FILE to a readable file."
            )
        user = self.db_user if self.db_role == "app" else f"{self.db_user}_executor"
        return (
            f"postgresql+psycopg://{user}:{self.db_password}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}"
        )


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
