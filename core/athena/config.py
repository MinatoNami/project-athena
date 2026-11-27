from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import Field, field_validator, model_validator
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

    db_host: str = "db"
    db_port: int = 5432
    db_name: str = "athena"
    db_user: str = "athena"
    db_password_file: str | None = None
    db_password: str | None = None

    db_role: str = "app"

    master_key_file: str | None = None
    master_key: str | None = None
    node_signing_key_file: str | None = None

    bind_host: str = "0.0.0.0"  # noqa: S104
    bind_port: int = 8000
    session_ttl_hours: int = 12
    cookie_secure: bool = True
    session_idle_minutes: int = 30
    step_up_ttl_seconds: int = 300

    worker_concurrency: int = 4
    job_lease_seconds: int = 300
    poll_interval_seconds: float = 1.0

    work_volume: str = "athena-work"
    work_dir: str = "/work"
    image_scan_memory: str = "3g"
    sandbox_network: str = "athena-nodechannel"
    docker_proxy_host: str = "tcp://docker-proxy:2375"

    code_scans_enabled: bool = True
    gitleaks_image: str = (
        "ghcr.io/gitleaks/gitleaks:v8.30.1"
        "@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
    )
    trivy_image: str = (
        "aquasec/trivy:0.76.2"
        "@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb"
    )
    syft_image: str = (
        "anchore/syft:v1.57.2"
        "@sha256:e97e20b6e6d1699c60296b66ab337941724f9bd06ac279d893eda89601fc4b2a"
    )
    git_image: str = (
        "alpine/git:v2.54.1"
        "@sha256:29cff25811f790b9f72fc266bf8009a5a911714c0e03c31c47339c50909d9aef"
    )

    @field_validator(
        "gitleaks_image", "trivy_image", "syft_image", "git_image", mode="before"
    )
    @classmethod
    def _blank_image_means_default(cls, value: Any, info: Any) -> Any:
        if isinstance(value, str) and not value.strip():
            return cls.model_fields[info.field_name].default
        return value

    ai_mode: str = "local_only"

    notify_max_per_window: int = 10
    notify_window_minutes: int = 60
    notify_quiet_hours: str = ""

    sla_days_critical: int = 7
    sla_days_high: int = 30
    sla_days_medium: int = 90
    llm_base_url: str = "http://127.0.0.1:1234"
    llm_model: str = "qwen/qwen3.6-35b-a3b"
    llm_timeout: float = 300.0
    ai_budget_calls: int = 500
    ai_budget_window_hours: int = 24
    triage_batch: int = 40

    investigation_floor: str = "all"

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
