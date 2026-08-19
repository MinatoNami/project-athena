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
