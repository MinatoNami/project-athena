from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ExecutorSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ATHENA_", extra="ignore")

    db_host: str = "db"
    db_port: int = 5432
    db_name: str = "athena"
    db_user: str = "athena_executor"
    db_password_file: str | None = None

    grant_public_key_file: str | None = None
    grant_max_lifetime_seconds: int = Field(default=900, gt=0)

    @property
    def grant_public_key(self) -> bytes | None:
        if not self.grant_public_key_file:
            return None
        p = Path(self.grant_public_key_file)
        return p.read_bytes() if p.exists() else None

    @property
    def grant_max_lifetime(self) -> timedelta:
        return timedelta(seconds=self.grant_max_lifetime_seconds)
