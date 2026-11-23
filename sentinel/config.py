"""Runtime settings, read from the environment or a local .env file."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    DATABASE_URL: str = "sqlite:///./sentinel.db"

    # abuse.ch asks automated clients to send a (free) Auth-Key.
    ABUSECH_AUTH_KEY: str = ""

    HTTP_TIMEOUT_SECONDS: float = 60.0
    # Deliberately generic: identifies the software, not the operator.
    USER_AGENT: str = "Sentinel-BD/0.1"

    BD_RANGES_PATH: str = "data/bd_ipv4.txt"

    # Feeds never return more than this many rows in one response.
    FEED_MAX_ROWS: int = 50_000


@lru_cache
def get_settings() -> Settings:
    return Settings()
