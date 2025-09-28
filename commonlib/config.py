"""Configuration helpers for the Flask applications.

The admin application previously fetched configuration values directly from
environment variables sprinkled throughout the module. Centralising the logic
in this module makes it easier for installers and tests to prime the expected
values without touching application internals.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping
import os

from dotenv import load_dotenv


@dataclass(frozen=True)
class AdminConfig:
    """Strongly typed configuration for the admin service."""

    base_dir: Path
    secret_key: str
    admin_email: str
    google_client_id: str
    google_client_secret: str
    firebase_web_api_key: str
    session_max_days: int
    allowed_origins: tuple[str, ...]

    @property
    def session_cookie_name(self) -> str:
        return "fb_session"


def _coerce_origins(raw: str | Iterable[str]) -> tuple[str, ...]:
    if isinstance(raw, str):
        items = [piece.strip() for piece in raw.split(",")]
    else:
        items = [piece.strip() for piece in raw]
    return tuple(filter(None, items)) or (
        "https://localhost",
        "https://127.0.0.1",
        "http://localhost",
        "http://127.0.0.1",
    )


def load_admin_config(base_dir: Path, env: Mapping[str, str] | None = None) -> AdminConfig:
    """Load admin configuration from the given base directory and env mapping."""

    load_dotenv(base_dir / ".env")
    env_map = dict(env or os.environ)

    secret_key = env_map.get("SECRET_KEY", "dev-change-me")
    admin_email = env_map.get("ADMIN_EMAIL", "tom05012013@gmail.com").lower()
    google_client_id = env_map.get("GOOGLE_CLIENT_ID", "")
    google_client_secret = env_map.get("GOOGLE_CLIENT_SECRET", "")
    firebase_web_api_key = env_map.get("FIREBASE_WEB_API_KEY", "").strip()
    session_max_days = int(env_map.get("SESSION_MAX_DAYS", "5"))
    allowed_origins = _coerce_origins(
        env_map.get(
            "ALLOWED_ORIGINS",
            "https://localhost,https://127.0.0.1,http://localhost,http://127.0.0.1",
        )
    )

    return AdminConfig(
        base_dir=Path(base_dir),
        secret_key=secret_key,
        admin_email=admin_email,
        google_client_id=google_client_id,
        google_client_secret=google_client_secret,
        firebase_web_api_key=firebase_web_api_key,
        session_max_days=session_max_days,
        allowed_origins=allowed_origins,
    )
