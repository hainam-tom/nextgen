"""Firebase helpers used by the admin service."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Optional
import json


def _load_service_account_file(path: Path) -> Optional[dict[str, Any]]:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if data.get("type") != "service_account":
        return None
    return data


def load_service_account(base_dir: Path, env: Mapping[str, str] | None = None) -> Optional[dict[str, Any]]:
    """Load Firebase service account credentials from disk or env."""

    base_dir = Path(base_dir)
    env_map = dict(env or {})

    for candidate in ("firebase-auth.json", "clientSecret.json"):
        data = _load_service_account_file(base_dir / candidate)
        if data:
            return data

    project_id = (env_map.get("FIREBASE_PROJECT_ID") or "").strip()
    private_key = (env_map.get("FIREBASE_PRIVATE_KEY") or "").strip()
    client_email = (env_map.get("FIREBASE_CLIENT_EMAIL") or "").strip()

    if project_id and private_key and client_email:
        return {
            "type": "service_account",
            "project_id": project_id,
            "private_key": private_key.replace("\\n", "\n"),
            "client_email": client_email,
            "token_uri": "https://oauth2.googleapis.com/token",
        }

    return None
