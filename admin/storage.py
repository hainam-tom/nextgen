"""Utilities for securely storing account metadata on disk.

This module provides two small helpers:

* ``JsonStore`` for plain JSON persistence (used for addresses/profile data).
* ``EncryptedJsonStore`` for writing encrypted JSON blobs (banking data).

Both helpers normalise missing/corrupted files and guarantee directory
creation before saving, making them safer for concurrent unit tests.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Dict

from cryptography.fernet import Fernet, InvalidToken


class StoreError(RuntimeError):
    """Raised when a persistence operation fails."""


class JsonStore:
    """Tiny JSON document store keyed by identifier."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> Dict[str, Any]:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}

    def _dump(self, data: Dict[str, Any]) -> None:
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def get(self, key: str, default: Any | None = None) -> Any:
        return self._load().get(key, default)

    def put(self, key: str, value: Dict[str, Any]) -> Dict[str, Any]:
        data = self._load()
        data[key] = value
        self._dump(data)
        return value

    def remove(self, key: str) -> None:
        data = self._load()
        if key in data:
            del data[key]
            self._dump(data)

    def all(self) -> Dict[str, Any]:
        return self._load()


def _derive_key(secret: str) -> bytes:
    if not secret:
        secret = "vendly-dev-secret"
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


class EncryptedJsonStore(JsonStore):
    """JSON store that encrypts payloads using Fernet symmetric encryption."""

    def __init__(self, path: Path | str, secret: str):
        super().__init__(path)
        self._fernet = Fernet(_derive_key(secret))

    def _load(self) -> Dict[str, Any]:  # type: ignore[override]
        if not self.path.exists():
            return {}
        try:
            blob = self.path.read_bytes()
        except OSError as exc:  # pragma: no cover - unlikely in tests
            raise StoreError(str(exc)) from exc
        if not blob:
            return {}
        try:
            decrypted = self._fernet.decrypt(blob)
        except InvalidToken as exc:
            raise StoreError("Encrypted store cannot be decoded; check key") from exc
        try:
            data = json.loads(decrypted.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise StoreError("Encrypted store is corrupted") from exc
        return data if isinstance(data, dict) else {}

    def _dump(self, data: Dict[str, Any]) -> None:  # type: ignore[override]
        try:
            payload = json.dumps(data, indent=2).encode("utf-8")
            blob = self._fernet.encrypt(payload)
            self.path.write_bytes(blob)
        except OSError as exc:  # pragma: no cover - unlikely in tests
            raise StoreError(str(exc)) from exc
