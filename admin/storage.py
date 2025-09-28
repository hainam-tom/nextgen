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
import os
from pathlib import Path
from typing import Any, Dict

from cryptography.fernet import Fernet, InvalidToken


class StoreError(RuntimeError):
    """Raised when a persistence operation fails."""


class JsonStore:
    """Tiny JSON document store keyed by identifier.

    The store maintains a configurable number of backup files (``.bakN``) and
    uses atomic writes to reduce the risk of corruption. When loading, it
    automatically falls back to the newest readable backup, creating a small
    layer of redundancy for self-hosted deployments where abrupt shutdowns are
    common.
    """

    def __init__(self, path: Path | str, backups: int = 2):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.backups = max(0, backups)

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------
    def _candidate_paths(self) -> list[Path]:
        paths = [self.path]
        for idx in range(1, self.backups + 1):
            paths.append(self.path.with_suffix(self.path.suffix + f".bak{idx}"))
        return paths

    def _read_json(self, path: Path) -> Dict[str, Any] | None:
        if not path.exists():
            return None
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:  # pragma: no cover - propagated for visibility
            raise StoreError(str(exc)) from exc
        if not raw:
            return {}
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, dict) else {}

    def _write_json(self, path: Path, data: Dict[str, Any]) -> None:
        payload = json.dumps(data, indent=2)
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        try:
            with tmp_path.open("w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, path)
        except OSError as exc:  # pragma: no cover - bubbled up to callers
            raise StoreError(str(exc)) from exc
        finally:
            tmp_path.unlink(missing_ok=True)

    def _rotate_backups(self) -> None:
        if self.backups <= 0:
            return
        for idx in range(self.backups, 0, -1):
            if idx == 1:
                src = self.path
            else:
                src = self.path.with_suffix(self.path.suffix + f".bak{idx - 1}")
            dest = self.path.with_suffix(self.path.suffix + f".bak{idx}")
            if src.exists():
                try:
                    os.replace(src, dest)
                except OSError:
                    # Best effort; if rotation fails we continue without
                    # clobbering the new write.
                    continue

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def _load(self) -> Dict[str, Any]:
        for candidate in self._candidate_paths():
            data = self._read_json(candidate)
            if data is not None:
                return data
        return {}

    def _dump(self, data: Dict[str, Any]) -> None:
        self._rotate_backups()
        self._write_json(self.path, data)

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

    def __init__(self, path: Path | str, secret: str, backups: int = 2):
        super().__init__(path, backups=backups)
        self._fernet = Fernet(_derive_key(secret))

    def _read_json(self, path: Path) -> Dict[str, Any] | None:  # type: ignore[override]
        if not path.exists():
            return None
        try:
            blob = path.read_bytes()
        except OSError as exc:  # pragma: no cover - unlikely in tests
            raise StoreError(str(exc)) from exc
        if not blob:
            return {}
        try:
            decrypted = self._fernet.decrypt(blob)
        except InvalidToken:
            return None
        try:
            data = json.loads(decrypted.decode("utf-8"))
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, dict) else {}

    def _write_json(self, path: Path, data: Dict[str, Any]) -> None:  # type: ignore[override]
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        try:
            payload = json.dumps(data, indent=2).encode("utf-8")
            blob = self._fernet.encrypt(payload)
            with tmp_path.open("wb") as fh:
                fh.write(blob)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, path)
        except OSError as exc:  # pragma: no cover - unlikely in tests
            raise StoreError(str(exc)) from exc
        finally:
            tmp_path.unlink(missing_ok=True)
