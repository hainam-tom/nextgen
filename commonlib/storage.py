"""Shared storage helpers for Vendly services.

This module centralises the JSON-backed persistence helpers used by both the
admin Flask application and any auxiliary scripts. Storing the helpers in a
single location avoids code drift between services and keeps redundancy logic
(such as atomic writes and rotating backups) consistent everywhere.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import datetime as _dt
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Sequence, Tuple

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


class ListStore:
    """JSON list store with atomic writes and backup recovery."""

    def __init__(
        self,
        path: Path | str,
        backups: int = 2,
        *,
        recovery_label: str | None = None,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.backups = max(0, backups)
        self._recovery_label = recovery_label

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------
    def _candidate_paths(self) -> list[Path]:
        paths = [self.path]
        for idx in range(1, self.backups + 1):
            paths.append(self.path.with_suffix(self.path.suffix + f".bak{idx}"))
        return paths

    def _read_json(self, path: Path) -> List[Dict[str, Any]] | None:
        if not path.exists():
            return None
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:  # pragma: no cover - surfaced to callers
            raise StoreError(str(exc)) from exc
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, list) else None

    def _write_json(self, path: Path, data: Sequence[Dict[str, Any]]) -> None:
        payload = json.dumps(list(data), indent=2)
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
                    continue

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def load(self) -> List[Dict[str, Any]]:
        for candidate in self._candidate_paths():
            data = self._read_json(candidate)
            if data is not None:
                if candidate != self.path and self._recovery_label:
                    print(f"Recovered {self._recovery_label} from backup {candidate.name}")
                return list(data)
        return []

    def save(self, items: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        snapshot: List[Dict[str, Any]] = []
        for item in items:
            snapshot.append(dict(item))
        self._rotate_backups()
        self._write_json(self.path, snapshot)
        return snapshot

    def mutate(
        self,
        mutator: Callable[[List[Dict[str, Any]]], Iterable[Dict[str, Any]] | None],
    ) -> List[Dict[str, Any]]:
        snapshot = self.load()
        outcome = mutator(snapshot)
        if outcome is None:
            updated = snapshot
        else:
            updated = [dict(item) for item in outcome]
        self._rotate_backups()
        self._write_json(self.path, updated)
        return updated


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
        payload = json.dumps(data, indent=2).encode("utf-8")
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        try:
            with tmp_path.open("wb") as fh:
                fh.write(self._fernet.encrypt(payload))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, path)
        except OSError as exc:  # pragma: no cover - bubbled up to callers
            raise StoreError(str(exc)) from exc
        finally:
            tmp_path.unlink(missing_ok=True)


class DailyKeyEncryptedJsonStore(JsonStore):
    """JSON store that rotates encryption keys every day.

    The store derives a Fernet key from ``secret`` combined with the current
    date (``YYYY-MM-DD``). When reading existing payloads it automatically
    retries decryption with keys from previous days (up to ``retention_days``
    back) and transparently migrates plaintext JSON files created before daily
    encryption was introduced.
    """

    def __init__(
        self,
        path: Path | str,
        secret: str,
        backups: int = 2,
        *,
        retention_days: int = 1,
    ) -> None:
        super().__init__(path, backups=backups)
        self._secret = secret or "vendly-daily-secret"
        self._retention_days = max(0, retention_days)
        self._migration_needed = False
        self._stale_key_detected = False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _daily_key(self, day: _dt.date) -> Fernet:
        material = f"{self._secret}:{day.isoformat()}"
        return Fernet(_derive_key(material))

    def _candidate_keys(self) -> List[Tuple[_dt.date, Fernet]]:
        today = _dt.date.today()
        keys: List[Tuple[_dt.date, Fernet]] = []
        for offset in range(self._retention_days + 1):
            day = today - _dt.timedelta(days=offset)
            keys.append((day, self._daily_key(day)))
        return keys

    # ------------------------------------------------------------------
    # Overrides
    # ------------------------------------------------------------------
    def _read_json(self, path: Path) -> Dict[str, Any] | None:  # type: ignore[override]
        self._migration_needed = False
        self._stale_key_detected = False
        if not path.exists():
            return None
        try:
            blob = path.read_bytes()
        except OSError as exc:  # pragma: no cover - unlikely in tests
            raise StoreError(str(exc)) from exc
        if not blob:
            return {}

        for idx, (day, fernet) in enumerate(self._candidate_keys()):
            try:
                decrypted = fernet.decrypt(blob)
            except InvalidToken:
                continue
            try:
                data = json.loads(decrypted.decode("utf-8"))
            except json.JSONDecodeError:
                return None
            if not isinstance(data, dict):
                return {}
            if idx > 0:
                self._stale_key_detected = True
            return data

        # Legacy plaintext fallback for first-run migrations.
        try:
            decoded = blob.decode("utf-8")
            data = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if isinstance(data, dict):
            self._migration_needed = True
            return data
        return {}

    def _write_json(self, path: Path, data: Dict[str, Any]) -> None:  # type: ignore[override]
        payload = json.dumps(data, indent=2).encode("utf-8")
        today_key = self._daily_key(_dt.date.today())
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        try:
            with tmp_path.open("wb") as fh:
                fh.write(today_key.encrypt(payload))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, path)
        except OSError as exc:  # pragma: no cover - bubbled up to callers
            raise StoreError(str(exc)) from exc
        finally:
            tmp_path.unlink(missing_ok=True)

    def _load(self) -> Dict[str, Any]:  # type: ignore[override]
        data = super()._load()
        if (self._migration_needed or self._stale_key_detected) and data is not None:
            try:
                self._rotate_backups()
                self._write_json(self.path, data)
            except StoreError:
                pass
        return data
