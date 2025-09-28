"""Storage helpers shared across services."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping
import json
import os

from cryptography.fernet import Fernet, InvalidToken


@dataclass
class JsonStore:
    """Utility wrapper for resilient JSON persistence."""

    path: Path

    def read(self, default: Any = None) -> Any:
        return safe_read_json(self.path, default=default)

    def write(self, payload: Any) -> None:
        safe_write_json(self.path, payload)


class EncryptedJSONStore(JsonStore):
    """JSON store that encrypts contents using ``cryptography.fernet``."""

    def __init__(self, path: Path, key: bytes | str):
        super().__init__(Path(path))
        if isinstance(key, str):
            key = key.encode("utf-8")
        if len(key) != 44:
            raise ValueError("Fernet keys must be 32 url-safe base64-encoded bytes")
        self._fernet = Fernet(key)

    @classmethod
    def from_environment(
        cls,
        path: Path,
        env: Mapping[str, str] | Iterable[tuple[str, str]] | None = None,
        key_path: Path | None = None,
    ) -> "EncryptedJSONStore":
        env_map = dict(env or os.environ)
        key = env_map.get("FERNET_KEY") or env_map.get("BANK_ENCRYPTION_KEY")

        key_file = Path(key_path) if key_path is not None else Path(Path(path).with_suffix(".key"))
        if not key and key_file.exists():
            key = key_file.read_text(encoding="utf-8").strip()

        if not key:
            key = Fernet.generate_key().decode("utf-8")
            try:
                key_file.write_text(key, encoding="utf-8")
            except OSError:
                pass
        elif key_file and not key_file.exists():
            try:
                key_file.write_text(key, encoding="utf-8")
            except OSError:
                pass

        return cls(Path(path), key)

    def read(self, default: Any = None) -> Any:
        path = self.path
        if not path.exists():
            return default
        try:
            data = path.read_bytes()
            if not data:
                return default
            decrypted = self._fernet.decrypt(data)
            return json.loads(decrypted.decode("utf-8"))
        except (InvalidToken, json.JSONDecodeError, OSError):
            return default

    def write(self, payload: Any) -> None:
        encoded = json.dumps(payload, indent=2).encode("utf-8")
        ciphertext = self._fernet.encrypt(encoded)
        tmp_path = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp_path.write_bytes(ciphertext)
        tmp_path.replace(self.path)


def safe_write_json(path: Path, data: Any) -> None:
    path = Path(path)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    backup_path = path.with_suffix(path.suffix + ".bak")
    payload = json.dumps(data, indent=2)
    tmp_path.write_text(payload, encoding="utf-8")

    if path.exists():
        try:
            path.replace(backup_path)
        except OSError:
            backup_path.unlink(missing_ok=True)
            path.replace(backup_path)

    tmp_path.replace(path)


def safe_read_json(path: Path, default: Any = None) -> Any:
    path = Path(path)
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            backup_path = path.with_suffix(path.suffix + ".bak")
            if backup_path.exists():
                try:
                    return json.loads(backup_path.read_text(encoding="utf-8"))
                except Exception:
                    return default
            return default
    return default
