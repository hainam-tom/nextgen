import json
from pathlib import Path

from admin.storage import EncryptedJsonStore, JsonStore


def test_json_store_recovers_from_backup(tmp_path):
    path = tmp_path / "profiles.json"
    store = JsonStore(path, backups=2)
    store.put("user", {"value": 1})
    store.put("user", {"value": 2})
    path.write_text("{corrupt", encoding="utf-8")
    data = store.get("user")
    assert data["value"] == 1


def test_encrypted_store_falls_back_on_backup(tmp_path):
    path = tmp_path / "bank.enc"
    store = EncryptedJsonStore(path, "secret-key", backups=2)
    store.put("user", {"card": "1111"})
    store.put("user", {"card": "2222"})
    path.write_bytes(b"not-valid")
    data = store.get("user")
    assert data["card"] == "1111"


def test_json_store_creates_backup_files(tmp_path):
    path = tmp_path / "accounts.json"
    store = JsonStore(path, backups=2)
    store.put("user", {"name": "alpha"})
    store.put("user", {"name": "beta"})
    store.put("user", {"name": "gamma"})
    backups = sorted(p.name for p in path.parent.glob("accounts.json.bak*"))
    assert backups == ["accounts.json.bak1", "accounts.json.bak2"]
    assert json.loads(Path(path.with_suffix(path.suffix + ".bak1")).read_text())
