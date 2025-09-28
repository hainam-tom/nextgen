from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from commonlib.storage import safe_write_json, safe_read_json, EncryptedJSONStore
from commonlib.firebase import load_service_account
import os


def test_safe_write_creates_backup(tmp_path):
    target = tmp_path / "products.json"
    first = [{"id": "1", "name": "Widget", "price": 5.0}]
    second = [{"id": "2", "name": "Gadget", "price": 7.5}]

    safe_write_json(target, first)
    assert target.exists()

    safe_write_json(target, second)
    backup = target.with_suffix(target.suffix + ".bak")
    assert backup.exists()

    # Corrupt the primary file to trigger fallback recovery.
    target.write_text("not-json", encoding="utf-8")
    recovered = safe_read_json(target)
    assert recovered == first


def test_load_credentials_env(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FIREBASE_PROJECT_ID", "vendly-test")
    monkeypatch.setenv("FIREBASE_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----\\nABC\\n-----END PRIVATE KEY-----")
    monkeypatch.setenv("FIREBASE_CLIENT_EMAIL", "service@vendly-test.iam.gserviceaccount.com")

    creds = load_service_account(tmp_path, os.environ)
    assert creds is not None
    assert creds["project_id"] == "vendly-test"
    assert "BEGIN PRIVATE KEY" in creds["private_key"]
    assert creds["private_key"].count("\n") >= 2
    assert creds["client_email"].endswith("vendly-test.iam.gserviceaccount.com")


def test_load_credentials_missing(monkeypatch):
    base_dir = Path(__file__).resolve().parents[1] / "admin" / "non-existent"
    monkeypatch.delenv("FIREBASE_PROJECT_ID", raising=False)
    monkeypatch.delenv("FIREBASE_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("FIREBASE_CLIENT_EMAIL", raising=False)
    creds = load_service_account(base_dir, {})
    assert creds is None


def test_encrypted_store_round_trip(tmp_path, monkeypatch):
    key = "NvzfhZm_YnHf8o1Qph-QJrHFz3sChaXaIcYqRVGqG7w="
    monkeypatch.setenv("FERNET_KEY", key)
    path = tmp_path / "banking.json.enc"
    store = EncryptedJSONStore.from_environment(path, key_path=tmp_path / "fernet.key")
    payload = {"accounts": {"uid": {"cards": [{"last4": "1234"}]}}}
    store.write(payload)
    assert path.exists()
    restored = store.read()
    assert restored == payload
