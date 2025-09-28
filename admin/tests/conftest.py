import pytest

from admin import app as flask_app
from admin.storage import EncryptedJsonStore, JsonStore


@pytest.fixture(autouse=True)
def configure_test_env(tmp_path, monkeypatch):
    flask_app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    product_file = tmp_path / "products.json"
    monkeypatch.setattr(flask_app, "PRODUCT_FILE", product_file)
    talisman = flask_app.app.extensions.get("talisman")
    if talisman:
        talisman.force_https = False
    if product_file.exists():
        product_file.unlink()
    profile_file = tmp_path / "accounts.json"
    bank_file = tmp_path / "banking.enc"
    auth_file = tmp_path / "auth.json"
    monkeypatch.setattr(flask_app, "PROFILE_STORE", JsonStore(profile_file))
    monkeypatch.setattr(flask_app, "AUTH_STORE", JsonStore(auth_file))
    monkeypatch.setattr(flask_app, "BANKING_STORE", EncryptedJsonStore(bank_file, "test-secret"))
    monkeypatch.setattr(flask_app, "PROFILE_FILE", profile_file)
    monkeypatch.setattr(flask_app, "AUTH_FILE", auth_file)
    monkeypatch.setattr(flask_app, "BANKING_FILE", bank_file)
    monkeypatch.setattr(flask_app, "FIREBASE_READY", False)
    yield product_file
