import json

import pytest

from admin import app as flask_app
from commonlib.storage import DailyKeyEncryptedJsonStore


@pytest.fixture(autouse=True)
def configure_test_env(tmp_path, monkeypatch):
    flask_app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    product_file = tmp_path / "products.json"
    monkeypatch.setattr(flask_app, "PRODUCT_FILE", product_file)
    monkeypatch.setattr(flask_app, "_PRODUCT_CATALOG", None)
    talisman = flask_app.app.extensions.get("talisman")
    if talisman:
        talisman.force_https = False
    if product_file.exists():
        product_file.unlink()
    profile_file = tmp_path / "accounts.enc"
    bank_file = tmp_path / "banking.enc"
    auth_file = tmp_path / "auth.enc"
    reviews_file = tmp_path / "reviews.enc"
    site_file = tmp_path / "site.json"

    monkeypatch.setattr(
        flask_app,
        "PROFILE_STORE",
        DailyKeyEncryptedJsonStore(profile_file, "test-secret"),
    )
    monkeypatch.setattr(
        flask_app,
        "AUTH_STORE",
        DailyKeyEncryptedJsonStore(auth_file, "test-secret"),
    )
    monkeypatch.setattr(
        flask_app,
        "BANKING_STORE",
        DailyKeyEncryptedJsonStore(bank_file, "bank-secret"),
    )
    monkeypatch.setattr(
        flask_app,
        "REVIEWS_STORE",
        DailyKeyEncryptedJsonStore(reviews_file, "review-secret"),
    )
    monkeypatch.setattr(flask_app, "PROFILE_FILE", profile_file)
    monkeypatch.setattr(flask_app, "AUTH_FILE", auth_file)
    monkeypatch.setattr(flask_app, "BANKING_FILE", bank_file)
    monkeypatch.setattr(flask_app, "REVIEWS_FILE", reviews_file)
    monkeypatch.setattr(flask_app, "SITE_FILE", site_file)
    site_file.write_text(json.dumps(flask_app.SITE_DEFAULTS, indent=2), encoding="utf-8")
    flask_app._SITE_CACHE = {"path": None, "mtime": None, "data": flask_app.SITE_DEFAULTS}
    monkeypatch.setattr(flask_app, "FIREBASE_READY", False)
    yield product_file
