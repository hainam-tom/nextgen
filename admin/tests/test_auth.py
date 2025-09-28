import pytest

from admin import app as flask_app
from werkzeug.security import generate_password_hash


pytestmark = pytest.mark.usefixtures("configure_test_env")


def test_register_creates_account_and_sets_cookie():
    client = flask_app.app.test_client()
    response = client.post(
        "/auth/register",
        json={"email": "shopper@example.com", "password": "Secret123", "name": "Shopper"},
        base_url="https://localhost",
    )
    assert response.status_code == 201
    payload = response.get_json()
    assert "id" in payload
    assert flask_app.AUTH_STORE.get(payload["id"]) is not None
    stored = flask_app.AUTH_STORE.get(payload["id"])
    assert stored["email"] == "shopper@example.com"
    assert stored["password_hash"] != "Secret123"
    set_cookie = response.headers.get("Set-Cookie", "")
    assert flask_app.SESSION_COOKIE_NAME in set_cookie

    me = client.get("/auth/me", base_url="https://localhost")
    assert me.status_code == 200
    assert me.get_json()["email"] == "shopper@example.com"


def test_login_validates_credentials():
    uid = "user-1"
    flask_app.AUTH_STORE.put(
        uid,
        {
            "email": "login@example.com",
            "name": "Login User",
            "password_hash": generate_password_hash("CorrectHorse1"),
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
        },
    )
    client = flask_app.app.test_client()

    bad = client.post(
        "/auth/login",
        json={"email": "login@example.com", "password": "wrong"},
        base_url="https://localhost",
    )
    assert bad.status_code == 401

    good = client.post(
        "/auth/login",
        json={"email": "login@example.com", "password": "CorrectHorse1"},
        base_url="https://localhost",
    )
    assert good.status_code == 200
    assert flask_app.SESSION_COOKIE_NAME in good.headers.get("Set-Cookie", "")


def test_auth_me_requires_cookie():
    client = flask_app.app.test_client()
    response = client.get("/auth/me", base_url="https://localhost")
    assert response.status_code == 401
    assert response.get_json()["error"] == "Not authenticated"
