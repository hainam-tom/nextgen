import pytest

from admin import app as flask_app


pytestmark = pytest.mark.usefixtures("configure_test_env")


def auth_client(monkeypatch):
    client = flask_app.app.test_client()
    monkeypatch.setattr(
        flask_app,
        "current_user_from_cookie",
        lambda: {"uid": "user-1", "email": "shopper@example.com"},
    )
    return client


def test_me_profile_requires_auth():
    client = flask_app.app.test_client()
    response = client.get("/me/profile", base_url="https://localhost")
    assert response.status_code == 401


def test_me_profile_round_trip(monkeypatch):
    client = auth_client(monkeypatch)
    payload = {
        "name": "Casey Shopper",
        "email": "shopper@example.com",
        "phone": "+1-555-0000",
        "address": {
            "line1": "1 Infinite Loop",
            "line2": "Suite 2",
            "city": "Cupertino",
            "state": "CA",
            "postal_code": "95014",
            "country": "USA",
        },
    }
    response = client.put("/me/profile", json=payload, base_url="https://localhost")
    assert response.status_code == 200
    data = response.get_json()
    assert data["address"]["line1"] == "1 Infinite Loop"
    stored = flask_app.PROFILE_STORE.get("user-1")
    assert stored["address"]["postal_code"] == "95014"

    fetched = client.get("/me/profile", base_url="https://localhost")
    assert fetched.status_code == 200
    assert fetched.get_json()["email"] == "shopper@example.com"


def test_me_banking_encrypted(monkeypatch):
    client = auth_client(monkeypatch)
    payload = {
        "cardholder": "Casey Shopper",
        "card_number": "4111111111111111",
        "exp_month": 12,
        "exp_year": 2031,
        "cvc": "999",
        "postal_code": "95014",
    }
    response = client.put("/me/banking", json=payload, base_url="https://localhost")
    assert response.status_code == 200
    summary = response.get_json()
    assert summary["card_last4"] == "1111"
    record = flask_app.BANKING_STORE.get("user-1")
    assert record["card_number"].endswith("1111")
    raw_bytes = flask_app.BANKING_FILE.read_bytes()
    assert b"4111111111111111" not in raw_bytes


def admin_client(monkeypatch):
    client = flask_app.app.test_client()
    monkeypatch.setattr(flask_app, "is_admin", lambda: True)
    monkeypatch.setattr(flask_app, "current_user_email", lambda: flask_app.ADMIN_EMAIL)
    with client.session_transaction() as session:
        session["user"] = {"email": flask_app.ADMIN_EMAIL}
        session["is_admin"] = True
    return client


def test_admin_profile_round_trip(monkeypatch):
    client = admin_client(monkeypatch)
    payload = {
        "name": "Jamie Admin",
        "email": "jamie@example.com",
        "phone": "555-2121",
        "address": {
            "line1": "500 Market St",
            "line2": "Floor 4",
            "city": "San Francisco",
            "state": "CA",
            "postal_code": "94105",
            "country": "USA",
        },
    }
    response = client.put(
        "/accounts/demo-user/profile",
        json=payload,
        base_url="https://localhost",
    )
    assert response.status_code == 200
    stored = flask_app.PROFILE_STORE.get("demo-user")
    assert stored["address"]["city"] == "San Francisco"

    fetched = client.get(
        "/accounts/demo-user/profile",
        base_url="https://localhost",
    )
    assert fetched.status_code == 200
    assert fetched.get_json()["address"]["country"] == "USA"


def test_admin_banking_exposes_full_card(monkeypatch):
    client = admin_client(monkeypatch)
    payload = {
        "cardholder": "Jamie Admin",
        "card_number": "5555444433332222",
        "exp_month": 3,
        "exp_year": 2032,
        "cvc": "123",
        "postal_code": "94105",
        "brand": "visa",
    }
    response = client.put(
        "/accounts/demo-user/banking",
        json=payload,
        base_url="https://localhost",
    )
    assert response.status_code == 200
    record = flask_app.BANKING_STORE.get("demo-user")
    assert record["card_number"].endswith("2222")

    fetched = client.get(
        "/accounts/demo-user/banking",
        base_url="https://localhost",
    )
    assert fetched.status_code == 200
    data = fetched.get_json()
    assert data["card_number"].endswith("2222")
    assert data["has_cvc"] is True
