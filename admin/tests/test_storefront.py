import json

import json

from admin import app as flask_app


def test_storefront_home_renders_products(configure_test_env):
    product_file = configure_test_env
    product_file.write_text(
        json.dumps([{"id": "p1", "name": "Desk Lamp", "price": 39.5, "description": "Warm light"}]),
        encoding="utf-8",
    )
    client = flask_app.app.test_client()
    response = client.get("/")
    assert response.status_code == 200
    assert b"Desk Lamp" in response.data
    assert b"Warm light" in response.data


def test_cart_add_and_update(configure_test_env):
    product_file = configure_test_env
    product_file.write_text(
        json.dumps([{"id": "p2", "name": "Keyboard", "price": 90.0}]),
        encoding="utf-8",
    )
    client = flask_app.app.test_client()

    add_response = client.post("/cart/add/p2", data={"quantity": "2"}, follow_redirects=True)
    assert add_response.status_code == 200
    assert b"Keyboard" in add_response.data

    cart_response = client.get("/cart")
    assert cart_response.status_code == 200
    assert b"Keyboard" in cart_response.data
    assert b"$180.00" in cart_response.data

    update_response = client.post("/cart/update", data={"quantity_p2": "1"}, follow_redirects=True)
    assert update_response.status_code == 200
    assert b"$90.00" in update_response.data

    clear_response = client.post("/cart/clear", follow_redirects=True)
    assert b"Your cart is empty" in clear_response.data


def test_auth_register_form_sets_cookie(configure_test_env):
    client = flask_app.app.test_client()
    response = client.post(
        "/auth/register",
        data={"email": "shopper@example.com", "name": "Casey Shopper", "password": "hunter222"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/account")
    assert flask_app.SESSION_COOKIE_NAME in response.headers.get("Set-Cookie", "")

    account_page = client.get("/account", follow_redirects=True)
    assert account_page.status_code == 200
    assert b"Account settings" in account_page.data


def test_product_detail_page_and_reviews(configure_test_env):
    product_file = configure_test_env
    product_file.write_text(
        json.dumps([{"id": "p1", "name": "Desk Lamp", "price": 39.5, "description": "Warm light"}]),
        encoding="utf-8",
    )
    flask_app.REVIEWS_STORE.put(
        "p1",
        [
            {
                "id": "r1",
                "rating": 4,
                "comment": "Bright and cosy",
                "created_at": "2024-01-01T12:00:00",
                "author": {"uid": "u1", "email": "demo@example.com", "name": "Demo"},
            }
        ],
    )
    client = flask_app.app.test_client()
    response = client.get("/catalog/p1")
    assert response.status_code == 200
    assert b"Desk Lamp" in response.data
    assert b"Bright and cosy" in response.data


def test_product_review_requires_login(configure_test_env):
    product_file = configure_test_env
    product_file.write_text(
        json.dumps([{"id": "p1", "name": "Desk Lamp", "price": 39.5}]),
        encoding="utf-8",
    )
    client = flask_app.app.test_client()
    response = client.post(
        "/catalog/p1/reviews",
        data={"rating": "5", "comment": "Great"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/auth/login?next=/catalog/p1")


def test_product_review_submission(monkeypatch, configure_test_env):
    product_file = configure_test_env
    product_file.write_text(
        json.dumps([{"id": "p1", "name": "Desk Lamp", "price": 39.5}]),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        flask_app,
        "current_user_from_cookie",
        lambda: {"uid": "user-1", "email": "shopper@example.com"},
    )
    client = flask_app.app.test_client()
    response = client.post(
        "/catalog/p1/reviews",
        data={"rating": "4", "comment": "Solid glow"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    stored = flask_app.REVIEWS_STORE.get("p1")
    assert stored and stored[0]["comment"] == "Solid glow"
    assert b"Solid glow" in response.data
