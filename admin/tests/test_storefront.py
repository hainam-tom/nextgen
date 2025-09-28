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
