import json

import pytest

from admin import app as flask_app


def test_create_product_requires_admin():
    client = flask_app.app.test_client()
    response = client.post(
        "/products",
        json={"name": "Widget", "price": 5.0},
        base_url="https://localhost",
    )
    assert response.status_code == 401
    payload = response.get_json()
    assert payload["error"] == "Authentication required"


def test_create_product_recovers_from_corrupt_store(configure_test_env):
    product_file = configure_test_env
    product_file.write_text('{"bad": true}', encoding="utf-8")

    client = flask_app.app.test_client()
    with client.session_transaction() as session:
        session["user"] = {"email": "admin@example.com"}
        session["is_admin"] = True

    response = client.post(
        "/products",
        json={"name": "Test Item", "price": 9.99},
        base_url="https://localhost",
    )

    assert response.status_code == 201
    payload = response.get_json()
    assert "id" in payload and isinstance(payload["id"], str)

    saved = json.loads(product_file.read_text(encoding="utf-8"))
    assert isinstance(saved, list)
    assert saved[0]["name"] == "Test Item"
    assert saved[0]["price"] == pytest.approx(9.99)

    # Subsequent reads should surface the newly created product
    get_response = client.get("/products", base_url="https://localhost")
    assert get_response.status_code == 200
    products = get_response.get_json()
    assert isinstance(products, list) and len(products) == 1
    assert products[0]["id"] == payload["id"]


def test_products_endpoint_falls_back_to_backup(configure_test_env):
    product_file = configure_test_env
    client = flask_app.app.test_client()
    with client.session_transaction() as session:
        session["user"] = {"email": "admin@example.com"}
        session["is_admin"] = True

    first = client.post(
        "/products",
        json={"name": "Primary", "price": 10},
        base_url="https://localhost",
    ).get_json()

    client.post(
        "/products",
        json={"name": "Secondary", "price": 12},
        base_url="https://localhost",
    )

    product_file.write_text("{corrupt", encoding="utf-8")

    resp = client.get("/products", base_url="https://localhost")
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, list) and len(data) >= 1
    assert any(item["id"] == first["id"] for item in data)
