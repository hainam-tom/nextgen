import pytest

from admin import app as flask_app


def test_canonical_origin_handles_default_ports():
    assert flask_app.canonical_origin("example.com", 443, "https") == "https://example.com"
    assert flask_app.canonical_origin("example.com", 80, "http") == "http://example.com"


def test_canonical_origin_invalid_inputs():
    with pytest.raises(ValueError):
        flask_app.canonical_origin("", 443, "https")
    with pytest.raises(ValueError):
        flask_app.canonical_origin("example.com", 0, "https")
    with pytest.raises(ValueError):
        flask_app.canonical_origin("example.com", 80, "ftp")


def test_infer_public_base_url_prefers_explicit():
    result = flask_app.infer_public_base_url("https://api.example.com", "shop.example.com", 443, True)
    assert result == "https://api.example.com"


def test_infer_public_base_url_from_domain():
    result = flask_app.infer_public_base_url("", "shop.example.com", 443, True)
    assert result == "https://shop.example.com"


def test_infer_allowed_origins_builds_domain_and_fallback():
    origins = flask_app.infer_allowed_origins(
        "",
        7890,
        "https",
        "shop.example.com",
        "https://shop.example.com",
        "10.0.0.5",
        443,
    )
    assert "https://127.0.0.1:7890" in origins
    assert "http://127.0.0.1:7890" in origins
    assert "https://10.0.0.5:7890" in origins
    assert "https://shop.example.com" in origins
    assert "https://www.shop.example.com" in origins


def test_infer_allowed_origins_respects_explicit_list():
    origins = flask_app.infer_allowed_origins(
        "https://custom.example,https://other.example",
        7890,
        "https",
        "shop.example.com",
        "https://shop.example.com",
        "",
        443,
    )
    assert origins == ["https://custom.example", "https://other.example"]
