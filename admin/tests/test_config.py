import pytest

from admin import app as flask_app
from commonlib import (
    canonical_origin,
    infer_public_base_url,
    infer_allowed_origins,
    discover_api_bases,
)


def test_canonical_origin_handles_default_ports():
    assert canonical_origin("example.com", 443, "https") == "https://example.com"
    assert canonical_origin("example.com", 80, "http") == "http://example.com"


def test_canonical_origin_invalid_inputs():
    with pytest.raises(ValueError):
        canonical_origin("", 443, "https")
    with pytest.raises(ValueError):
        canonical_origin("example.com", 0, "https")
    with pytest.raises(ValueError):
        canonical_origin("example.com", 80, "ftp")


def test_infer_public_base_url_prefers_explicit():
    result = infer_public_base_url("https://api.example.com", "shop.example.com", 443, True)
    assert result == "https://api.example.com"


def test_infer_public_base_url_from_domain():
    result = infer_public_base_url("", "shop.example.com", 443, True)
    assert result == "https://shop.example.com"


def test_infer_allowed_origins_builds_domain_and_fallback():
    origins = infer_allowed_origins(
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
    origins = infer_allowed_origins(
        "https://custom.example,https://other.example",
        7890,
        "https",
        "shop.example.com",
        "https://shop.example.com",
        "",
        443,
    )
    assert origins == ["https://custom.example", "https://other.example"]


def test_discover_api_bases_generates_fallbacks():
    bases = discover_api_bases(hints=["https://api.example.com"], include_defaults=False)
    assert bases[0] == "https://api.example.com"
    assert "http://api.example.com" in bases
