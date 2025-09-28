"""Network/origin helpers shared across Vendly services."""
from __future__ import annotations

from typing import Sequence

DEFAULT_LOCAL_BASES = ("https://127.0.0.1:7890", "http://127.0.0.1:7890")


def canonical_origin(host: str, port: int, scheme: str) -> str:
    """Return a canonical origin string (scheme://host[:port])."""

    host = (host or "").strip()
    if not host:
        raise ValueError("host is required")

    scheme = (scheme or "").strip().lower()
    if scheme not in {"http", "https"}:
        raise ValueError("scheme must be http or https")

    if port <= 0 or port > 65535:
        raise ValueError("port must be between 1 and 65535")

    default_port = 443 if scheme == "https" else 80
    suffix = "" if port == default_port else f":{port}"
    return f"{scheme}://{host}{suffix}"


def infer_public_base_url(raw_base: str, domain: str, public_port: int, force_tls: bool) -> str:
    """Return the preferred public API base URL based on config inputs."""

    candidate = (raw_base or "").strip().rstrip("/")
    if candidate:
        return candidate

    domain = (domain or "").strip()
    if not domain:
        return ""

    scheme = "https" if force_tls else "http"
    try:
        return canonical_origin(domain, public_port, scheme)
    except ValueError:
        return ""


def infer_allowed_origins(
    configured: str,
    port: int,
    scheme: str,
    domain: str,
    base_url: str,
    fallback_host: str,
    public_port: int,
) -> list[str]:
    """Compute CORS origins including local redundancies."""

    explicit = (configured or "").strip()
    if explicit:
        return [origin.strip() for origin in explicit.split(",") if origin.strip()]

    origins: list[str] = []
    for local_scheme in ("http", "https"):
        try:
            origins.append(canonical_origin("127.0.0.1", port, local_scheme))
        except ValueError:
            continue

    fallback_host = (fallback_host or "").strip()
    if fallback_host:
        try:
            origins.append(canonical_origin(fallback_host, port, scheme))
        except ValueError:
            pass

    domain = (domain or "").strip()
    if domain:
        for hostname in (domain, f"www.{domain}"):
            try:
                origins.append(canonical_origin(hostname, public_port, "https"))
            except ValueError:
                continue

    base_url = (base_url or "").strip()
    if base_url and base_url not in origins:
        origins.append(base_url)

    # De-duplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for origin in origins:
        if origin not in seen:
            seen.add(origin)
            unique.append(origin)
    return unique


def build_api_url(base: str, path: str = "/") -> str:
    """Combine a base URL with a path while avoiding double slashes."""

    base = (base or "").rstrip("/")
    if not path:
        return base
    suffix = path if path.startswith("/") else f"/{path}"
    return f"{base}{suffix}"


def _add_with_fallback(bases: list[str], seen: set[str], base: str) -> None:
    base = base.rstrip("/")
    if not base or base in seen:
        return
    seen.add(base)
    bases.append(base)
    fallback = None
    if base.startswith("https://"):
        fallback = f"http://{base[len('https://'):]}"
    elif base.startswith("http://"):
        fallback = f"https://{base[len('http://'):]}"
    if fallback and fallback not in seen:
        seen.add(fallback)
        bases.append(fallback)


def discover_api_bases(*, hints: Sequence[str] | None = None, include_defaults: bool = True) -> list[str]:
    """Normalise a list of candidate API base URLs with scheme redundancy."""

    bases: list[str] = []
    seen: set[str] = set()

    if hints:
        for hint in hints:
            hint = (hint or "").strip()
            if not hint:
                continue
            _add_with_fallback(bases, seen, hint)

    if include_defaults:
        for default in DEFAULT_LOCAL_BASES:
            _add_with_fallback(bases, seen, default)

    return bases
