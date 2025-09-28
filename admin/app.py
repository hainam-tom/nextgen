"""Simple Flask API for product and account management.

- Products are stored **locally** (JSON file).
- Accounts are managed via **Firebase Admin SDK** (create/list users). No
  Firestore and **no Firebase client in the browser**.
- **Admin authentication** is server-side **Google OAuth (OIDC)** using
  Authlib. The admin session is stored in a server-side cookie; only the
  `ADMIN_EMAIL` may create products, create accounts, or view all accounts.
- **End-user auth** uses Firebase Identity Toolkit via server-only REST to
  verify password and mint a secure **session cookie**. No Firebase config
  on the client.
"""

from __future__ import annotations

import datetime
import json
import os
import re
from pathlib import Path
from uuid import uuid4
from functools import wraps

from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    redirect,
    url_for,
    session,
    make_response,
)
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask_cors import CORS
from flask_talisman import Talisman
from firebase_admin import credentials, auth as fb_auth
from pydantic import BaseModel, ValidationError, Field, EmailStr, field_validator
from typing import Optional
from werkzeug.middleware.proxy_fix import ProxyFix
import firebase_admin
import requests
from urllib.parse import urlparse

from .storage import EncryptedJsonStore, JsonStore, StoreError

BASE_DIR = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Config / Secrets
# ---------------------------------------------------------------------------
load_dotenv(BASE_DIR / ".env")


def env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def canonical_origin(host: str, port: int, scheme: str) -> str:
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


def infer_public_base_url(
    raw_base: str, domain: str, public_port: int, force_tls: bool
) -> str:
    candidate = (raw_base or "").strip().rstrip("/")
    if candidate:
        return candidate
    if domain:
        scheme = "https" if force_tls else "http"
        try:
            return canonical_origin(domain, public_port, scheme)
        except ValueError:
            return ""
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
    explicit = (configured or "").strip()
    if explicit:
        return [o.strip() for o in explicit.split(",") if o.strip()]

    origins: list[str] = []
    for local_scheme in ("http", "https"):
        try:
            origins.append(canonical_origin("127.0.0.1", port, local_scheme))
        except ValueError:
            continue

    if fallback_host:
        try:
            origins.append(canonical_origin(fallback_host, port, scheme))
        except ValueError:
            pass

    if domain:
        try:
            origins.append(canonical_origin(domain, public_port, scheme))
            if not domain.startswith("www."):
                origins.append(
                    canonical_origin(f"www.{domain}", public_port, scheme)
                )
        except ValueError:
            pass

    if base_url:
        parsed = urlparse(base_url)
        if parsed.hostname:
            inferred_scheme = parsed.scheme or scheme
            inferred_port = (
                parsed.port
                if parsed.port
                else (443 if inferred_scheme == "https" else 80)
            )
            try:
                origins.append(
                    canonical_origin(parsed.hostname, inferred_port, inferred_scheme)
                )
            except ValueError:
                pass

    deduped: list[str] = []
    seen: set[str] = set()
    for origin in origins:
        if origin not in seen:
            seen.add(origin)
            deduped.append(origin)
    return deduped


ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "tom05012013@gmail.com").lower()
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-change-me")
BANKING_SECRET_KEY = os.environ.get("BANKING_SECRET_KEY", SECRET_KEY)
FORCE_TLS = env_bool("FORCE_TLS", True)
API_HOST = os.environ.get("API_HOST", "0.0.0.0")
API_PORT = int(os.environ.get("API_PORT", "7890"))
PUBLIC_PORT = int(os.environ.get("PUBLIC_PORT", str(API_PORT)))
PUBLIC_DOMAIN = os.environ.get("PUBLIC_DOMAIN", "").strip().lower()
PUBLIC_FALLBACK_HOST = os.environ.get("PUBLIC_FALLBACK_HOST", "").strip()
TLS_CERT_FILE = os.environ.get("TLS_CERT_FILE", "").strip()
TLS_KEY_FILE = os.environ.get("TLS_KEY_FILE", "").strip()
LETS_ENCRYPT_EMAIL = os.environ.get("LETS_ENCRYPT_EMAIL", "").strip()
RAW_PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").strip().rstrip("/")
PUBLIC_BASE_URL = infer_public_base_url(
    RAW_PUBLIC_BASE_URL,
    PUBLIC_DOMAIN,
    PUBLIC_PORT,
    FORCE_TLS,
)
PRODUCT_BACKUPS = int(os.environ.get("PRODUCT_BACKUPS", "3"))

# Google OAuth (server-side)
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")

# Identity Toolkit (server-only password auth for end-users)
FIREBASE_WEB_API_KEY = os.environ.get("FIREBASE_WEB_API_KEY", "").strip()
SESSION_COOKIE_NAME = "fb_session"
SESSION_MAX_DAYS = int(os.environ.get("SESSION_MAX_DAYS", "5"))

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(
    __name__,
    template_folder=str(BASE_DIR),
    static_folder=str(BASE_DIR),
    static_url_path="",
)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=FORCE_TLS,
    PREFERRED_URL_SCHEME="https" if FORCE_TLS else "http",
    PUBLIC_DOMAIN=PUBLIC_DOMAIN,
    PUBLIC_BASE_URL=PUBLIC_BASE_URL,
    PUBLIC_FALLBACK_HOST=PUBLIC_FALLBACK_HOST,
    PUBLIC_PORT=PUBLIC_PORT,
    LETS_ENCRYPT_EMAIL=LETS_ENCRYPT_EMAIL,
)

# CORS (same-origin requests for dashboard; keep modest defaults)
_default_origins = (
    "https://localhost,https://127.0.0.1,http://localhost,http://127.0.0.1"
)
allowed_origins = infer_allowed_origins(
    os.environ.get("ALLOWED_ORIGINS", ""),
    API_PORT,
    "https" if FORCE_TLS else "http",
    PUBLIC_DOMAIN,
    PUBLIC_BASE_URL,
    PUBLIC_FALLBACK_HOST,
    PUBLIC_PORT,
)
if not allowed_origins:
    allowed_origins = [o.strip() for o in _default_origins.split(",") if o.strip()]
CORS(app, resources={r"/*": {"origins": [o.strip() for o in allowed_origins if o.strip()]}})

# Security headers
Talisman(app, content_security_policy=None, force_https=FORCE_TLS)

if TLS_CERT_FILE and not Path(TLS_CERT_FILE).exists():
    print(f"WARNING: TLS_CERT_FILE not found at {TLS_CERT_FILE}")
if TLS_KEY_FILE and not Path(TLS_KEY_FILE).exists():
    print(f"WARNING: TLS_KEY_FILE not found at {TLS_KEY_FILE}")

if env_bool("TRUST_PROXY_HEADERS", True):
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Google OAuth (server-side)
# ---------------------------------------------------------------------------
if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    print("WARNING: GOOGLE_CLIENT_ID/SECRET not set; /login will 503")

oauth = OAuth(app)
oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
    api_base_url="https://openidconnect.googleapis.com/v1/",
)

# ---------------------------------------------------------------------------
# Firebase Admin SDK (for account management only; no client SDK in browser)
# ---------------------------------------------------------------------------


def load_credentials() -> dict:
    """Return service account credentials from file or environment."""
    auth_file = BASE_DIR / "firebase-auth.json"
    if auth_file.exists():
        return json.loads(auth_file.read_text(encoding="utf-8"))

    secret_file = BASE_DIR / "clientSecret.json"
    if secret_file.exists():
        data = json.loads(secret_file.read_text(encoding="utf-8"))
        if data.get("type") == "service_account":
            return data

    return {
        "type": "service_account",
        "project_id": os.environ.get("FIREBASE_PROJECT_ID", ""),
        # IMPORTANT: env var usually stores newlines as \n
        "private_key": os.environ.get("FIREBASE_PRIVATE_KEY", "").replace("\\n", "\n"),
        "client_email": os.environ.get("FIREBASE_CLIENT_EMAIL", ""),
        "token_uri": "https://oauth2.googleapis.com/token",
    }


FIREBASE_READY = False
try:
    cred = credentials.Certificate(load_credentials())
    firebase_admin.initialize_app(cred)
    FIREBASE_READY = True
except Exception as exc:  # optional
    print(f"Firebase Admin disabled: {exc}")


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class ProductModel(BaseModel):
    name: str = Field(..., min_length=1)
    price: float = Field(..., ge=0)


class AccountModel(BaseModel):
    email: EmailStr
    name: str = ""


class ProductUpdateModel(BaseModel):
    name: Optional[str] = Field(None, min_length=1)
    price: Optional[float] = Field(None, ge=0)


class AccountUpdateModel(BaseModel):
    email: Optional[EmailStr] = None
    name: Optional[str] = None
    disabled: Optional[bool] = None


class AddressModel(BaseModel):
    line1: str = Field(..., min_length=1, max_length=200)
    line2: str = Field("", max_length=200)
    city: str = Field(..., min_length=1, max_length=120)
    state: str = Field(..., min_length=1, max_length=120)
    postal_code: str = Field(..., min_length=1, max_length=20)
    country: str = Field(..., min_length=1, max_length=80)


class AccountProfileModel(BaseModel):
    name: str = ""
    email: Optional[EmailStr] = None
    phone: str = ""
    avatar: Optional[str] = None
    address: AddressModel


CURRENT_YEAR = datetime.datetime.now(datetime.UTC).year


class BankingModel(BaseModel):
    cardholder: str = Field(..., min_length=2, max_length=120)
    card_number: str = Field(..., min_length=12, max_length=19)
    exp_month: int = Field(..., ge=1, le=12)
    exp_year: int = Field(..., ge=CURRENT_YEAR, le=CURRENT_YEAR + 20)
    cvc: str = Field(..., min_length=3, max_length=4)
    postal_code: str = Field("", max_length=20)
    brand: str = ""

    @staticmethod
    def _digits(value: str) -> str:
        digits = re.sub(r"\D", "", value or "")
        return digits

    @classmethod
    def _validate_digits(cls, value: str, field: str, minimum: int, maximum: int) -> str:
        digits = cls._digits(value)
        if len(digits) < minimum or len(digits) > maximum:
            raise ValueError(f"{field} must contain between {minimum} and {maximum} digits")
        return digits

    @field_validator("card_number", mode="before")
    @classmethod
    def validate_card_number(cls, value: str) -> str:  # noqa: D401
        """Ensure the card number only contains digits and is realistic."""
        return cls._validate_digits(str(value), "Card number", 12, 19)

    @field_validator("cvc", mode="before")
    @classmethod
    def validate_cvc(cls, value: str) -> str:
        return cls._validate_digits(str(value), "CVC", 3, 4)


# ---------------------------------------------------------------------------
# Local JSON helpers (PRODUCTS ONLY)
# ---------------------------------------------------------------------------
PRODUCT_FILE = BASE_DIR / "products.json"
PROFILE_FILE = BASE_DIR / "accounts.json"
BANKING_FILE = BASE_DIR / "banking.enc"

PROFILE_STORE = JsonStore(PROFILE_FILE, backups=PRODUCT_BACKUPS)
BANKING_STORE = EncryptedJsonStore(BANKING_FILE, BANKING_SECRET_KEY, backups=PRODUCT_BACKUPS)


def _product_backup_path(path: Path, index: int) -> Path:
    return path.with_suffix(path.suffix + f".bak{index}")


def _product_candidates(path: Path) -> list[Path]:
    candidates = [path]
    for idx in range(1, PRODUCT_BACKUPS + 1):
        candidates.append(_product_backup_path(path, idx))
    return candidates


def _product_rotate_backups(path: Path) -> None:
    if PRODUCT_BACKUPS <= 0:
        return
    for idx in range(PRODUCT_BACKUPS, 0, -1):
        src = path if idx == 1 else _product_backup_path(path, idx - 1)
        dest = _product_backup_path(path, idx)
        if src.exists():
            try:
                os.replace(src, dest)
            except OSError:
                continue


def safe_write_json(path: Path, data: list) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _product_rotate_backups(path)
    payload = json.dumps(data, indent=2)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as fh:
        fh.write(payload)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp_path, path)
    tmp_path.unlink(missing_ok=True)


def safe_read_json(path: Path) -> list:
    """Return a list from ``path`` or a redundant backup when available."""

    for candidate in _product_candidates(Path(path)):
        if not candidate.exists():
            continue
        try:
            raw = candidate.read_text(encoding="utf-8")
        except OSError:
            continue
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(data, list):
            if candidate != Path(path):
                print(f"Recovered product catalog from backup {candidate.name}")
            return data
    return []


def list_products_local() -> list:
    return safe_read_json(PRODUCT_FILE)


def append_product_local(doc: dict) -> str:
    items = safe_read_json(PRODUCT_FILE)
    doc_id = str(uuid4())
    doc["id"] = doc_id
    items.append(doc)
    safe_write_json(PRODUCT_FILE, items)
    return doc_id


def get_product_local(doc_id: str) -> dict | None:
    items = safe_read_json(PRODUCT_FILE)
    for item in items:
        if item.get("id") == doc_id:
            return item
    return None


def update_product_local(doc_id: str, updates: dict) -> dict | None:
    """Update product; returns updated product or None."""
    items = safe_read_json(PRODUCT_FILE)
    for item in items:
        if item.get("id") == doc_id:
            item.update({k: v for k, v in updates.items() if v is not None})
            safe_write_json(PRODUCT_FILE, items)
            return item
    return None


def delete_product_local(doc_id: str) -> bool:
    """Remove product from local JSON store. Returns True if deleted."""
    items = safe_read_json(PRODUCT_FILE)
    new_items = [p for p in items if p.get("id") != doc_id]
    if len(new_items) == len(items):
        return False
    safe_write_json(PRODUCT_FILE, new_items)
    return True


def _blank_address() -> dict:
    return {
        "line1": "",
        "line2": "",
        "city": "",
        "state": "",
        "postal_code": "",
        "country": "",
    }


def load_profile(uid: str, email_hint: str | None = None) -> dict:
    stored = PROFILE_STORE.get(uid, {}) or {}
    address = {**_blank_address(), **(stored.get("address") or {})}
    return {
        "uid": uid,
        "email": email_hint or stored.get("email") or "",
        "name": stored.get("name", ""),
        "phone": stored.get("phone", ""),
        "avatar": stored.get("avatar"),
        "address": address,
    }


def save_profile(uid: str, profile: AccountProfileModel, *, email_override: str | None = None) -> dict:
    payload = profile.model_dump()
    if email_override:
        payload["email"] = email_override
    else:
        payload["email"] = (payload.get("email") or "").lower()
    if payload.get("avatar") is None:
        payload.pop("avatar", None)
    payload["address"] = profile.address.model_dump()
    PROFILE_STORE.put(uid, payload)
    return load_profile(uid, payload.get("email"))


def detect_card_brand(card_number: str) -> str:
    digits = re.sub(r"\D", "", card_number or "")
    if digits.startswith("4"):
        return "visa"
    if digits[:2] in {"51", "52", "53", "54", "55"} or (
        digits[:4].isdigit() and 2221 <= int(digits[:4]) <= 2720
    ):
        return "mastercard"
    if digits.startswith("34") or digits.startswith("37"):
        return "amex"
    if digits.startswith("6011") or digits.startswith("65"):
        return "discover"
    if digits.startswith("35"):
        return "jcb"
    if digits.startswith("30") or digits.startswith("36") or digits.startswith("38"):
        return "diners"
    return "other"


def save_banking(uid: str, payload: BankingModel) -> dict:
    record = payload.model_dump()
    record["card_number"] = payload.card_number  # ensure digits-only
    record["brand"] = payload.brand or detect_card_brand(payload.card_number)
    BANKING_STORE.put(uid, record)
    return record


def banking_summary(record: dict | None, *, reveal: bool = False) -> dict:
    record = record or {}
    summary = {
        "cardholder": record.get("cardholder", ""),
        "brand": record.get("brand", ""),
        "card_last4": (record.get("card_number") or "")[-4:],
        "exp_month": record.get("exp_month"),
        "exp_year": record.get("exp_year"),
        "billing_postal": record.get("postal_code", ""),
    }
    if reveal:
        summary["card_number"] = record.get("card_number")
        summary["cvc"] = record.get("cvc")
    summary["has_cvc"] = bool(record.get("cvc"))
    return summary


# ---------------------------------------------------------------------------
# Admin session helpers (Google OAuth)
# ---------------------------------------------------------------------------


def current_user_email() -> str | None:
    user = session.get("user") or {}
    email = user.get("email")
    return email.lower() if isinstance(email, str) else None


def is_admin() -> bool:
    return current_user_email() == ADMIN_EMAIL


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not is_admin():
            # If not logged in, send 401; if logged in but not admin, 403.
            if session.get("user"):
                return jsonify({"error": "Admin privileges required"}), 403
            return jsonify({"error": "Authentication required"}), 401
        return fn(*args, **kwargs)

    return wrapper


def user_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user_from_cookie()
        if not user:
            return jsonify({"error": "Authentication required"}), 401
        kwargs["current_user"] = user
        return fn(*args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------------
# End-user session helpers (Firebase session cookie)
# ---------------------------------------------------------------------------


def _gitkit_url(method: str) -> str:
    return f"https://identitytoolkit.googleapis.com/v1/accounts:{method}?key={FIREBASE_WEB_API_KEY}"


def _set_session_cookie(resp, id_token: str):
    expires_in = datetime.timedelta(days=SESSION_MAX_DAYS)
    session_cookie = fb_auth.create_session_cookie(id_token, expires_in=expires_in)
    resp.set_cookie(
        SESSION_COOKIE_NAME,
        session_cookie,
        max_age=int(expires_in.total_seconds()),
        httponly=True,
        secure=True,
        samesite="Lax",
    )


def _clear_session_cookie(resp):
    resp.delete_cookie(SESSION_COOKIE_NAME, samesite="Lax")


def current_user_from_cookie():
    cookie = request.cookies.get(SESSION_COOKIE_NAME)
    if not cookie:
        return None
    try:
        decoded = fb_auth.verify_session_cookie(cookie, check_revoked=True)
        return {
            "uid": decoded.get("uid"),
            "email": (decoded.get("email") or "").lower(),
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# OAuth routes (admin)
# ---------------------------------------------------------------------------
@app.route("/login")
def login():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return "Google OAuth not configured", 503
    redirect_uri = url_for("auth_callback", _external=True, _scheme="https")
    return oauth.google.authorize_redirect(redirect_uri)


@app.route("/auth/callback")
def auth_callback():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return "Google OAuth not configured", 503

    token = oauth.google.authorize_access_token()

    # Prefer ID token claims (already in the token)
    info = None
    try:
        info = oauth.google.parse_id_token(token)
    except Exception:
        info = None

    # Fallback: call the userinfo endpoint
    if not info:
        userinfo_url = (
            oauth.google.server_metadata.get("userinfo_endpoint")
            or "https://openidconnect.googleapis.com/v1/userinfo"
        )
        resp = oauth.google.get(userinfo_url)
        info = resp.json() if resp else {}

    email = (info.get("email") or "").lower()
    session["user"] = {
        "email": email,
        "name": info.get("name") or "",
        "sub": info.get("sub") or "",
    }
    session["is_admin"] = email == ADMIN_EMAIL
    return redirect(url_for("admin_dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("admin_dashboard"))


# ---------------------------------------------------------------------------
# End-user auth routes (password login via server)
# ---------------------------------------------------------------------------
@app.route("/auth/register", methods=["POST"])
def auth_register():
    if not FIREBASE_READY:
        return jsonify({"error": "Firebase Admin not configured"}), 503
    try:
        payload = request.get_json(force=True) or {}
        email = (payload.get("email") or "").strip()
        password = payload.get("password") or ""
        name = (payload.get("name") or "").strip()
        if not email or not password or len(password) < 8:
            return jsonify({"error": "Email and password (>=8 chars) required"}), 400
        user = fb_auth.create_user(
            email=email, password=password, display_name=name or None
        )
        return jsonify({"id": user.uid}), 201
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/auth/login", methods=["POST"])
def auth_login():
    if not FIREBASE_READY or not FIREBASE_WEB_API_KEY:
        return jsonify({"error": "Auth not configured"}), 503
    try:
        payload = request.get_json(force=True) or {}
        email = (payload.get("email") or "").strip()
        password = payload.get("password") or ""
        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400
        r = requests.post(
            _gitkit_url("signInWithPassword"),
            json={
                "email": email,
                "password": password,
                "returnSecureToken": True,
            },
            timeout=10,
        )
        if r.status_code != 200:
            msg = r.json().get("error", {}).get("message", "INVALID_LOGIN")
            return jsonify({"error": f"Login failed: {msg}"}), 401
        id_token = r.json()["idToken"]
        resp = make_response(jsonify({"ok": True}))
        _set_session_cookie(resp, id_token)
        return resp
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/auth/logout", methods=["POST"])
def auth_logout():
    resp = make_response(jsonify({"ok": True}))
    _clear_session_cookie(resp)
    return resp


@app.route("/auth/me", methods=["GET"])
def auth_me():
    user = current_user_from_cookie()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    return jsonify(user)


@app.route("/me/profile", methods=["GET", "PUT"])
@user_required
def me_profile(current_user):
    if request.method == "GET":
        return jsonify(load_profile(current_user["uid"], current_user.get("email")))
    try:
        payload = request.get_json(force=True) or {}
        profile = AccountProfileModel(**payload)
    except ValidationError as err:
        return jsonify({"error": err.errors()}), 400
    saved = save_profile(current_user["uid"], profile, email_override=current_user.get("email"))
    return jsonify(saved)


@app.route("/me/banking", methods=["GET", "PUT"])
@user_required
def me_banking(current_user):
    try:
        record = BANKING_STORE.get(current_user["uid"], {})
    except StoreError as exc:
        return jsonify({"error": str(exc)}), 500
    if request.method == "GET":
        return jsonify(banking_summary(record))
    try:
        payload = request.get_json(force=True) or {}
        banking = BankingModel(**payload)
    except ValidationError as err:
        return jsonify({"error": err.errors()}), 400
    try:
        record = save_banking(current_user["uid"], banking)
    except StoreError as exc:
        return jsonify({"error": str(exc)}), 500
    return jsonify(banking_summary(record))


# ---------------------------------------------------------------------------
# Routes — Products (LOCAL) — admin required for create
# ---------------------------------------------------------------------------
@app.route("/products", methods=["GET"])
def get_products():
    return jsonify(list_products_local())


@app.route("/products/<product_id>", methods=["GET"])
def get_product(product_id):
    item = get_product_local(product_id)
    if not item:
        return jsonify({"error": "Not found"}), 404
    return jsonify(item)


@app.route("/products", methods=["POST"])
@admin_required
def create_product():
    try:
        payload = request.get_json(force=True) or {}
        product = ProductModel(**payload)
    except ValidationError as err:
        return jsonify({"error": err.errors()}), 400
    doc = product.model_dump()
    doc_id = append_product_local(doc)
    return jsonify({"id": doc_id}), 201


@app.route("/products/<product_id>", methods=["PUT"])
@admin_required
def update_product(product_id):
    try:
        payload = request.get_json(force=True) or {}
        product = ProductUpdateModel(**payload)
    except ValidationError as err:
        return jsonify({"error": err.errors()}), 400
    updated = update_product_local(product_id, product.model_dump(exclude_none=True))
    if not updated:
        return jsonify({"error": "Not found"}), 404
    return jsonify(updated)


@app.route("/products/<product_id>", methods=["DELETE"])
@admin_required
def delete_product(product_id):
    deleted = delete_product_local(product_id)
    if not deleted:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Routes — Accounts (Firebase Admin only) — admin only
# ---------------------------------------------------------------------------
@app.route("/accounts", methods=["GET"])
@admin_required
def get_accounts():
    if not FIREBASE_READY:
        return jsonify({"error": "Firebase Admin not configured"}), 503
    users = []
    try:
        for u in fb_auth.list_users().iterate_all():
            users.append(
                {
                    "id": u.uid,
                    "email": u.email,
                    "name": u.display_name or "",
                    "disabled": bool(u.disabled),
                    "email_verified": bool(u.email_verified),
                }
            )
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    return jsonify(users)


@app.route("/accounts/<uid>", methods=["GET"])
@admin_required
def get_account(uid):
    if not FIREBASE_READY:
        return jsonify({"error": "Firebase Admin not configured"}), 503
    try:
        u = fb_auth.get_user(uid)
        return jsonify(
            {
                "id": u.uid,
                "email": u.email,
                "name": u.display_name or "",
                "disabled": bool(u.disabled),
                "email_verified": bool(u.email_verified),
            }
        )
    except fb_auth.UserNotFoundError:
        return jsonify({"error": "Not found"}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/accounts", methods=["POST"])
@admin_required
def create_account():
    if not FIREBASE_READY:
        return jsonify({"error": "Firebase Admin not configured"}), 503
    try:
        payload = request.get_json(force=True) or {}
        account = AccountModel(**payload)
    except ValidationError as err:
        return jsonify({"error": err.errors()}), 400
    try:
        user = fb_auth.create_user(
            email=account.email, display_name=account.name or None
        )
        return jsonify({"id": user.uid}), 201
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/accounts/<uid>", methods=["PUT"])
@admin_required
def update_account(uid):
    if not FIREBASE_READY:
        return jsonify({"error": "Firebase Admin not configured"}), 503
    try:
        payload = request.get_json(force=True) or {}
        account = AccountUpdateModel(**payload)
    except ValidationError as err:
        return jsonify({"error": err.errors()}), 400
    try:
        fb_auth.update_user(
            uid,
            email=account.email,
            display_name=account.name,
            disabled=account.disabled,
        )
        updated = fb_auth.get_user(uid)
        return jsonify(
            {
                "id": updated.uid,
                "email": updated.email,
                "name": updated.display_name or "",
                "disabled": bool(updated.disabled),
                "email_verified": bool(updated.email_verified),
            }
        )
    except fb_auth.UserNotFoundError:
        return jsonify({"error": "Not found"}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/accounts/<uid>", methods=["DELETE"])
@admin_required
def delete_account(uid):
    if not FIREBASE_READY:
        return jsonify({"error": "Firebase Admin not configured"}), 503
    try:
        fb_auth.delete_user(uid)
        return jsonify({"ok": True})
    except fb_auth.UserNotFoundError:
        return jsonify({"error": "Not found"}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/accounts/<uid>/profile", methods=["GET", "PUT"])
@admin_required
def admin_account_profile(uid):
    email_hint = None
    if FIREBASE_READY:
        try:
            fb_user = fb_auth.get_user(uid)
            email_hint = (fb_user.email or "").lower()
        except Exception:
            email_hint = None
    if request.method == "GET":
        return jsonify(load_profile(uid, email_hint))
    try:
        payload = request.get_json(force=True) or {}
        profile = AccountProfileModel(**payload)
    except ValidationError as err:
        return jsonify({"error": err.errors()}), 400
    saved = save_profile(uid, profile, email_override=email_hint or profile.email)
    return jsonify(saved)


@app.route("/accounts/<uid>/banking", methods=["GET", "PUT"])
@admin_required
def admin_account_banking(uid):
    try:
        record = BANKING_STORE.get(uid, {})
    except StoreError as exc:
        return jsonify({"error": str(exc)}), 500
    if request.method == "GET":
        return jsonify(banking_summary(record, reveal=True))
    try:
        payload = request.get_json(force=True) or {}
        banking = BankingModel(**payload)
    except ValidationError as err:
        return jsonify({"error": err.errors()}), 400
    try:
        record = save_banking(uid, banking)
    except StoreError as exc:
        return jsonify({"error": str(exc)}), 500
    return jsonify(banking_summary(record, reveal=True))


# ---------------------------------------------------------------------------
# Admin dashboard (SSR). Accounts only shown to admin session.
# ---------------------------------------------------------------------------
@app.route("/")
def root():
    return redirect(url_for("admin_dashboard"))


@app.route("/admin")
def admin_dashboard():
    products = list_products_local()
    accounts = []
    if is_admin() and FIREBASE_READY:
        try:
            for u in fb_auth.list_users().iterate_all():
                accounts.append({"email": u.email, "name": u.display_name or ""})
        except Exception as exc:
            print(f"Failed to preload accounts: {exc}")
    api_base = PUBLIC_BASE_URL or request.url_root.rstrip("/")
    scheme = request.headers.get("X-Forwarded-Proto")
    if not PUBLIC_BASE_URL and scheme in {"http", "https"}:
        host = request.headers.get("X-Forwarded-Host") or request.host
        api_base = f"{scheme}://{host}".rstrip("/")
    if not api_base.startswith("http"):
        api_base = ("https" if FORCE_TLS else "http") + "://" + request.host
    return render_template(
        "index.html",
        products=products,
        accounts=accounts,
        is_admin=is_admin(),
        user_email=current_user_email(),
        ADMIN_EMAIL=ADMIN_EMAIL,
        api_base=api_base,
    )


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------
@app.after_request
def secure_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Prefer explicit certificate pair when provided, fall back to adhoc for local dev
    if TLS_CERT_FILE and TLS_KEY_FILE:
        ssl_ctx = (TLS_CERT_FILE, TLS_KEY_FILE)
    elif FORCE_TLS:
        ssl_ctx = "adhoc"
    else:
        ssl_ctx = None
    app.run(host=API_HOST, port=API_PORT, ssl_context=ssl_ctx)
