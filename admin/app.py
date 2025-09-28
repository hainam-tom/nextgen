"""Simple Flask API for product and account management.

- Products, shopper credentials, and profile data are persisted to local
  JSON stores with redundant backups for self-hosted resilience.
- Admin access is granted via the Firebase Admin SDK by tagging specific
  Google accounts with an ``is_admin`` custom claim. Only the configured
  service manager can enrol new admins, and Firebase is never exposed to the
  browser.
- Admin authentication uses server-side Google OAuth (OIDC) with Authlib;
  sessions are stored server-side and restricted to accounts tagged as admins.
- Shopper authentication is provided entirely by the Flask API using
  bcrypt-strength password hashing and signed session cookies—no Firebase
  dependency for end-users.
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
    send_from_directory,
    flash,
)
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask_cors import CORS
from flask_talisman import Talisman
from firebase_admin import credentials, auth as fb_auth
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from pydantic import BaseModel, ValidationError, Field, EmailStr, field_validator
from typing import Optional
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
import firebase_admin
import secrets

from commonlib.network import (
    canonical_origin,
    infer_public_base_url,
    infer_allowed_origins,
)
from commonlib.storage import EncryptedJsonStore, JsonStore, StoreError

BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
COMMONLIB_DIR = BASE_DIR.parent / "commonlib"

# ---------------------------------------------------------------------------
# Config / Secrets
# ---------------------------------------------------------------------------
load_dotenv(BASE_DIR / ".env")


def env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


SERVICE_MANAGER_EMAIL = (
    os.environ.get("SERVICE_MANAGER_EMAIL")
    or os.environ.get("ADMIN_EMAIL")
    or "tom05012013@gmail.com"
).lower()
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

# Local session/token configuration for shopper accounts
SESSION_COOKIE_NAME = "vendly_session"
SESSION_MAX_DAYS = int(os.environ.get("SESSION_MAX_DAYS", "5"))
SESSION_SERIALIZER = URLSafeTimedSerializer(SECRET_KEY, salt="vendly-user-session")

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(
    __name__,
    template_folder=str(TEMPLATE_DIR),
    static_folder=str(STATIC_DIR),
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


def _load_cart() -> dict[str, int]:
    cart = session.get("cart")
    if not isinstance(cart, dict):
        return {}
    cleaned: dict[str, int] = {}
    for product_id, quantity in cart.items():
        try:
            qty = int(quantity)
        except (TypeError, ValueError):
            continue
        if qty > 0:
            cleaned[str(product_id)] = qty
    return cleaned


def _cart_items_with_totals(cart: dict[str, int]) -> tuple[list[dict], float]:
    items: list[dict] = []
    total = 0.0
    for product_id, quantity in cart.items():
        product = get_product_local(product_id)
        if not product:
            continue
        price = float(product.get("price", 0) or 0)
        subtotal = price * quantity
        total += subtotal
        items.append({"product": product, "quantity": quantity, "total": subtotal})
    return items, total


def _wants_json_response() -> bool:
    if request.is_json:
        return True
    accept = request.accept_mimetypes
    return accept and accept.best == "application/json"


@app.context_processor
def inject_template_globals():
    user = current_user_from_cookie()
    cart = _load_cart()
    return {"current_user": user, "cart_count": sum(cart.values())}


@app.route("/commonlib/<path:filename>")
def serve_commonlib(filename: str):
    """Expose shared browser helpers for both admin and storefront UIs."""

    return send_from_directory(COMMONLIB_DIR, filename)

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
    description: str = ""
    image: Optional[str] = None


class AccountModel(BaseModel):
    email: EmailStr
    name: str = ""


class AccountCreateModel(AccountModel):
    password: Optional[str] = Field(default=None, min_length=8, max_length=128)

    @field_validator("password", mode="before")
    @classmethod
    def normalise_password(cls, value):
        if value is None:
            return None
        value = str(value).strip()
        return value or None


class ProductUpdateModel(BaseModel):
    name: Optional[str] = Field(None, min_length=1)
    price: Optional[float] = Field(None, ge=0)
    description: Optional[str] = None
    image: Optional[str] = None


class AccountUpdateModel(BaseModel):
    email: Optional[EmailStr] = None
    name: Optional[str] = None
    password: Optional[str] = Field(default=None, min_length=8, max_length=128)

    @field_validator("password", mode="before")
    @classmethod
    def normalise_optional_password(cls, value):
        if value is None:
            return None
        value = str(value).strip()
        return value or None


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
# Local JSON helpers (products + shopper accounts)
# ---------------------------------------------------------------------------
PRODUCT_FILE = BASE_DIR / "products.json"
PROFILE_FILE = BASE_DIR / "accounts.json"
AUTH_FILE = BASE_DIR / "auth.json"
BANKING_FILE = BASE_DIR / "banking.enc"

PROFILE_STORE = JsonStore(PROFILE_FILE, backups=PRODUCT_BACKUPS)
AUTH_STORE = JsonStore(AUTH_FILE, backups=PRODUCT_BACKUPS)
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


def _normalise_email(value: str | None) -> str:
    return (value or "").strip().lower()


def _list_local_accounts() -> dict[str, dict]:
    return AUTH_STORE.all()


def _find_account_by_email(email: str) -> tuple[str | None, dict | None]:
    target = _normalise_email(email)
    if not target:
        return (None, None)
    for uid, record in _list_local_accounts().items():
        if _normalise_email(record.get("email")) == target:
            return (uid, record)
    return (None, None)


def _load_account(uid: str) -> dict | None:
    return _list_local_accounts().get(uid)


def _store_account(uid: str, payload: dict) -> dict:
    payload = {**payload, "email": _normalise_email(payload.get("email"))}
    AUTH_STORE.put(uid, payload)
    return payload


def _ensure_profile(uid: str, email: str | None = None, name: str | None = None) -> None:
    existing = PROFILE_STORE.get(uid)
    if existing:
        return
    PROFILE_STORE.put(
        uid,
        {
            "email": _normalise_email(email),
            "name": name or "",
            "phone": "",
            "address": _blank_address(),
        },
    )


def _account_response(uid: str, record: dict) -> dict:
    return {
        "id": uid,
        "email": record.get("email", ""),
        "name": record.get("name", ""),
        "created_at": record.get("created_at"),
        "updated_at": record.get("updated_at"),
    }


def _generate_password(length: int = 12) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


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
    return _normalise_email(email) if isinstance(email, str) else None


def is_service_manager() -> bool:
    return bool(session.get("is_service_manager")) or (
        current_user_email() == SERVICE_MANAGER_EMAIL
    )


def is_admin() -> bool:
    return bool(session.get("is_admin"))


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


def _admin_flags_for_email(email: str) -> tuple[bool, bool]:
    normalised = _normalise_email(email)
    is_service = normalised == SERVICE_MANAGER_EMAIL
    is_admin_flag = False
    if FIREBASE_READY and normalised:
        try:
            user = fb_auth.get_user_by_email(normalised)
            claims = user.custom_claims or {}
            is_admin_flag = bool(claims.get("is_admin"))
        except fb_auth.UserNotFoundError:
            is_admin_flag = False
        except Exception:
            is_admin_flag = False
    return is_admin_flag, is_service


def grant_admin_via_firebase(email: str) -> dict:
    if not FIREBASE_READY:
        raise RuntimeError("Firebase Admin not configured")
    normalised = _normalise_email(email)
    if not normalised:
        raise ValueError("Email required")
    try:
        user = fb_auth.get_user_by_email(normalised)
    except fb_auth.UserNotFoundError:
        user = fb_auth.create_user(email=normalised)
    claims = user.custom_claims or {}
    if not claims.get("is_admin"):
        claims["is_admin"] = True
        fb_auth.set_custom_user_claims(user.uid, claims)
    return {"uid": user.uid, "email": normalised}


def _list_firebase_admins() -> list[dict]:
    if not FIREBASE_READY:
        return []
    admins: list[dict] = []
    try:
        for user in fb_auth.list_users().iterate_all():
            claims = user.custom_claims or {}
            if claims.get("is_admin"):
                admins.append(
                    {
                        "uid": user.uid,
                        "email": _normalise_email(user.email or ""),
                        "name": user.display_name or "",
                    }
                )
    except Exception as exc:
        raise RuntimeError(str(exc)) from exc
    return admins


def _set_session_cookie(resp, uid: str, email: str):
    expires_in = datetime.timedelta(days=SESSION_MAX_DAYS)
    payload = {
        "uid": uid,
        "email": _normalise_email(email),
        "issued_at": datetime.datetime.now(datetime.UTC).timestamp(),
    }
    token = SESSION_SERIALIZER.dumps(payload)
    resp.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        max_age=int(expires_in.total_seconds()),
        httponly=True,
        secure=FORCE_TLS,
        samesite="Lax",
    )


def _clear_session_cookie(resp):
    resp.delete_cookie(SESSION_COOKIE_NAME, samesite="Lax")


def current_user_from_cookie():
    cookie = request.cookies.get(SESSION_COOKIE_NAME)
    if not cookie:
        return None
    try:
        decoded = SESSION_SERIALIZER.loads(
            cookie, max_age=SESSION_MAX_DAYS * 24 * 60 * 60
        )
    except (BadSignature, SignatureExpired):
        return None
    uid = decoded.get("uid")
    email = decoded.get("email")
    if not uid:
        return None
    account = _load_account(uid)
    if not account:
        return None
    return {"uid": uid, "email": account.get("email") or _normalise_email(email)}


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

    email = _normalise_email(info.get("email"))
    session["user"] = {
        "email": email,
        "name": info.get("name") or "",
        "sub": info.get("sub") or "",
    }
    is_admin_flag, is_service = _admin_flags_for_email(email)
    session["is_admin"] = is_admin_flag
    session["is_service_manager"] = is_service
    if not is_admin_flag and not is_service:
        session["login_error"] = (
            "This Google account is not authorised for the admin dashboard. "
            "Ask the service manager to grant access."
        )
        session.pop("user", None)
        session.pop("is_admin", None)
        session.pop("is_service_manager", None)
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/setup")
def admin_setup():
    if not is_service_manager():
        return redirect(url_for("admin_dashboard"))
    admins: list[dict] = []
    error = None
    try:
        admins = _list_firebase_admins()
    except RuntimeError as exc:
        error = str(exc)
    return render_template(
        "admin/setup.html",
        service_manager_email=SERVICE_MANAGER_EMAIL,
        admins=admins,
        firebase_ready=FIREBASE_READY,
        error=error,
    )


@app.route("/admin/setup/begin")
def admin_setup_begin():
    if not is_service_manager():
        return redirect(url_for("admin_dashboard"))
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return "Google OAuth not configured", 503
    redirect_uri = url_for("admin_setup_callback", _external=True, _scheme="https")
    return oauth.google.authorize_redirect(
        redirect_uri, prompt="select_account", access_type="offline"
    )


@app.route("/admin/setup/callback")
def admin_setup_callback():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return "Google OAuth not configured", 503
    if not is_service_manager():
        session.clear()
        return redirect(url_for("admin_dashboard"))

    token = oauth.google.authorize_access_token()
    info = None
    try:
        info = oauth.google.parse_id_token(token)
    except Exception:
        info = None
    if not info:
        userinfo_url = (
            oauth.google.server_metadata.get("userinfo_endpoint")
            or "https://openidconnect.googleapis.com/v1/userinfo"
        )
        resp = oauth.google.get(userinfo_url)
        info = resp.json() if resp else {}

    email = _normalise_email(info.get("email"))
    success = False
    error = None
    if not email:
        error = "Google did not return an email address."
    elif not FIREBASE_READY:
        error = "Firebase Admin SDK is not configured."
    else:
        try:
            grant_admin_via_firebase(email)
            success = True
        except Exception as exc:
            error = str(exc)

    session.clear()
    return render_template(
        "admin/setup_result.html",
        success=success,
        created_email=email,
        error=error,
        service_manager_email=SERVICE_MANAGER_EMAIL,
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("admin_dashboard"))


# ---------------------------------------------------------------------------
# End-user auth routes (password login via server)
# ---------------------------------------------------------------------------
@app.route("/auth/register", methods=["GET", "POST"])
def auth_register():
    if request.method == "GET":
        return render_template("storefront/register.html")

    json_request = request.is_json
    try:
        if json_request:
            payload = request.get_json(force=True) or {}
        else:
            payload = {k: v for k, v in request.form.items()}
        registration = AccountCreateModel(**payload)
    except ValidationError as err:
        if json_request:
            return jsonify({"error": err.errors()}), 400
        flash("; ".join(e["msg"] for e in err.errors()), "danger")
        return redirect(url_for("auth_register"))

    existing_uid, _ = _find_account_by_email(registration.email)
    if existing_uid:
        if json_request:
            return jsonify({"error": "Email already exists"}), 409
        flash("Email already exists", "danger")
        return redirect(url_for("auth_register"))

    uid = str(uuid4())
    now_iso = datetime.datetime.now(datetime.UTC).isoformat()
    password = registration.password or _generate_password()
    stored = {
        "email": registration.email,
        "name": registration.name or "",
        "password_hash": generate_password_hash(password),
        "created_at": now_iso,
        "updated_at": now_iso,
    }
    _store_account(uid, stored)
    _ensure_profile(uid, registration.email, registration.name)

    try:
        if json_request:
            resp = make_response(jsonify({"id": uid, "password": password}))
        else:
            message = "Account created successfully."
            if not registration.password:
                message += f" Temporary password: {password}"
            flash(message, "success")
            resp = make_response(redirect(url_for("account_settings")))
        _set_session_cookie(resp, uid, registration.email)
        if json_request:
            return resp, 201
        return resp
    except Exception as exc:
        if json_request:
            return jsonify({"error": str(exc)}), 500
        flash(f"Failed to create account: {exc}", "danger")
        return redirect(url_for("auth_register"))


@app.route("/auth/login", methods=["GET", "POST"])
def auth_login():
    if request.method == "GET":
        return render_template("storefront/login.html")

    json_request = request.is_json
    try:
        if json_request:
            payload = request.get_json(force=True) or {}
        else:
            payload = {k: v for k, v in request.form.items()}
        email = (payload.get("email") or "").strip()
        password = payload.get("password") or ""
        if not email or not password:
            if json_request:
                return jsonify({"error": "Email and password are required"}), 400
            flash("Email and password are required", "danger")
            return redirect(url_for("auth_login"))
        uid, record = _find_account_by_email(email)
        if not uid or not record or not check_password_hash(record.get("password_hash", ""), password):
            if json_request:
                return jsonify({"error": "Invalid credentials"}), 401
            flash("Invalid credentials", "danger")
            return redirect(url_for("auth_login"))
        if json_request:
            resp = make_response(jsonify({"ok": True}))
        else:
            flash("Signed in successfully", "success")
            resp = make_response(redirect(url_for("storefront_home")))
        _set_session_cookie(resp, uid, record.get("email") or email)
        return resp
    except Exception as exc:
        if json_request:
            return jsonify({"error": str(exc)}), 500
        flash(f"Login failed: {exc}", "danger")
        return redirect(url_for("auth_login"))


@app.route("/auth/logout", methods=["POST", "GET"])
def auth_logout():
    json_request = _wants_json_response()
    if json_request:
        resp = make_response(jsonify({"ok": True}))
    else:
        flash("Signed out", "success")
        resp = make_response(redirect(url_for("storefront_home")))
    _clear_session_cookie(resp)
    session.pop("cart", None)
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
    try:
        payload = [
            _account_response(uid, record)
            for uid, record in _list_local_accounts().items()
        ]
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    return jsonify(payload)


@app.route("/accounts/<uid>", methods=["GET"])
@admin_required
def get_account(uid):
    record = _load_account(uid)
    if not record:
        return jsonify({"error": "Not found"}), 404
    return jsonify(_account_response(uid, record))


@app.route("/accounts", methods=["POST"])
@admin_required
def create_account():
    try:
        payload = request.get_json(force=True) or {}
        account = AccountCreateModel(**payload)
    except ValidationError as err:
        return jsonify({"error": err.errors()}), 400
    existing_uid, _ = _find_account_by_email(account.email)
    if existing_uid:
        return jsonify({"error": "Email already exists"}), 409
    password = account.password or _generate_password()
    uid = str(uuid4())
    now_iso = datetime.datetime.now(datetime.UTC).isoformat()
    stored = {
        "email": account.email,
        "name": account.name or "",
        "password_hash": generate_password_hash(password),
        "created_at": now_iso,
        "updated_at": now_iso,
    }
    _store_account(uid, stored)
    _ensure_profile(uid, account.email, account.name)
    return jsonify({"id": uid, "password": password}), 201


@app.route("/accounts/<uid>", methods=["PUT"])
@admin_required
def update_account(uid):
    record = _load_account(uid)
    if not record:
        return jsonify({"error": "Not found"}), 404
    try:
        payload = request.get_json(force=True) or {}
        updates = AccountUpdateModel(**payload)
    except ValidationError as err:
        return jsonify({"error": err.errors()}), 400
    new_record = dict(record)
    changed_password = None
    if updates.email:
        new_email = _normalise_email(updates.email)
        existing_uid, _ = _find_account_by_email(new_email)
        if existing_uid and existing_uid != uid:
            return jsonify({"error": "Email already exists"}), 409
        new_record["email"] = new_email
    if updates.name is not None:
        new_record["name"] = updates.name
    if updates.password:
        changed_password = updates.password
        new_record["password_hash"] = generate_password_hash(updates.password)
    new_record["updated_at"] = datetime.datetime.now(datetime.UTC).isoformat()
    _store_account(uid, new_record)
    _ensure_profile(uid, new_record.get("email"), new_record.get("name"))
    response = _account_response(uid, new_record)
    if changed_password:
        response["password"] = changed_password
    return jsonify(response)


@app.route("/accounts/<uid>", methods=["DELETE"])
@admin_required
def delete_account(uid):
    record = _load_account(uid)
    if not record:
        return jsonify({"error": "Not found"}), 404
    AUTH_STORE.remove(uid)
    PROFILE_STORE.remove(uid)
    BANKING_STORE.remove(uid)
    return jsonify({"ok": True})


@app.route("/accounts/<uid>/profile", methods=["GET", "PUT"])
@admin_required
def admin_account_profile(uid):
    account = _load_account(uid)
    email_hint = account.get("email") if account else None
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
# Storefront views (server-rendered to avoid client-side duplication).
# ---------------------------------------------------------------------------
@app.route("/")
def storefront_home():
    products = list_products_local()
    cart = _load_cart()
    return render_template(
        "storefront/home.html",
        products=products,
        cart_count=sum(cart.values()),
    )


@app.route("/cart")
def storefront_cart():
    cart = _load_cart()
    items, total = _cart_items_with_totals(cart)
    return render_template("storefront/cart.html", items=items, total=total)


@app.route("/cart/add/<product_id>", methods=["POST"])
def cart_add(product_id: str):
    product = get_product_local(product_id)
    if not product:
        flash("Product not found", "danger")
        return redirect(url_for("storefront_home"))
    try:
        quantity = int(request.form.get("quantity", "1"))
    except ValueError:
        quantity = 1
    quantity = max(1, quantity)
    cart = _load_cart()
    cart[product_id] = cart.get(product_id, 0) + quantity
    session["cart"] = cart
    session.modified = True
    flash(f"Added {product.get('name', 'item')} to cart", "success")
    return redirect(request.referrer or url_for("storefront_home"))


@app.route("/cart/update", methods=["POST"])
def cart_update():
    cart: dict[str, int] = {}
    for key, value in request.form.items():
        if not key.startswith("quantity_"):
            continue
        product_id = key[len("quantity_"):]
        try:
            qty = int(value)
        except ValueError:
            continue
        if qty > 0 and get_product_local(product_id):
            cart[product_id] = qty
    session["cart"] = cart
    session.modified = True
    flash("Cart updated", "success")
    return redirect(url_for("storefront_cart"))


@app.route("/cart/clear", methods=["POST"])
def cart_clear():
    session.pop("cart", None)
    session.modified = True
    flash("Cart cleared", "info")
    return redirect(url_for("storefront_cart"))


@app.route("/account")
def account_settings():
    user = current_user_from_cookie()
    if not user:
        flash("Please sign in to manage your account", "warning")
        return redirect(url_for("auth_login"))
    profile = load_profile(user["uid"], user.get("email"))
    try:
        raw_banking = BANKING_STORE.get(user["uid"], {})
    except StoreError as exc:
        flash(f"Unable to load payment details: {exc}", "danger")
        raw_banking = {}
    summary = banking_summary(raw_banking)
    summary_display = {
        "cardholder": summary.get("cardholder", ""),
        "card_number": "",
        "exp_month": summary.get("exp_month"),
        "exp_year": summary.get("exp_year"),
        "cvc": "",
        "postal_code": summary.get("billing_postal", ""),
    }
    return render_template(
        "storefront/account.html",
        profile=profile,
        banking=summary_display,
    )


@app.route("/account/profile", methods=["POST"])
def account_profile():
    user = current_user_from_cookie()
    if not user:
        flash("Please sign in to update your profile", "warning")
        return redirect(url_for("auth_login"))
    address_payload = {
        "line1": request.form.get("line1", "").strip(),
        "line2": request.form.get("line2", "").strip(),
        "city": request.form.get("city", "").strip(),
        "state": request.form.get("state", "").strip(),
        "postal_code": request.form.get("postal_code", "").strip(),
        "country": request.form.get("country", "").strip(),
    }
    payload = {
        "email": request.form.get("email"),
        "name": request.form.get("name", ""),
        "phone": request.form.get("phone", ""),
        "address": address_payload,
    }
    try:
        profile_model = AccountProfileModel(**payload)
    except ValidationError as err:
        flash("; ".join(e["msg"] for e in err.errors()), "danger")
        return redirect(url_for("account_settings"))
    try:
        save_profile(user["uid"], profile_model, email_override=request.form.get("email"))
    except StoreError as exc:
        flash(f"Failed to save profile: {exc}", "danger")
        return redirect(url_for("account_settings"))
    flash("Profile updated", "success")
    return redirect(url_for("account_settings"))


@app.route("/account/banking", methods=["POST"])
def account_banking():
    user = current_user_from_cookie()
    if not user:
        flash("Please sign in to update payment details", "warning")
        return redirect(url_for("auth_login"))
    payload = {
        "cardholder": request.form.get("cardholder", ""),
        "card_number": request.form.get("card_number", ""),
        "exp_month": request.form.get("exp_month"),
        "exp_year": request.form.get("exp_year"),
        "cvc": request.form.get("cvc", ""),
        "postal_code": request.form.get("postal_code", ""),
    }
    try:
        banking_model = BankingModel(**payload)
    except ValidationError as err:
        flash("; ".join(e["msg"] for e in err.errors()), "danger")
        return redirect(url_for("account_settings"))
    try:
        save_banking(user["uid"], banking_model)
    except StoreError as exc:
        flash(f"Failed to save payment info: {exc}", "danger")
        return redirect(url_for("account_settings"))
    flash("Payment information updated", "success")
    return redirect(url_for("account_settings"))


# ---------------------------------------------------------------------------
# Admin dashboard (SSR) and product helpers
# ---------------------------------------------------------------------------
@app.route("/admin")
def admin_dashboard():
    products = list_products_local()
    return render_template("admin/dashboard.html", products=products)


@app.route("/admin/products/create", methods=["POST"])
def admin_create_product():
    if not (is_admin() or is_service_manager()):
        flash("Admin privileges required", "danger")
        return redirect(url_for("admin_dashboard"))
    form_data = {
        "name": request.form.get("name", ""),
        "price": request.form.get("price"),
        "description": request.form.get("description", ""),
        "image": request.form.get("image") or None,
    }
    try:
        if form_data["price"] is not None:
            form_data["price"] = float(form_data["price"])
        product = ProductModel(**form_data)
    except (ValidationError, ValueError) as err:
        message = "; ".join(e["msg"] for e in err.errors()) if isinstance(err, ValidationError) else str(err)
        flash(f"Unable to create product: {message}", "danger")
        return redirect(url_for("admin_dashboard"))
    append_product_local(product.model_dump())
    flash("Product added", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/products/<product_id>/delete", methods=["POST"])
def admin_delete_product(product_id: str):
    if not (is_admin() or is_service_manager()):
        flash("Admin privileges required", "danger")
        return redirect(url_for("admin_dashboard"))
    if delete_product_local(product_id):
        flash("Product removed", "success")
    else:
        flash("Product not found", "warning")
    return redirect(url_for("admin_dashboard"))


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
