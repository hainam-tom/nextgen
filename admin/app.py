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

import os
import datetime
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
from flask_cors import CORS
from flask_talisman import Talisman
from authlib.integrations.flask_client import OAuth
import firebase_admin
from firebase_admin import credentials, auth as fb_auth
from pydantic import BaseModel, ValidationError, Field, EmailStr
from typing import Optional, Any
import requests

from commonlib import (
    load_admin_config,
    load_service_account,
    EncryptedJSONStore,
    JsonStore,
)

BASE_DIR = Path(__file__).resolve().parent

CONFIG = load_admin_config(BASE_DIR)

ADMIN_EMAIL = CONFIG.admin_email
SECRET_KEY = CONFIG.secret_key

GOOGLE_CLIENT_ID = CONFIG.google_client_id
GOOGLE_CLIENT_SECRET = CONFIG.google_client_secret

FIREBASE_WEB_API_KEY = CONFIG.firebase_web_api_key
SESSION_COOKIE_NAME = CONFIG.session_cookie_name
SESSION_MAX_DAYS = CONFIG.session_max_days

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
    SESSION_COOKIE_SECURE=True,  # we're serving with https (adhoc)
)

# CORS (same-origin requests for dashboard; keep modest defaults)
allowed_origins = [o for o in CONFIG.allowed_origins]
CORS(app, resources={r"/*": {"origins": allowed_origins}})

# Security headers
Talisman(app, content_security_policy=None)

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


def load_credentials() -> Optional[dict[str, Any]]:
    """Return service account credentials from disk/env when available."""

    return load_service_account(BASE_DIR, os.environ)


FIREBASE_READY = False
try:
    credential_info = load_credentials()
    if credential_info:
        if firebase_admin._apps:
            firebase_admin.get_app()
        else:
            cred = credentials.Certificate(credential_info)
            firebase_admin.initialize_app(cred)
        FIREBASE_READY = True
    else:
        raise RuntimeError("credentials not provided")
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


class ProfileUpdateModel(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    address: Optional[dict[str, Any]] = None


class BankingUpdateModel(BaseModel):
    accounts: Optional[list[dict[str, Any]]] = None
    cards: Optional[list[dict[str, Any]]] = None


# ---------------------------------------------------------------------------
# Local JSON helpers (products, accounts, banking)
# ---------------------------------------------------------------------------
PRODUCT_FILE = BASE_DIR / "products.json"
PRODUCT_STORE = JsonStore(PRODUCT_FILE)
ACCOUNT_STORE = JsonStore(BASE_DIR / "accounts.json")
BANKING_STORE = EncryptedJSONStore.from_environment(
    BASE_DIR / "banking.json.enc", os.environ, BASE_DIR / ".fernet.key"
)


def _load_account_profiles() -> dict[str, dict[str, Any]]:
    raw = ACCOUNT_STORE.read(default={})
    if isinstance(raw, dict):
        profiles = raw.get("profiles")
        if isinstance(profiles, dict):
            return profiles
    elif isinstance(raw, list):
        profiles = {}
        for item in raw:
            if isinstance(item, dict) and item.get("uid"):
                profiles[item["uid"]] = item
        return profiles
    return {}


def _store_account_profiles(profiles: dict[str, dict[str, Any]]) -> None:
    ACCOUNT_STORE.write({"profiles": profiles})


def upsert_account_profile(
    uid: str,
    *,
    email: Optional[str] = None,
    name: Optional[str] = None,
    address: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    profiles = _load_account_profiles()
    profile = profiles.get(uid, {"uid": uid})
    if email is not None:
        profile["email"] = email
    if name is not None:
        profile["name"] = name
    if address is not None:
        profile["address"] = address
    profiles[uid] = profile
    _store_account_profiles(profiles)
    return profile


def get_account_profile(uid: str) -> Optional[dict[str, Any]]:
    return _load_account_profiles().get(uid)


def delete_account_profile(uid: str) -> None:
    profiles = _load_account_profiles()
    if uid in profiles:
        profiles.pop(uid)
        _store_account_profiles(profiles)


def _load_banking_payload() -> dict[str, Any]:
    raw = BANKING_STORE.read(default={})
    if isinstance(raw, dict):
        return raw
    return {}


def get_account_banking(uid: str) -> dict[str, Any]:
    payload = _load_banking_payload()
    accounts = payload.get("accounts")
    if not isinstance(accounts, dict):
        return {}
    data = accounts.get(uid)
    return data if isinstance(data, dict) else {}


def set_account_banking(uid: str, banking: dict[str, Any]) -> dict[str, Any]:
    payload = _load_banking_payload()
    accounts = payload.setdefault("accounts", {})
    if not isinstance(accounts, dict):
        accounts = {}
        payload["accounts"] = accounts
    accounts[uid] = banking
    BANKING_STORE.write(payload)
    return banking


def delete_account_banking(uid: str) -> None:
    payload = _load_banking_payload()
    accounts = payload.get("accounts")
    if isinstance(accounts, dict) and uid in accounts:
        accounts.pop(uid)
        BANKING_STORE.write(payload)


def list_products_local() -> list:
    return PRODUCT_STORE.read(default=[])


def append_product_local(doc: dict) -> str:
    items = PRODUCT_STORE.read(default=[])
    doc_id = str(uuid4())
    doc["id"] = doc_id
    items.append(doc)
    PRODUCT_STORE.write(items)
    return doc_id


def get_product_local(doc_id: str) -> dict | None:
    items = PRODUCT_STORE.read(default=[])
    for item in items:
        if item.get("id") == doc_id:
            return item
    return None


def update_product_local(doc_id: str, updates: dict) -> dict | None:
    """Update product; returns updated product or None."""
    items = PRODUCT_STORE.read(default=[])
    for item in items:
        if item.get("id") == doc_id:
            item.update({k: v for k, v in updates.items() if v is not None})
            PRODUCT_STORE.write(items)
            return item
    return None


def delete_product_local(doc_id: str) -> bool:
    """Remove product from local JSON store. Returns True if deleted."""
    items = PRODUCT_STORE.read(default=[])
    new_items = [p for p in items if p.get("id") != doc_id]
    if len(new_items) == len(items):
        return False
    PRODUCT_STORE.write(new_items)
    return True


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
        upsert_account_profile(user.uid, email=account.email, name=account.name)
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
        upsert_account_profile(
            updated.uid,
            email=updated.email,
            name=updated.display_name or None,
        )
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
        delete_account_profile(uid)
        delete_account_banking(uid)
        return jsonify({"ok": True})
    except fb_auth.UserNotFoundError:
        return jsonify({"error": "Not found"}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/accounts/<uid>/profile", methods=["GET", "PUT"])
@admin_required
def manage_account_profile(uid):
    if request.method == "GET":
        profile = get_account_profile(uid) or {"uid": uid}
        return jsonify(profile)

    try:
        payload = request.get_json(force=True) or {}
        data = ProfileUpdateModel(**payload)
    except ValidationError as err:
        return jsonify({"error": err.errors()}), 400

    profile = upsert_account_profile(
        uid,
        email=data.email,
        name=data.name,
        address=data.address,
    )
    if profile.get("email") is None and FIREBASE_READY:
        try:
            fb_user = fb_auth.get_user(uid)
            profile = upsert_account_profile(
                uid,
                email=fb_user.email,
                name=fb_user.display_name or None,
                address=data.address,
            )
        except Exception:
            pass
    return jsonify(profile)


@app.route("/accounts/<uid>/banking", methods=["GET", "PUT", "DELETE"])
@admin_required
def manage_account_banking(uid):
    if request.method == "GET":
        return jsonify(get_account_banking(uid))

    if request.method == "DELETE":
        delete_account_banking(uid)
        return jsonify({"ok": True})

    try:
        payload = request.get_json(force=True) or {}
        data = BankingUpdateModel(**payload)
    except ValidationError as err:
        return jsonify({"error": err.errors()}), 400

    record = get_account_banking(uid)
    if data.cards is not None:
        record["cards"] = data.cards
    if data.accounts is not None:
        record["accounts"] = data.accounts
    record["updated_at"] = datetime.datetime.utcnow().isoformat()
    set_account_banking(uid, record)
    return jsonify(record)


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
    return render_template(
        "index.html",
        products=products,
        accounts=accounts,
        is_admin=is_admin(),
        user_email=current_user_email(),
        ADMIN_EMAIL=ADMIN_EMAIL,
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
    # Self-signed certificate for local HTTPS
    app.run(host="0.0.0.0", port=7890, ssl_context="adhoc")
