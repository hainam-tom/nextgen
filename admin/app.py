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
import json
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
from dotenv import load_dotenv
from flask_cors import CORS
from flask_talisman import Talisman
from authlib.integrations.flask_client import OAuth
import firebase_admin
from firebase_admin import credentials, auth as fb_auth
from pydantic import BaseModel, ValidationError, Field, EmailStr
import requests

BASE_DIR = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Config / Secrets
# ---------------------------------------------------------------------------
load_dotenv(BASE_DIR / ".env")

ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "tom05012013@gmail.com").lower()
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-change-me")

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
    SESSION_COOKIE_SECURE=True,  # we're serving with https (adhoc)
)

# CORS (same-origin requests for dashboard; keep modest defaults)
_default_origins = "https://localhost,https://127.0.0.1,http://localhost,http://127.0.0.1"
allowed_origins = os.environ.get("ALLOWED_ORIGINS", _default_origins).split(",")
CORS(app, resources={r"/*": {"origins": [o.strip() for o in allowed_origins]}})

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

# ---------------------------------------------------------------------------
# Local JSON helpers (PRODUCTS ONLY)
# ---------------------------------------------------------------------------
PRODUCT_FILE = BASE_DIR / "products.json"


def safe_write_json(path: Path, data: list) -> None:
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def safe_read_json(path: Path) -> list:
    if Path(path).exists():
        try:
            return json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception:
            return []
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
        return {"uid": decoded.get("uid"), "email": (decoded.get("email") or "").lower()}
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
    session["is_admin"] = (email == ADMIN_EMAIL)
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
        user = fb_auth.create_user(email=email, password=password, display_name=name or None)
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
        r = requests.post(_gitkit_url("signInWithPassword"), json={
            "email": email,
            "password": password,
            "returnSecureToken": True,
        }, timeout=10)
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
            users.append({
                "id": u.uid,
                "email": u.email,
                "name": u.display_name or "",
                "disabled": bool(u.disabled),
                "email_verified": bool(u.email_verified),
            })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    return jsonify(users)


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
        user = fb_auth.create_user(email=account.email, display_name=account.name or None)
        return jsonify({"id": user.uid}), 201
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

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
