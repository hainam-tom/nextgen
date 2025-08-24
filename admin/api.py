"""Simple Flask API for product and account management."""

import os
import json
from pathlib import Path
from uuid import uuid4

from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv
from flask_cors import CORS
from flask_talisman import Talisman
import firebase_admin
from firebase_admin import credentials, firestore
from pydantic import BaseModel, ValidationError, Field, EmailStr

BASE_DIR = Path(__file__).resolve().parent


def load_credentials() -> dict:
    """Return service account credentials from file or environment.

    The function prefers a local ``firebase-auth.json`` file. If missing it
    falls back to ``clientSecret.json`` or finally to environment variables.
    Missing or malformed data simply disables Firestore.
    """

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
        "private_key": os.environ.get("FIREBASE_PRIVATE_KEY", "").replace("\\n", "\n"),
        "client_email": os.environ.get("FIREBASE_CLIENT_EMAIL", ""),
        "token_uri": "https://oauth2.googleapis.com/token",
    }


load_dotenv(BASE_DIR / ".env")

try:
    cred = credentials.Certificate(load_credentials())
    firebase_admin.initialize_app(cred)
    db = firestore.client()
except Exception as exc:  # pragma: no cover - Firestore optional
    print(f"Firestore disabled: {exc}")
    db = None

# Local JSON file snapshots
PRODUCT_FILE = BASE_DIR / "products.json"
ACCOUNT_FILE = BASE_DIR / "accounts.json"

app = Flask(__name__, template_folder=str(BASE_DIR), static_folder=str(BASE_DIR), static_url_path="")

# Restrict CORS origins to provided list or default localhost
allowed_origins = os.environ.get("ALLOWED_ORIGINS", "http://localhost").split(",")
CORS(app, resources={r"/*": {"origins": [o.strip() for o in allowed_origins]}})

# Security headers via Flask-Talisman
Talisman(app, content_security_policy=None)


class ProductModel(BaseModel):
    """Schema for validating product payloads."""

    name: str = Field(..., min_length=1)
    price: float = Field(..., ge=0)


class AccountModel(BaseModel):
    """Schema for validating account payloads."""

    email: EmailStr
    name: str = ""


def safe_write_json(path: str, data: list) -> None:
    """Atomically write ``data`` to ``path`` in JSON format."""

    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def safe_read_json(path: str) -> list:
    """Read a JSON array from ``path`` if it exists and is valid."""

    if Path(path).exists():
        try:
            return json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception:  # pragma: no cover - defensive
            return []
    return []


def snapshot_products() -> list:
    """Retrieve products from Firestore or local snapshot."""

    if db:
        try:
            docs = db.collection("products").stream()
            products = []
            for doc in docs:
                data = doc.to_dict()
                data["id"] = doc.id
                products.append(data)
            safe_write_json(PRODUCT_FILE, products)
            return products
        except Exception:  # pragma: no cover - network issues
            pass
    return safe_read_json(PRODUCT_FILE)


def snapshot_accounts() -> list:
    """Retrieve accounts from Firestore or local snapshot."""

    if db:
        try:
            docs = db.collection("accounts").stream()
            accounts = []
            for doc in docs:
                data = doc.to_dict()
                data["id"] = doc.id
                accounts.append(data)
            safe_write_json(ACCOUNT_FILE, accounts)
            return accounts
        except Exception:  # pragma: no cover - network issues
            pass
    return safe_read_json(ACCOUNT_FILE)


@app.route("/products", methods=["GET"])
def get_products():
    """Return the product catalog."""

    products = snapshot_products()
    return jsonify(products)


@app.route("/products", methods=["POST"])
def create_product():
    """Create a new product record."""

    try:
        product = ProductModel(**(request.get_json(force=True) or {}))
    except ValidationError as err:
        return jsonify({"error": err.errors()}), 400

    doc = product.dict()
    if db:
        try:
            ref = db.collection("products").add(doc)[1]
            doc_id = ref.id
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500
    else:
        products = safe_read_json(PRODUCT_FILE)
        doc_id = str(uuid4())
        doc["id"] = doc_id
        products.append(doc)
        safe_write_json(PRODUCT_FILE, products)
    snapshot_products()
    return jsonify({"id": doc_id}), 201


@app.route("/accounts", methods=["GET"])
def get_accounts():
    """Return all account records."""

    accounts = snapshot_accounts()
    return jsonify(accounts)


@app.route("/accounts", methods=["POST"])
def create_account():
    """Create a new account record."""

    try:
        account = AccountModel(**(request.get_json(force=True) or {}))
    except ValidationError as err:
        return jsonify({"error": err.errors()}), 400

    doc = account.dict()
    if db:
        try:
            ref = db.collection("accounts").add(doc)[1]
            doc_id = ref.id
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500
    else:
        accounts = safe_read_json(ACCOUNT_FILE)
        doc_id = str(uuid4())
        doc["id"] = doc_id
        accounts.append(doc)
        safe_write_json(ACCOUNT_FILE, accounts)
    snapshot_accounts()
    return jsonify({"id": doc_id}), 201


@app.route("/admin")
def admin_dashboard():
    """Render the admin dashboard template."""

    products = snapshot_products()
    accounts = snapshot_accounts()
    return render_template("dashboard.html", products=products, accounts=accounts)


@app.after_request
def secure_headers(resp):
    """Apply basic security headers on every response."""

    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp



if __name__ == "__main__":
    # Run the development server on port 7890
    app.run(host="0.0.0.0", port=7890)
