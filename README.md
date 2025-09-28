# NextGen Marketplace

## Backend
- Flask app in `admin/app.py` manages products and accounts.
- Products are stored locally in `admin/products.json`.
- Accounts are managed through the Firebase Admin SDK (no client-side Firebase).

## Frontend
- Storefront lives under `user/` and loads products from the API.
- Shopping cart uses a DataTable for sortable items.
- Admin dashboard served from `/admin` uses Bootstrap 5 and DataTables for full CRUD.

### Quick start

- **Linux (bash):** `./scripts/install.sh`
- **macOS:** `./scripts/install_macos.sh`
- **Zsh environments:** `./scripts/install.zsh`
- **Windows PowerShell:** `pwsh scripts/install.ps1`

Each installer guides you through selecting the API port, configures HTTPS or HTTP, checks public port reachability using ifconfig.co, writes `admin/.env`, and provisions a Python virtual environment.

### Manual setup

If you prefer the manual path:

1. `pip install -r admin/requirements.txt`
2. `python -m admin.app`

Environment variables of note:

- `API_PORT` / `API_HOST` – listening address and port (defaults to `0.0.0.0:7890`).
- `FORCE_TLS` – set to `0` to serve over HTTP.
- `PUBLIC_BASE_URL` – external origin used by the admin dashboard and storefront scripts.
- `PRODUCT_BACKUPS` – number of rotating backups preserved for JSON stores (default `3`).
