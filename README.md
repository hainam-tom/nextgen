# NextGen Marketplace

## Backend
- Flask app in `admin/app.py` manages products and accounts.
- Products are stored locally in `admin/products.json`.
- Accounts are managed through the Firebase Admin SDK (no client-side Firebase).
- Shared persistence/origin helpers live in `commonlib/` and are consumed by both the backend and browser clients to avoid duplication.

## Frontend
- The shopper experience is rendered with Flask templates in `admin/templates/storefront/`, so catalog browsing, carts, and checkout forms work without JavaScript API calls.
- Account management posts directly back to the Flask routes, reusing the same validation models as the API to avoid divergent logic.
- The admin dashboard at `/admin` now uses server-rendered forms under `admin/templates/admin/`, removing the previous JavaScript client and keeping inventory edits on the backend.

### Quick start

- **Linux (bash):** `./scripts/install.sh`
- **macOS:** `./scripts/install_macos.sh`
- **Zsh environments:** `./scripts/install.zsh`
- **Windows PowerShell:** `pwsh scripts/install.ps1`

Each installer now guides you through selecting the API port and fallback technician host, wiring optional domains (with Cloudflare DNS and Let's Encrypt certificate automation), checking public port reachability via ifconfig.co, and writing `admin/.env` before provisioning a Python virtual environment.

Populate `scripts/.env` to preseed those installers with defaults (for example `INSTALL_REPO_URL`, `LETS_ENCRYPT_EMAIL`, `PUBLIC_DOMAIN`, or Cloudflare credentials) when automating repeated deployments.

### Domain & HTTPS

- Supply your domain during installation to have the scripts derive `PUBLIC_BASE_URL`, update `ALLOWED_ORIGINS`, and (optionally) request Cloudflare DNS A records via API tokens.
- If Let's Encrypt is chosen and `certbot` is available, certificates are requested automatically; otherwise, the installer captures existing certificate paths so Flask can serve them.
- Skipping certificates keeps Flask on its adhoc self-signed TLS (or HTTP) so you can revisit the installer once production certificates are ready.

### Manual setup

If you prefer the manual path:

1. `pip install -r admin/requirements.txt`
2. `python -m admin.app`

Environment variables of note:

- `API_PORT` / `API_HOST` – listening address and port (defaults to `0.0.0.0:7890`).
- `PUBLIC_PORT` – external port exposed to browsers (defaults to the API port).
- `FORCE_TLS` – set to `0` to serve over HTTP.
- `PUBLIC_BASE_URL` – external origin used by the admin dashboard and storefront scripts.
- `PUBLIC_DOMAIN` – canonical domain name used for generated links and security headers.
- `PUBLIC_FALLBACK_HOST` – technician/local hostname retained for direct connections.
- `TLS_CERT_FILE` / `TLS_KEY_FILE` – optional absolute paths to production TLS assets served by Flask.
- `LETS_ENCRYPT_EMAIL` – stored contact for certificate renewal reminders.
- `ACCOUNT_ENCRYPTION_SECRET` – base secret used to derive the daily encryption key for shopper accounts.
- `REVIEW_SECRET_KEY` / `BANKING_SECRET_KEY` – optional overrides for encrypting product feedback and stored payment details.
- `PRODUCT_BACKUPS` – number of rotating backups preserved for JSON stores (default `3`).

### Customise each storefront quickly

- Edit `admin/site.json` to update the shop name, hero copy, and call-to-action buttons without touching templates.
- Replace or expand the sample catalog in `admin/products.json`; each entry includes placeholder lorem descriptions and prices from $1–$10.
- Shopper reviews and saved accounts are encrypted locally using a rotating daily key, so each vendor’s data stays isolated even when self-hosted.
