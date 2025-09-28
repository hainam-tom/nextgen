# NextGen Marketplace

## Backend
- Flask app in `admin/app.py` manages products and accounts and delegates shared
  behaviour to the new `commonlib/` helpers so installers and tests share one
  source of truth.
- Products are stored locally in `admin/products.json` with automatic backup
  rotation via `commonlib.storage.JsonStore`.
- Accounts keep human-readable profile details in `admin/accounts.json` while
  sensitive banking details are encrypted in `admin/banking.json.enc` using
  Fernet keys that persist to `admin/.fernet.key`.
- Firebase Admin SDK is still used for administrative identity and is wired
  through `commonlib.firebase.load_service_account` for reliable setup.

## Frontend
- Storefront lives under `user/` and loads products from the API.
- Shopping cart uses a DataTable for sortable items.
- Admin dashboard served from `/admin` uses Bootstrap 5 and DataTables for full CRUD.

Run `pip install -r admin/requirements.txt` then `python admin/app.py` to start the service.
The first start generates a Fernet key in `admin/.fernet.key` unless
`BANK_ENCRYPTION_KEY`/`FERNET_KEY` is provided.

### Testing

- Execute `pytest` from the repository root to validate the storage redundancy
  helpers, encrypted store round-trips, and Firebase credential discovery.
