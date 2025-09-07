# NextGen Marketplace

## Backend
- Flask app in `admin/app.py` manages products and accounts.
- Products are stored locally in `admin/products.json`.
- Accounts are managed through the Firebase Admin SDK (no client-side Firebase).

## Frontend
- Storefront lives under `user/` and loads products from the API.
- Shopping cart uses a DataTable for sortable items.
- Admin dashboard served from `/admin` uses Bootstrap 5 and DataTables for full CRUD.

Run `pip install -r admin/requirements.txt` then `python admin/app.py` to start the service.
