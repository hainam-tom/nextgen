# NextGen Marketplace

## Backend
- Flask API in `admin/api.py` authenticates with Firebase via `firebase-auth.json`.
- Mirrors Firestore data into `admin/products.json` and `admin/accounts.json` when available.

## Frontend
- Browser-ready storefront lives under `user/` and loads products from `http://<host>:7890`.
- Admin dashboard served from `/admin` to manage products and accounts.

Run `pip install -r admin/requirements.txt` then `python admin/api.py` to start the service.
