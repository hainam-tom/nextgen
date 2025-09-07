// static/admin-api.js
const axiosLib = import('https://cdn.jsdelivr.net/npm/axios@1.11.0/+esm');

// same-origin requests so cookies (session) are sent
const API_URL = window.location.origin;

async function apiFetch(path, options = {}) {
  try {
    const axios = (await axiosLib).default;
    const res = await axios({ url: `${API_URL}${path}`, ...options });
    return res.data;
  } catch (err) {
    const status = err.response?.status || '';
    const details = err.response?.data?.error || err.message;
    throw new Error(`API request failed: ${status} ${details}`.trim());
  }
}

// Public helpers
function getProducts() { return apiFetch('/products'); }
function getProduct(id) { return apiFetch(`/products/${id}`); }
function createProduct(product) { return apiFetch('/products', { method: 'post', data: product }); }
function updateProduct(id, product) { return apiFetch(`/products/${id}`, { method: 'put', data: product }); }
function deleteProduct(id) { return apiFetch(`/products/${id}`, { method: 'delete' }); }
function getAccounts() { return apiFetch('/accounts'); }
function getAccount(id) { return apiFetch(`/accounts/${id}`); }
function createAccount(account) { return apiFetch('/accounts', { method: 'post', data: account }); }
function updateAccount(id, account) { return apiFetch(`/accounts/${id}`, { method: 'put', data: account }); }
function deleteAccount(id) { return apiFetch(`/accounts/${id}`, { method: 'delete' }); }

window.AdminAPI = { getProducts, getProduct, createProduct, updateProduct, deleteProduct, getAccounts, getAccount, createAccount, updateAccount, deleteAccount };
