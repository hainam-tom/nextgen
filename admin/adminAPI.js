// static/admin-api.js
const axiosLib = import('https://cdn.jsdelivr.net/npm/axios@1.11.0/+esm');

// same-origin requests so cookies (session) are sent
const API_URL = 'https://localhost:7890';

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
function createProduct(product) { return apiFetch('/products', { method: 'post', data: product }); }
function getAccounts() { return apiFetch('/accounts'); }
function createAccount(account) { return apiFetch('/accounts', { method: 'post', data: account }); }

window.AdminAPI = { getProducts, createProduct, getAccounts, createAccount };
