// Lazy-load Axios from a CDN
const axiosLib = import('https://cdn.jsdelivr.net/npm/axios@1.6.7/dist/axios.min.js');

// Construct API base URL using current host and port 7890
const API_URL = `${location.protocol}//${location.hostname}:7890`;

// Generic helper for making HTTP requests to the backend
async function apiFetch(path, options = {}) {
  try {
    const axios = (await axiosLib).default;
    const res = await axios({ url: `${API_URL}${path}`, ...options });
    return res.data;
  } catch (err) {
    const status = err.response?.status || err.message;
    throw new Error(`API request failed: ${status}`);
  }
}

// Fetch full product list
function getProducts() {
  return apiFetch('/products');
}

// Create a new product
function createProduct(product) {
  return apiFetch('/products', { method: 'post', data: product });
}

// Fetch all accounts
function getAccounts() {
  return apiFetch('/accounts');
}

// Create a new account
function createAccount(account) {
  return apiFetch('/accounts', { method: 'post', data: account });
}

// Expose helpers on the global object for dashboard scripts
window.AdminAPI = { getProducts, createProduct, getAccounts, createAccount };
