// Vendly admin helper without external runtime dependencies.
const API_HOST = '127.0.0.1:7890';

function buildUrl(path) {
  const base = API_HOST.includes('://')
    ? API_HOST
    : `${window.location.protocol}//${API_HOST}`;
  return `${base}${path}`;
}

function toError(response, bodyText) {
  const status = response.status || '';
  const reason = bodyText || response.statusText || 'Request failed';
  return new Error(`API request failed: ${status} ${reason}`.trim());
}

async function apiFetch(path, options = {}) {
  const { method = 'GET', data, headers = {} } = options;
  const url = buildUrl(path);

  const payload = data !== undefined ? JSON.stringify(data) : undefined;
  const commonHeaders = payload
    ? { 'Content-Type': 'application/json', ...headers }
    : headers;

  if (window.fetch) {
    const response = await fetch(url, {
      method,
      body: payload,
      credentials: 'include',
      headers: commonHeaders,
    });
    if (!response.ok) {
      const text = await response.text();
      throw toError(response, text);
    }
    return response.status === 204 ? null : response.json();
  }

  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open(method, url, true);
    xhr.withCredentials = true;
    Object.entries(commonHeaders).forEach(([key, value]) => {
      xhr.setRequestHeader(key, value);
    });

    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        if (!xhr.responseText) {
          resolve(null);
          return;
        }
        try {
          resolve(JSON.parse(xhr.responseText));
        } catch (err) {
          reject(err);
        }
      } else {
        reject(toError(xhr, xhr.responseText));
      }
    };

    xhr.onerror = () => reject(toError(xhr));
    xhr.send(payload);
  });
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
function getAccountProfile(id) { return apiFetch(`/accounts/${id}/profile`); }
function updateAccountProfile(id, profile) {
  return apiFetch(`/accounts/${id}/profile`, { method: 'put', data: profile });
}
function getAccountBanking(id) { return apiFetch(`/accounts/${id}/banking`); }
function updateAccountBanking(id, data) {
  return apiFetch(`/accounts/${id}/banking`, { method: 'put', data });
}
function deleteAccountBanking(id) {
  return apiFetch(`/accounts/${id}/banking`, { method: 'delete' });
}

window.AdminAPI = {
  getProducts,
  getProduct,
  createProduct,
  updateProduct,
  deleteProduct,
  getAccounts,
  getAccount,
  createAccount,
  updateAccount,
  deleteAccount,
  getAccountProfile,
  updateAccountProfile,
  getAccountBanking,
  updateAccountBanking,
  deleteAccountBanking,
};
