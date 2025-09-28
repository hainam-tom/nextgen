// Lightweight Admin API helper that relies on browser-native primitives only.
// No Node.js tooling is required; fetch is used when available with an XHR
// fallback for older browsers.

(function () {
  const DEFAULT_BASE = 'https://127.0.0.1:7890';

  function resolveApiBase() {
    try {
      const { protocol, hostname } = window.location;
      const safeProtocol = protocol === 'http:' || protocol === 'https:' ? protocol : 'https:';
      const host = hostname && hostname !== '' ? hostname : '127.0.0.1';
      return `${safeProtocol}//${host}:7890`;
    } catch (err) {
      console.warn('Falling back to default API base:', err);
      return DEFAULT_BASE;
    }
  }

  const API_BASE = resolveApiBase().replace(/\/$/, '');

  function buildUrl(path) {
    const suffix = path.startsWith('/') ? path : `/${path}`;
    return `${API_BASE}${suffix}`;
  }

  function normaliseOptions(options) {
    const opts = { method: 'GET', headers: { Accept: 'application/json' }, ...options };
    if (opts.body !== undefined && opts.body !== null) {
      opts.headers = { 'Content-Type': 'application/json', ...opts.headers };
      if (typeof opts.body !== 'string') {
        opts.body = JSON.stringify(opts.body);
      }
    } else {
      delete opts.body;
    }
    return opts;
  }

  async function parseJsonResponse(status, statusText, text) {
    if (!text) {
      if (status >= 200 && status < 300) {
        return null;
      }
      throw new Error(`API request failed (${status}): ${statusText || 'Unknown error'}`);
    }

    let payload = null;
    try {
      payload = JSON.parse(text);
    } catch (err) {
      throw new Error(`Failed to parse server response (${status})`);
    }

    if (status >= 200 && status < 300) {
      return payload;
    }

    const detail =
      (payload && (payload.error || payload.message)) ||
      statusText ||
      'Request failed';
    throw new Error(`API request failed (${status}): ${detail}`);
  }

  async function fetchWithFetch(url, options) {
    try {
      const response = await fetch(url, { ...options, credentials: 'include' });
      const text = await response.text();
      return parseJsonResponse(response.status, response.statusText, text);
    } catch (err) {
      if (err instanceof TypeError) {
        throw new Error('Network error while contacting the API');
      }
      throw err;
    }
  }

  function fetchWithXhr(url, options) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open(options.method || 'GET', url, true);
      xhr.withCredentials = true;
      Object.entries(options.headers || {}).forEach(([key, value]) => {
        xhr.setRequestHeader(key, value);
      });
      xhr.onload = function () {
        parseJsonResponse(xhr.status, xhr.statusText, xhr.responseText)
          .then(resolve)
          .catch(reject);
      };
      xhr.onerror = function () {
        reject(new Error('Network error while contacting the API'));
      };
      xhr.send(options.body || null);
    });
  }

  function request(path, { method = 'GET', body, headers } = {}) {
    const url = buildUrl(path);
    const options = normaliseOptions({ method: method.toUpperCase(), body, headers });
    if (typeof window.fetch === 'function') {
      return fetchWithFetch(url, options);
    }
    return fetchWithXhr(url, options);
  }

  const AdminAPI = {
    getProducts: () => request('/products'),
    getProduct: (id) => request(`/products/${encodeURIComponent(id)}`),
    createProduct: (product) => request('/products', { method: 'POST', body: product }),
    updateProduct: (id, product) => request(`/products/${encodeURIComponent(id)}`, { method: 'PUT', body: product }),
    deleteProduct: (id) => request(`/products/${encodeURIComponent(id)}`, { method: 'DELETE' }),
    getAccounts: () => request('/accounts'),
    getAccount: (id) => request(`/accounts/${encodeURIComponent(id)}`),
    createAccount: (account) => request('/accounts', { method: 'POST', body: account }),
    updateAccount: (id, account) => request(`/accounts/${encodeURIComponent(id)}`, { method: 'PUT', body: account }),
    deleteAccount: (id) => request(`/accounts/${encodeURIComponent(id)}`, { method: 'DELETE' }),
    getAccountProfile: (id) => request(`/accounts/${encodeURIComponent(id)}/profile`),
    updateAccountProfile: (id, profile) => request(`/accounts/${encodeURIComponent(id)}/profile`, { method: 'PUT', body: profile }),
    getAccountBanking: (id) => request(`/accounts/${encodeURIComponent(id)}/banking`),
    updateAccountBanking: (id, banking) => request(`/accounts/${encodeURIComponent(id)}/banking`, { method: 'PUT', body: banking }),
  };

  window.AdminAPI = AdminAPI;
})();
