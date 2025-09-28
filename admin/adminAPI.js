// Lightweight Admin API helper that relies on browser-native primitives only.
// No Node.js tooling is required; fetch is used when available with an XHR
// fallback for older browsers.

(function () {
  const DEFAULT_BASES = ['https://127.0.0.1:7890', 'http://127.0.0.1:7890'];

  function normaliseBase(raw) {
    if (!raw) return null;
    try {
      const baseUrl = new URL(raw, window.location.origin);
      if (baseUrl.protocol !== 'http:' && baseUrl.protocol !== 'https:') {
        return null;
      }
      const port = baseUrl.port ? `:${baseUrl.port}` : '';
      return `${baseUrl.protocol}//${baseUrl.hostname}${port}`;
    } catch (err) {
      return null;
    }
  }

  function collectApiBases() {
    const seen = new Set();
    const bases = [];

    const push = (raw) => {
      const base = normaliseBase(raw);
      if (!base || seen.has(base)) return;
      seen.add(base);
      bases.push(base);
      const fallback = base.startsWith('https://')
        ? `http://${base.slice('https://'.length)}`
        : `https://${base.slice('http://'.length)}`;
      if (!seen.has(fallback)) {
        seen.add(fallback);
        bases.push(fallback);
      }
    };

    const meta = document.querySelector('meta[name="vendly-api-base"]');
    if (meta && meta.content) push(meta.content);

    const docBase = document.documentElement.getAttribute('data-api-base');
    if (docBase) push(docBase);

    const bodyBase = document.body && document.body.dataset ? document.body.dataset.apiBase : null;
    if (bodyBase) push(bodyBase);

    if (window.NEXTGEN_API_BASE) push(window.NEXTGEN_API_BASE);
    if (Array.isArray(window.NEXTGEN_API_BASES)) {
      window.NEXTGEN_API_BASES.forEach(push);
    }

    const dataPort =
      document.documentElement.getAttribute('data-api-port') ||
      (document.body && document.body.dataset ? document.body.dataset.apiPort : null);
    if (dataPort) {
      const port = String(dataPort).trim();
      if (port) {
        try {
          const { protocol, hostname } = window.location;
          const proto = protocol === 'http:' ? 'http:' : 'https:';
          const host = hostname && hostname !== '' ? hostname : '127.0.0.1';
          push(`${proto}//${host}:${port}`);
        } catch (err) {
          console.warn('Unable to derive API host for custom port', err);
        }
      }
    }

    try {
      const { protocol, hostname, port } = window.location;
      if (protocol === 'http:' || protocol === 'https:') {
        const host = hostname && hostname !== '' ? hostname : '127.0.0.1';
        const suffix = port ? `:${port}` : '';
        push(`${protocol}//${host}${suffix}`);
      }
    } catch (err) {
      console.warn('Failed to derive API base from location:', err);
    }

    DEFAULT_BASES.forEach(push);
    return bases;
  }

  const API_BASES = collectApiBases();

  function buildUrl(base, path) {
    const suffix = path.startsWith('/') ? path : `/${path}`;
    return `${base.replace(/\/$/, '')}${suffix}`;
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
        const networkError = new Error('Network error while contacting the API');
        networkError.code = 'NETWORK';
        throw networkError;
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
        const networkError = new Error('Network error while contacting the API');
        networkError.code = 'NETWORK';
        reject(networkError);
      };
      xhr.send(options.body || null);
    });
  }

  async function request(path, { method = 'GET', body, headers } = {}) {
    const baseOptions = normaliseOptions({ method: method.toUpperCase(), body, headers });
    const dispatcher = typeof window.fetch === 'function' ? fetchWithFetch : fetchWithXhr;
    const errors = [];

    for (const base of API_BASES) {
      const url = buildUrl(base, path);
      const opts = { ...baseOptions, headers: { ...baseOptions.headers } };
      try {
        return await dispatcher(url, opts);
      } catch (err) {
        if (!err || err.code !== 'NETWORK') {
          throw err;
        }
        errors.push(`${base}: ${err.message}`);
        console.warn(`Admin API network error for ${base}; trying fallback`, err);
      }
    }

    const detail = errors.length ? errors.join('\n') : API_BASES.join('\n');
    const aggregate = new Error(`All admin API endpoints are unreachable. Tried:\n${detail}`);
    aggregate.code = 'NETWORK';
    throw aggregate;
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
