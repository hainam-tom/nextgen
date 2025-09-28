(function (global) {
  const CommonLib = global.CommonLib || {};

  const DEFAULT_BASES = ['https://127.0.0.1:7890', 'http://127.0.0.1:7890'];

  function safeLocalStorage() {
    try {
      if (typeof global.localStorage !== 'undefined') {
        const testKey = '__vendly_probe__';
        global.localStorage.setItem(testKey, '1');
        global.localStorage.removeItem(testKey);
        return global.localStorage;
      }
    } catch (err) {
      // Ignore; storage unavailable.
    }
    return null;
  }

  const storage = safeLocalStorage();

  function normaliseBase(raw) {
    if (!raw) return null;
    try {
      const baseUrl = new URL(raw, global.location ? global.location.origin : undefined);
      if (baseUrl.protocol !== 'http:' && baseUrl.protocol !== 'https:') {
        return null;
      }
      const port = baseUrl.port ? `:${baseUrl.port}` : '';
      return `${baseUrl.protocol}//${baseUrl.hostname}${port}`;
    } catch (err) {
      return null;
    }
  }

  function pushWithFallback(list, seen, raw) {
    const base = normaliseBase(raw);
    if (!base || seen.has(base)) return;
    seen.add(base);
    list.push(base);
    const fallback = base.startsWith('https://')
      ? `http://${base.slice('https://'.length)}`
      : `https://${base.slice('http://'.length)}`;
    if (!seen.has(fallback)) {
      seen.add(fallback);
      list.push(fallback);
    }
  }

  function domHints() {
    if (typeof document === 'undefined') return [];
    const hints = [];
    const meta = document.querySelector('meta[name="vendly-api-base"]');
    if (meta && meta.content) hints.push(meta.content);
    const docBase = document.documentElement && document.documentElement.getAttribute('data-api-base');
    if (docBase) hints.push(docBase);
    const bodyBase = document.body && document.body.dataset ? document.body.dataset.apiBase : null;
    if (bodyBase) hints.push(bodyBase);
    const apiPort =
      (document.documentElement && document.documentElement.getAttribute('data-api-port')) ||
      (document.body && document.body.dataset ? document.body.dataset.apiPort : null);
    if (apiPort) {
      const port = String(apiPort).trim();
      if (port) {
        try {
          const proto = global.location && global.location.protocol === 'http:' ? 'http://' : 'https://';
          const host = (global.location && global.location.hostname) || '127.0.0.1';
          hints.push(`${proto}${host}:${port}`);
        } catch (err) {
          // ignore
        }
      }
    }
    return hints;
  }

  function runtimeHints() {
    const hints = [];
    if (global.NEXTGEN_API_BASE) hints.push(global.NEXTGEN_API_BASE);
    if (Array.isArray(global.NEXTGEN_API_BASES)) {
      global.NEXTGEN_API_BASES.forEach((hint) => hints.push(hint));
    }
    if (global.location && (global.location.protocol === 'http:' || global.location.protocol === 'https:')) {
      const { protocol, hostname, port } = global.location;
      const suffix = port ? `:${port}` : '';
      hints.push(`${protocol}//${hostname || '127.0.0.1'}${suffix}`);
    }
    return hints;
  }

  function loadStickyBase(key) {
    if (!storage || !key) return null;
    try {
      return storage.getItem(key);
    } catch (err) {
      return null;
    }
  }

  function saveStickyBase(key, base) {
    if (!storage || !key || !base) return;
    try {
      storage.setItem(key, base);
    } catch (err) {
      // ignore storage failures
    }
  }

  function discoverApiBases({ hints = [], stickyKey, includeDefaults = true } = {}) {
    const bases = [];
    const seen = new Set();

    const sticky = loadStickyBase(stickyKey);
    if (sticky) pushWithFallback(bases, seen, sticky);

    [...hints, ...domHints(), ...runtimeHints()].forEach((hint) => pushWithFallback(bases, seen, hint));

    if (includeDefaults) {
      DEFAULT_BASES.forEach((hint) => pushWithFallback(bases, seen, hint));
    }

    return bases;
  }

  function buildApiUrl(base, path = '/') {
    const cleanBase = (base || '').replace(/\/$/, '');
    const suffix = path.startsWith('/') ? path : `/${path}`;
    return `${cleanBase}${suffix}`;
  }

  function normaliseOptions({ method = 'GET', body, headers } = {}) {
    const options = {
      method: method.toUpperCase(),
      headers: { Accept: 'application/json', ...(headers || {}) },
    };

    if (body !== undefined && body !== null) {
      options.headers['Content-Type'] = 'application/json';
      options.body = typeof body === 'string' ? body : JSON.stringify(body);
    }

    return options;
  }

  async function fetchWithFetch(url, options) {
    try {
      const response = await global.fetch(url, { ...options, credentials: 'include' });
      const text = await response.text();
      return parsePayload(response.status, response.statusText, text);
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
        const { status, statusText } = xhr;
        const text = xhr.responseText;
        try {
          resolve(parsePayload(status, statusText, text));
        } catch (err) {
          reject(err);
        }
      };
      xhr.onerror = function () {
        const networkError = new Error('Network error while contacting the API');
        networkError.code = 'NETWORK';
        reject(networkError);
      };
      xhr.send(options.body || null);
    });
  }

  function parsePayload(status, statusText, text) {
    if (!text) {
      if (status >= 200 && status < 300) {
        return null;
      }
      throw new Error(`Request failed (${status}): ${statusText || 'Unknown error'}`);
    }

    let payload;
    try {
      payload = JSON.parse(text);
    } catch (err) {
      throw new Error('API returned invalid JSON');
    }

    if (status >= 200 && status < 300) {
      return payload;
    }

    const detail = (payload && (payload.error || payload.message)) || statusText || 'Request failed';
    throw new Error(`Request failed (${status}): ${detail}`);
  }

  function createHttpClient({ hints = [], stickyKey = null, resource = 'API' } = {}) {
    let candidates = discoverApiBases({ hints, stickyKey });
    const dispatcher = typeof global.fetch === 'function' ? fetchWithFetch : fetchWithXhr;

    async function request(path, { method = 'GET', body, headers } = {}) {
      const options = normaliseOptions({ method, body, headers });
      const errors = [];

      for (const base of candidates) {
        const url = buildApiUrl(base, path);
        try {
          const result = await dispatcher(url, options);
          saveStickyBase(stickyKey, base);
          return result;
        } catch (err) {
          if (!err || err.code !== 'NETWORK') {
            throw err;
          }
          errors.push(`${base}: ${err.message}`);
        }
      }

      const detail = errors.length ? errors.join('\n') : candidates.join('\n');
      const aggregate = new Error(`All ${resource} endpoints are unreachable. Tried:\n${detail}`);
      aggregate.code = 'NETWORK';
      throw aggregate;
    }

    function refresh(newHints = []) {
      candidates = discoverApiBases({ hints: [...hints, ...newHints], stickyKey });
      return candidates.slice();
    }

    return {
      request,
      getBases: () => candidates.slice(),
      refreshBases: refresh,
    };
  }

  CommonLib.createHttpClient = createHttpClient;
  CommonLib.discoverApiBases = discoverApiBases;
  CommonLib.buildApiUrl = buildApiUrl;

  global.CommonLib = CommonLib;
})(typeof window !== 'undefined' ? window : this);
