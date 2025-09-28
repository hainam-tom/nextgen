// Lightweight Admin API helper built on top of the shared CommonLib client.
// Ensures the dashboard and storefront reuse the same networking logic and
// redundancy strategy.

(function () {
  const lib = window.CommonLib;
  if (!lib || typeof lib.createHttpClient !== 'function') {
    throw new Error('CommonLib.createHttpClient is required before loading adminAPI.js');
  }

  const client = lib.createHttpClient({
    stickyKey: 'vendly_admin_api_base',
    resource: 'admin API',
  });

  const request = client.request;

  function encodeId(id) {
    return encodeURIComponent(id);
  }

  const AdminAPI = {
    getProducts: () => request('/products'),
    getProduct: (id) => request(`/products/${encodeId(id)}`),
    createProduct: (product) => request('/products', { method: 'POST', body: product }),
    updateProduct: (id, product) => request(`/products/${encodeId(id)}`, { method: 'PUT', body: product }),
    deleteProduct: (id) => request(`/products/${encodeId(id)}`, { method: 'DELETE' }),
    getAccounts: () => request('/accounts'),
    getAccount: (id) => request(`/accounts/${encodeId(id)}`),
    createAccount: (account) => request('/accounts', { method: 'POST', body: account }),
    updateAccount: (id, account) => request(`/accounts/${encodeId(id)}`, { method: 'PUT', body: account }),
    deleteAccount: (id) => request(`/accounts/${encodeId(id)}`, { method: 'DELETE' }),
    getAccountProfile: (id) => request(`/accounts/${encodeId(id)}/profile`),
    updateAccountProfile: (id, profile) => request(`/accounts/${encodeId(id)}/profile`, { method: 'PUT', body: profile }),
    getAccountBanking: (id) => request(`/accounts/${encodeId(id)}/banking`),
    updateAccountBanking: (id, banking) => request(`/accounts/${encodeId(id)}/banking`, { method: 'PUT', body: banking }),
  };

  window.AdminAPI = AdminAPI;
})();
