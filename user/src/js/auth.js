// ========= UTIL =========
// Convenience DOM query helpers
const $qs = (sel, el = document) => el.querySelector(sel);
const $$qs = (sel, el = document) => [...el.querySelectorAll(sel)];
// Display a toast notification
const toast = (msg) =>
  Toastify({ text: msg, gravity: 'bottom', position: 'right', duration: 2000, className: 'bg-dark text-white' }).showToast();
// Toggle between light and dark themes
function applyTheme(next) {
  const cur = document.documentElement.getAttribute('data-bs-theme') || 'dark';
  const t = next || (cur === 'light' ? 'dark' : 'light');
  document.documentElement.setAttribute('data-bs-theme', t);
  localStorage.setItem('nm_theme', t);
}

// Basic HTML escaper for safe innerHTML usage
const esc = (s) => {
  const d = document.createElement('div');
  d.textContent = String(s);
  return d.innerHTML;
};

// Same-origin so HttpOnly session cookie is sent automatically
const API_URL = `127.0.0.1:7890`

// Libraries
const validatorLib = import('https://cdn.jsdelivr.net/npm/validator@13.9.0/validator.esm.js');
const axiosLib = import('https://cdn.jsdelivr.net/npm/axios@1.11.0/+esm');

// Lightweight HTTP helper (uses axios ESM)
async function http(path, method = 'get', data) {
  const axios = (await axiosLib).default;
  const res = await axios({ url: API_URL + path, method, data });
  return res.data;
}

// ========= ACCOUNT STORAGE (UI only / localStorage) =========
const ACCOUNTS_KEY = 'nm_accounts';
const ACTIVE_EMAIL_KEY = 'nm_auth_email';
// Retrieve remembered accounts from localStorage
function getAccounts() {
  try {
    return JSON.parse(localStorage.getItem(ACCOUNTS_KEY) || '[]');
  } catch (e) {
    return [];
  }
}
// Persist up to five accounts to localStorage
function saveAccounts(list) {
  localStorage.setItem(ACCOUNTS_KEY, JSON.stringify(list.slice(0, 5)));
}
// Store the currently active email
function setActiveEmail(email) {
  if (email) localStorage.setItem(ACTIVE_EMAIL_KEY, email);
  else localStorage.removeItem(ACTIVE_EMAIL_KEY);
}
// Look up the active account object
function getActiveAccount() {
  const email = localStorage.getItem(ACTIVE_EMAIL_KEY);
  if (!email) return null;
  const acc = getAccounts().find((a) => a.email === email);
  return acc || { email, name: '', avatar: '' };
}
// Guess display name from email when none provided
function deriveNameFromEmail(em) {
  const local = (em || '').split('@')[0].replace(/[._-]+/g, ' ');
  return (
    local
      .split(' ')
      .map((s) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : ''))
      .join(' ')
      .trim() || 'Account'
  );
}
// Insert or update an account entry
function upsertAccount(obj) {
  const email = (obj.email || '').trim();
  if (!email) return;
  const list = getAccounts();
  const i = list.findIndex((a) => a.email === email);
  const entry = { email, name: obj.name || deriveNameFromEmail(email), avatar: obj.avatar || '' };
  if (i >= 0) list[i] = { ...list[i], ...entry };
  else list.unshift(entry);
  saveAccounts(list);
  setActiveEmail(email);
}

// ========= ROUTER =========
const routes = { '/login': renderLogin, '/register': renderRegister, '/forgot': renderForgot };
// Parse hash into path and query parameters
function parseHash() {
  const h = location.hash.replace(/^#/, '') || '/login';
  const [path, qs] = h.split('?');
  return { path, params: Object.fromEntries(new URLSearchParams(qs || '')) };
}
// Navigate to a new route
function route(path, params = {}) {
  const qs = new URLSearchParams(params).toString();
  location.hash = path + (qs ? `?${qs}` : '');
}
// Handle hash changes and render views
function onRoute() {
  const { path, params } = parseHash();
  $$qs('.view').forEach((v) => v.classList.remove('active'));
  const map = { '/login': 'view-login', '/register': 'view-register', '/forgot': 'view-forgot' };
  const id = map[path] || 'view-login';
  const view = document.getElementById(id);
  if (view) view.classList.add('active');
  (routes[path] || routes['/login'])(params);
}
window.addEventListener('hashchange', onRoute);

// ========= RENDERERS =========
// Render the login view
function renderLogin() {
  // Determine session state via a clear variable, as requested
  let savedSession = getActiveAccount(); // {email, name, avatar} | null
  const hasSession = !!savedSession;

  // Header visuals
  const avatar = $qs('#loginAvatar');
  const title = $qs('#loginTitle');
  const sub = $qs('#loginSubtitle');
  const idStrip = $qs('#loginIdentity');
  const emailBadge = $qs('#loginEmailBadge');
  const emailWrap = $qs('#loginEmailWrap');
  const diffBtn = $qs('#useDifferentBtn');
  const forgetBtn = $qs('#forgetDeviceBtn');

  if (hasSession) {
    const name = savedSession.name || deriveNameFromEmail(savedSession.email);
    title.textContent = `Welcome back, ${name}`;
    sub.textContent = 'Enter your password to continue';
    emailBadge.textContent = savedSession.email;
    idStrip.classList.remove('d-none');
    emailWrap.classList.add('d-none');
    // Avatar
    if (savedSession.avatar) {
      avatar.innerHTML = `<img alt="avatar" src="${savedSession.avatar}" style="width:100%;height:100%;object-fit:cover">`;
    } else {
      avatar.innerHTML = '<i class="bi bi-person fs-4"></i>';
    }
    // Build account chips if multiple remembered
    const chipsRow = $qs('#savedAccountsRow');
    const chips = $qs('#accountChips');
    const list = getAccounts();
    if (list.length > 1 && chips && chipsRow) {
      chipsRow.classList.remove('d-none');
      chips.innerHTML = list
        .map(
          (a) =>
            `<span class="acct-chip" data-email="${esc(a.email)}">${a.avatar ? `<img src="${esc(a.avatar)}" alt="">` : '<i class="bi bi-person"></i>'}<span class="small">${esc(a.email)}</span></span>`
        )
        .join('');
      $$qs('.acct-chip', chips).forEach((ch) => (ch.onclick = () => {
        setActiveEmail(ch.dataset.email);
        renderLogin();
      }));
    } else if (chipsRow) {
      chipsRow.classList.add('d-none');
    }
  } else {
    title.textContent = 'Welcome back';
    sub.textContent = 'Sign in to continue';
    idStrip.classList.add('d-none');
    emailWrap.classList.remove('d-none');
    avatar.innerHTML = '<i class="bi bi-person fs-4"></i>';
  }

  // Toggle to use another account (shows email input without destroying saved list)
  if (diffBtn) {
    diffBtn.onclick = () => {
      emailWrap.classList.toggle('d-none');
      if (!emailWrap.classList.contains('d-none')) {
        $qs('#loginEmail').focus();
      }
    };
  }

  // Forget this device (clears active email, keeps accounts list intact)
  if (forgetBtn) {
    forgetBtn.onclick = () => {
      setActiveEmail(null);
      toast('Device forgotten');
      renderLogin();
    };
  }

  // jQuery Validate if present
  if (window.jQuery && $.fn && $.fn.validate) {
    $('#loginForm').validate({
      rules: { loginEmail: { required: !hasSession, email: true }, loginPassword: { required: true, minlength: 8 } },
      messages: { loginEmail: 'Please enter your email' },
      errorClass: 'is-invalid',
      validClass: 'is-valid',
    });
  }

  // Submit handler
  const form = $qs('#loginForm');
  if (form) {
    form.onsubmit = async (e) => {
      e.preventDefault();
      if (window.jQuery && $.fn && $.fn.validate) {
        if (!$('#loginForm').valid()) {
          toast('Please fix the highlighted fields');
          return;
        }
      } else {
        if (!form.checkValidity()) {
          form.classList.add('was-validated');
          toast('Please fix the highlighted fields');
          return;
        }
        const emailInput = $qs('#loginEmail');
        const emailTest = emailInput?.value || '';
        if (!hasSession && !(await (await validatorLib).default.isEmail(emailTest))) {
          toast('Enter a valid email');
          return;
        }
      }

      const emailInput = $qs('#loginEmail');
      const email = hasSession ? savedSession.email : (emailInput?.value || '').trim();
      const password = $qs('#loginPassword')?.value || '';

      try {
        await http('/auth/login', 'post', { email, password });
        const remember = $qs('#rememberMe')?.checked;
        if (remember && email) upsertAccount({ email });
        setActiveEmail(email);
        toast(`Signed in as ${email}`);
        // route('/') // optionally redirect after login
      } catch (err) {
        toast(err?.message || 'Login failed');
      }
    };
  }
}

// Render the registration view
function renderRegister() {
  // Masks
  if (window.Inputmask) {
    Inputmask({ mask: '+9{6,15}' }).mask('#regPhone');
  }

  // Optional avatar pick -> DataURL
  let regAvatarDataUrl = '';
  const av = $qs('#regAvatar');
  if (av) {
    av.onchange = () => {
      const f = av.files?.[0];
      if (!f) return;
      if (!f.type || !f.type.startsWith('image/')) return toast('Please choose an image');
      if (f.size > 2 * 1024 * 1024) return toast('Image must be under 2MB');
      const reader = new FileReader();
      reader.onload = () => (regAvatarDataUrl = String(reader.result || ''));
      reader.readAsDataURL(f);
    };
  }

  // Password strength
  const pwd = $qs('#regPassword');
  const bar = $qs('#pwdStrengthBar');
  const txt = $qs('#pwdStrengthText');
  if (pwd && bar) {
    pwd.addEventListener('input', () => {
      const score = window.zxcvbn ? zxcvbn(pwd.value).score : 0;
      const pct = [5, 25, 50, 75, 100][score];
      bar.style.width = pct + '%';
      bar.className = score < 2 ? 'bg-danger' : score < 3 ? 'bg-warning' : 'bg-success';
      if (txt) txt.textContent = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong'][score];
    });
  }

  // Validate
  if (window.jQuery && $.fn && $.fn.validate) {
    $('#registerForm').validate({
      rules: {
        regFirstName: { required: true, minlength: 2 },
        regLastName: { required: true, minlength: 2 },
        regEmail: { required: true, email: true },
        regPhone: { required: false },
        regPassword: { required: true, minlength: 8 },
        regConfirm: { required: true, equalTo: '#regPassword' },
        regTerms: { required: true },
      },
      messages: { regTerms: 'Please accept the terms to continue.' },
      errorClass: 'is-invalid',
      validClass: 'is-valid',
    });
  }

  const form = $qs('#registerForm');
  if (form) {
    form.onsubmit = async (e) => {
      e.preventDefault();
      if (window.jQuery && $.fn && $.fn.validate) {
        if (!$('#registerForm').valid()) {
          toast('Please fix the highlighted fields');
          return;
        }
      } else {
        if (!form.checkValidity()) {
          form.classList.add('was-validated');
          toast('Please fix the highlighted fields');
          return;
        }
        if ($qs('#regPassword')?.value !== $qs('#regConfirm')?.value) {
          toast('Passwords do not match');
          return;
        }
        const emailTest = $qs('#regEmail')?.value?.trim() || '';
        if (!(await (await validatorLib).default.isEmail(emailTest))) {
          toast('Please enter a valid email');
          return;
        }
      }

      const first = $qs('#regFirstName')?.value?.trim() || '';
      const last = $qs('#regLastName')?.value?.trim() || '';
      const email = $qs('#regEmail')?.value?.trim() || '';
      const name = `${first} ${last}`.trim();
      const password = $qs('#regPassword')?.value || '';

      try {
        await http('/auth/register', 'post', { email, password, name });
        upsertAccount({ email, name, avatar: regAvatarDataUrl });
        toast('Account created');
        route('/login');
      } catch (err) {
        toast(err?.message || 'Registration failed');
      }
    };
  }
}

// Render the forgot-password view
function renderForgot() {
  if (window.jQuery && $.fn && $.fn.validate) {
    $('#forgotForm').validate({ rules: { fpEmail: { required: true, email: true } }, errorClass: 'is-invalid', validClass: 'is-valid' });
  }
  const form = $qs('#forgotForm');
  if (form) {
    form.onsubmit = async (e) => {
      e.preventDefault();
      if (window.jQuery && $.fn && $.fn.validate) {
        if (!$('#forgotForm').valid()) {
          toast('Enter a valid email');
          return;
        }
      } else {
        if (!form.checkValidity()) {
          form.classList.add('was-validated');
          toast('Enter a valid email');
          return;
        }
        const emailTest = $qs('#fpEmail')?.value?.trim() || '';
        if (!(await (await validatorLib).default.isEmail(emailTest))) {
          toast('Enter a valid email');
          return;
        }
      }
      // Optional: hook up to /auth/forgot later
      toast('Reset link sent');
      route('/login');
    };
  }
}

// ========= Common widgets =========
// Toggle password field visibility
function wirePasswordToggles() {
  $$qs('[data-toggle-pass]').forEach((btn) => {
    btn.onclick = () => {
      const sel = btn.getAttribute('data-toggle-pass');
      const input = sel && document.querySelector(sel);
      if (!input) return;
      const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
      input.setAttribute('type', type);
      btn.innerHTML = type === 'password' ? '<i class="bi bi-eye"></i>' : '<i class="bi bi-eye-slash"></i>';
    };
  });
}

// ========= Boot =========
// Initial boot sequence
async function boot() {
  const themeBtn = document.getElementById('themeBtn');
  if (themeBtn) themeBtn.onclick = () => applyTheme();
  const yearEl = document.getElementById('year');
  if (yearEl) {
    const { default: dayjs } = await import('https://cdn.jsdelivr.net/npm/dayjs@1/dayjs.min.js');
    yearEl.textContent = dayjs().year();
  }
  onRoute();
  if (!location.hash) route('/login');
  wirePasswordToggles();
}
window.addEventListener('DOMContentLoaded', boot);

// Global error notice for failed external scripts
window.addEventListener('error', (e) => {
  if (String(e.message).toLowerCase().includes('script error')) {
    toast('Some external libraries failed to load. The page will still work with basic validation.');
  }
});
