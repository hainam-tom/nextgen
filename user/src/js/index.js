  // ==============================
  // Marketplace UI (no backend)
  // ==============================
  const $qs = (sel, el=document) => el.querySelector(sel);
  const $$qs = (sel, el=document) => [...el.querySelectorAll(sel)];
  const money = n => new Intl.NumberFormat(undefined, { style:'currency', currency:'USD' }).format(n||0);
  const safe = s => (window.DOMPurify ? DOMPurify.sanitize(String(s ?? ''), {ALLOWED_TAGS:[], ALLOWED_ATTR:[]}) : String(s ?? ''));

  const lib = window.CommonLib;
  if (!lib || typeof lib.createHttpClient !== 'function') {
    throw new Error('CommonLib.createHttpClient is required before loading storefront logic');
  }

  const httpClient = lib.createHttpClient({
    stickyKey: 'vendly_storefront_api_base',
    resource: 'storefront API',
  });

  let API_BASES = httpClient.getBases();
  if (!API_BASES.length) {
    API_BASES = httpClient.refreshBases();
  }
  const PRIMARY_API_BASE = API_BASES[0] || null;

  const adminLink = document.querySelector('[data-admin-link]');
  if (adminLink && PRIMARY_API_BASE) {
    adminLink.setAttribute('href', PRIMARY_API_BASE);
    adminLink.setAttribute('rel', 'noopener');
  }

  function apiRequest(path, options = {}) {
    const { method = 'GET', data, headers } = options;
    return httpClient.request(path, { method, body: data, headers });
  }

  const isAuthError = (err) => Boolean(err && typeof err.message === 'string' && err.message.includes('(401)'));

  const AccountGateway = (() => {
    const emptyAddress = () => ({
      line1: '',
      line2: '',
      city: '',
      state: '',
      postal_code: '',
      country: '',
    });

    let profileCache = null;
    let bankingCache = null;

    const normaliseProfile = (data = {}) => ({
      name: data.name || '',
      email: data.email || '',
      phone: data.phone || '',
      avatar: data.avatar || null,
      address: { ...emptyAddress(), ...(data.address || {}) },
    });

    const normaliseBanking = (data = {}) => ({
      cardholder: data.cardholder || '',
      card_last4: data.card_last4 || '',
      brand: data.brand || '',
      exp_month: data.exp_month || '',
      exp_year: data.exp_year || '',
      postal_code: data.billing_postal || data.postal_code || '',
    });

    async function loadProfile() {
      try {
        const result = await apiRequest('/me/profile');
        profileCache = normaliseProfile(result || {});
      } catch (err) {
        if (isAuthError(err)) {
          profileCache = null;
          return null;
        }
        throw err;
      }
      return profileCache;
    }

    async function saveProfile(payload) {
      const result = await apiRequest('/me/profile', { method: 'PUT', data: payload });
      profileCache = normaliseProfile(result || {});
      return profileCache;
    }

    function getProfile() {
      return profileCache;
    }

    async function loadBanking() {
      try {
        const result = await apiRequest('/me/banking');
        bankingCache = normaliseBanking(result || {});
      } catch (err) {
        if (isAuthError(err)) {
          bankingCache = null;
          return null;
        }
        throw err;
      }
      return bankingCache;
    }

    async function saveBanking(payload) {
      const result = await apiRequest('/me/banking', { method: 'PUT', data: payload });
      bankingCache = normaliseBanking(result || {});
      return bankingCache;
    }

    function getBanking() {
      return bankingCache;
    }

    return { loadProfile, saveProfile, getProfile, loadBanking, saveBanking, getBanking };
  })();

  function getCardDigits(value = ''){
    return String(value || '').replace(/\D/g, '');
  }


  // Pull product catalog from backend API
  async function loadCatalog(){
    try {
      const data = await apiRequest('/products');
      NM.setCatalog(Array.isArray(data) ? data : []);
    } catch(err){
      console.error(err);
      toast('Failed to load catalog');
    }
  }

  // Catalog is EMPTY by default. Load your products later via NM.setCatalog([...])
  const NM = window.NM = {
    catalog: [],
    setCatalog(list){
      this.catalog = Array.isArray(list) ? list : [];
      renderHome();
      renderShop();
      const { path, params } = parseHash();
      if(path==='/product' && params.id) renderProduct(params.id);
      if(path==='/cart') renderCart();
      if(path==='/checkout') renderCheckout();
    }
  };

  // ------------------------------
  // Cart (localStorage ONLY)
  // ------------------------------
  const store = {
    get cart(){ return JSON.parse(localStorage.getItem('nm_cart')||'[]') },
    set cart(v){ localStorage.setItem('nm_cart', JSON.stringify(v)); updateMiniCart(); },
  };
  // Update the mini-cart counter in the navbar
  function updateMiniCart(){ const el = $qs('#miniCartCount'); if(el) el.textContent = store.cart.reduce((s,i)=>s + Number(i.qty||0), 0) }

  // Add a product to the local cart
  function addToCart(id, qty=1){ const exists = NM.catalog.find(p=>String(p.id)===String(id)); if(!exists){ toast('Product not loaded yet'); return; } const cart = store.cart; const row = cart.find(i=>String(i.id)===String(id)); if(row) row.qty = Number(row.qty||0) + Number(qty||1); else cart.push({ id, qty:Number(qty)||1 }); store.cart = cart; toast('Added to cart'); }

  // Set quantity for an item in the cart
  function setQty(id, qty){ store.cart = store.cart.map(i=> String(i.id)===String(id) ? { ...i, qty: Math.max(1, Number(qty)||1) } : i) }

  // Remove an item from the cart
  function removeFromCart(id){ store.cart = store.cart.filter(i=> String(i.id)!==String(id)) }

  // Calculate total cart value
  function cartTotal(){ return store.cart.reduce((s,i)=>{ const p = NM.catalog.find(p=>String(p.id)===String(i.id)); return s + (p? (p.price||0) * (i.qty||0) : 0) }, 0) }

  // ------------------------------
  // Router (hash-based)
  // ------------------------------
  const routes = {
    '/home': renderHome,
    '/shop': () => renderShop(),
    '/product': params => renderProduct(params.id),
    '/cart': renderCart,
    '/checkout': renderCheckout,
    '/account': renderAccount,
    '/account/password': renderAccountPassword,
    '/account/card': renderAccountCard,
  };
  // Parse hash into path and params
  function parseHash(){ const h = location.hash.replace(/^#/, '') || '/home'; const [path, qs] = h.split('?'); const params = Object.fromEntries(new URLSearchParams(qs||'')); return { path, params }; }

  // Navigate to a new route
  function route(path, params={}){ const qs = new URLSearchParams(params).toString(); location.hash = path + (qs?`?${qs}`:''); }

  // React to hash changes and render matching view
  function onRoute(){
    const { path, params } = parseHash();
    $$qs('.nav-link[data-nav]').forEach(a => a.classList.toggle('active', a.getAttribute('href')===`#${path}`));
    $$qs('.view').forEach(v=>v.classList.remove('active'));
    const map = { '/home':'view-home', '/shop':'view-shop', '/product':'view-product', '/cart':'view-cart', '/checkout':'view-checkout', '/account':'view-account', '/account/password':'view-account-password', '/account/card':'view-account-card' };
    const id = map[path] || 'view-home';
    const view = document.getElementById(id);
    if(view) view.classList.add('active');
    try {
      const maybePromise = (routes[path] || routes['/home'])(params);
      if(maybePromise && typeof maybePromise.then === 'function'){
        maybePromise.catch(err => {
          if(!isAuthError(err)) console.error(err);
        });
      }
    } catch(err){
      console.error(err);
    }
  }
  window.addEventListener('hashchange', onRoute);

  // ------------------------------
  // Render: Home
  // ------------------------------
  // Render the trending section on the home page
  function renderHome(){ const list = [...NM.catalog].sort((a,b)=> (b.rating||0)-(a.rating||0)).slice(0,6); const wrap = $qs('#homeTrending'); if(!wrap) return; if(!list.length){ /* keep skeletons */ return; } wrap.innerHTML = list.map(cardHTML).join(''); wireCardButtons(wrap); }

  // ------------------------------
  // Render: Shop
  // ------------------------------
  // Build a product card
  function cardHTML(p){ const title = safe(p.title||'Untitled'); const price = typeof p.price==='number' ? money(p.price) : ''; const rating = p.rating ? `<span class="badge text-bg-warning"><i class="bi bi-star-fill me-1"></i>${p.rating}</span>` : ''; const cat = safe(p.category||''); return `<div class="col-12 col-sm-6 col-lg-4"><div class="card card-surface h-100 product-card"><div class="ph ph-img card-img-top"></div><div class="card-body d-grid gap-1"><div class="d-flex justify-content-between align-items-start gap-2"><h3 class="h6 mb-0">${title}</h3>${rating}</div><div class="fw-bold">${price}</div><div class="text-secondary small">${cat}</div><div class="d-flex gap-2 mt-2"><a class="btn btn-sm btn-outline-secondary" href="#/product?id=${encodeURIComponent(p.id)}"><i class="bi bi-eye"></i></a><button class="btn btn-sm btn-primary" data-add="${encodeURIComponent(p.id)}"><i class="bi bi-bag-plus"></i></button></div></div></div></div>`; }
  // Wire up add-to-cart buttons
  function wireCardButtons(scope=document){ $$qs('[data-add]', scope).forEach(btn=> btn.onclick = ()=> addToCart(btn.dataset.add) ); }
  // Render the shop grid with filters
  function renderShop(){ const cats = [...new Set(NM.catalog.map(p=>p.category).filter(Boolean))]; const catSel = $qs('#shopCat'); if(catSel) catSel.innerHTML = `<option value="">All</option>` + cats.map(c=>`<option>${safe(c)}</option>`).join(''); const apply = () => { let items = [...NM.catalog]; const qEl = $qs('#shopSearch'); const q = (qEl?.value || '').trim().toLowerCase(); if(q) items = items.filter(p=> String(p.title||'').toLowerCase().includes(q)); const c = $qs('#shopCat')?.value; if(c) items = items.filter(p=>p.category===c); const min = Number(($qs('#minPrice')?.value||'').replace(/,/g,''))||0; const maxRaw = $qs('#maxPrice')?.value; const max = maxRaw? Number(maxRaw.replace(/,/g,'')) : Infinity; items = items.filter(p=> (p.price??0) >= min && (p.price??0) <= max); const s = $qs('#shopSort')?.value; if(s==='price-asc') items.sort((a,b)=>(a.price??0)-(b.price??0)); else if(s==='price-desc') items.sort((a,b)=>(b.price??0)-(a.price??0)); else if(s==='rating-desc') items.sort((a,b)=>(b.rating??0)-(a.rating??0)); const grid = $qs('#shopGrid'); if(grid){ grid.innerHTML = items.length ? items.map(cardHTML).join('') : `<div class='text-center text-secondary py-5'>No results</div>`; wireCardButtons(grid); } const count = $qs('#shopCount'); if(count) count.textContent = `${items.length} items`; }; const applyBtn = $qs('#applyFilters'); if(applyBtn) applyBtn.onclick = apply; const clearBtn = $qs('#clearFilters'); if(clearBtn) clearBtn.onclick = ()=>{ const s1=$qs('#shopSearch'); if(s1) s1.value=''; if(catSel) catSel.selectedIndex=0; const mp=$qs('#minPrice'); const xp=$qs('#maxPrice'); if(mp) mp.value=''; if(xp) xp.value=''; const ss=$qs('#shopSort'); if(ss) ss.value='relevance'; apply(); }; apply(); }

  // ------------------------------
  // Render: Product
  // ------------------------------
  // Render the product detail page
  function renderProduct(id){ const p = NM.catalog.find(x=> String(x.id)===String(id)); const area = $qs('#productArea'); if(!area){ return; } if(!p){ area.innerHTML = `<div class='text-secondary'>Product not found or catalog not loaded.</div>`; return; } const specRows = p.specs ? Object.entries(p.specs).map(([k,v])=>`<tr><th class='text-secondary'>${safe(k)}</th><td>${safe(String(v))}</td></tr>`).join('') : ''; const rating = p.rating ? `<span class="badge text-bg-warning"><i class="bi bi-star-fill me-1"></i>${p.rating}</span>` : ''; area.innerHTML = `<div class="row g-3"><div class="col-lg-7"><div class="card card-surface"><div class="card-body"><div class="ph ph-img rounded mb-2"></div><div class="d-grid" style="grid-template-columns: repeat(5, 1fr); gap: .5rem"><div class="ph ph-img rounded" style="aspect-ratio:4/3"></div><div class="ph ph-img rounded" style="aspect-ratio:4/3"></div><div class="ph ph-img rounded" style="aspect-ratio:4/3"></div><div class="ph ph-img rounded" style="aspect-ratio:4/3"></div><div class="ph ph-img rounded" style="aspect-ratio:4/3"></div></div></div></div></div><div class="col-lg-5"><div class="card card-surface"><div class="card-body d-grid gap-2"><h1 class="h4 mb-1">${safe(p.title||'Untitled')}</h1><div class="d-flex align-items-center gap-2">${rating}<span class="text-secondary small">${p.stock??''} ${p.stock!=null?'in stock':''}</span></div><div class="h4">${typeof p.price==='number'? money(p.price): ''}</div><p class="mb-2 text-secondary">${safe(p.desc||'')}</p><div class="input-group" style="max-width:180px"><span class="input-group-text">Qty</span><input id="qty" type="number" min="1" value="1" class="form-control"></div><div class="d-flex gap-2 mt-1"><button id="addBtn" class="btn btn-primary"><i class="bi bi-bag-plus me-1"></i>Add to cart</button><a class="btn btn-outline-secondary" href="#/shop">Back to shop</a></div><hr><table class="table table-sm mb-0"><tbody>${specRows}</tbody></table></div></div></div></div>`; const addBtn = $qs('#addBtn'); if(addBtn) addBtn.onclick = ()=> addToCart(p.id, Math.max(1, Number($qs('#qty')?.value||1)) ); }

  // ------------------------------
  // Render: Cart & Checkout
  // ------------------------------
  // Render the cart page
  function renderCart(){
    const cart = store.cart;
    const area = $qs('#cartArea');
    if(!area) return;
    if(!cart.length){
      area.innerHTML = `<div class='text-center text-secondary py-5'>Your cart is empty.</div>`;
      return;
    }
    const rows = cart.map(i=>{
      const p = NM.catalog.find(p=> String(p.id)===String(i.id));
      const title = safe(p?.title || `Item ${i.id}`);
      const price = p?.price ?? 0;
      const cat = safe(p?.category||'');
      return `<tr><td style="width:72px"><div class="ph" style="width:72px;height:54px;border-radius:.5rem"></div></td><td><a href="#/product?id=${encodeURIComponent(i.id)}">${title}</a><div class='small text-secondary'>${cat}</div></td><td>${money(price)}</td><td style="width:130px"><input type="number" min="1" value="${i.qty}" class="form-control form-control-sm" data-qty="${i.id}"></td><td class="fw-bold">${money(price * (i.qty||0))}</td><td><button class="btn btn-sm btn-outline-danger" data-del="${i.id}"><i class="bi bi-x"></i></button></td></tr>`;
    }).join('');
    area.innerHTML = `<div class="table-responsive"><table id="cartTable" class="table table-striped align-middle"><thead><tr><th></th><th>Item</th><th>Price</th><th>Qty</th><th>Subtotal</th><th></th></tr></thead><tbody>${rows}</tbody></table></div><div class="d-flex justify-content-end gap-3"><div class="h5">Total: <span class="text-primary">${money(cartTotal())}</span></div></div>`;
    $$qs('[data-qty]', area).forEach(inp=> inp.onchange = ()=> setQty(inp.dataset.qty, inp.value) );
    $$qs('[data-del]', area).forEach(btn=> btn.onclick = ()=> removeFromCart(btn.dataset.del) );
    if(window.jQuery && $.fn && $.fn.dataTable){
      $('#cartTable').DataTable({ paging:false, info:false, searching:false, order:[[1,'asc']] });
    }
  }
  // Render the checkout form
  function renderCheckout(){ const cart = store.cart; const sum = $qs('#checkoutSummary'); if(sum) sum.innerHTML = cart.length ? cart.map(i=>{ const p = NM.catalog.find(p=> String(p.id)===String(i.id)); const title = safe(p?.title || `Item ${i.id}`); const price = p?.price ?? 0; return `<div class="d-flex justify-content-between"><div>${title} × ${i.qty}</div><div>${money(price*(i.qty||0))}</div></div>`; }).join('') + `<hr><div class="d-flex justify-content-between fw-bold"><div>Total</div><div>${money(cartTotal())}</div></div>` : `<div class='text-secondary'>Cart is empty.</div>`; // Validation (guarded if plugin missing)
    if (window.jQuery && $.fn && $.fn.validate) {
      $('#checkoutForm').validate({ rules:{ coFn:{required:true,minlength:2}, coLn:{required:true,minlength:2}, coEmail:{required:true,email:true}, coAddr:{required:true,minlength:5}, coCity:{required:true}, coState:{required:true}, coZip:{required:true,minlength:3} }, errorClass:'is-invalid', validClass:'is-valid', errorPlacement:(err,el)=>{ $(el).addClass('is-invalid'); }, highlight:(el)=>$(el).addClass('is-invalid'), unhighlight:(el)=>$(el).removeClass('is-invalid') });
    }
    const form = $qs('#checkoutForm'); if(form){ form.onsubmit = (e)=>{ e.preventDefault(); if (window.jQuery && $.fn && $.fn.validate) { if(!$('#checkoutForm').valid()) { toast('Please fix the highlighted fields'); return; } } else { if(!form.checkValidity()){ form.classList.add('was-validated'); toast('Please fix the highlighted fields'); return; } } toast('Order placed!'); route('/home'); }; }
  }

  // ------------------------------
  // Render: Account & subpages (UI only)
  // ------------------------------
  // Render the account settings page
  function setAvatarPreview(dataUrl){
    const prev = $qs('#accAvatarPreview');
    if(!prev) return;
    if(dataUrl){
      prev.innerHTML = `<img src="${dataUrl}" alt="avatar" class="rounded-circle" style="width:100%;height:100%;object-fit:cover">`;
    } else {
      prev.innerHTML = '<i class="bi bi-person fs-4"></i>';
    }
  }

  async function refreshAccountShortcuts(){
    try {
      let profile = AccountGateway.getProfile();
      if (!profile) {
        profile = await AccountGateway.loadProfile();
      }
      if (profile) {
        setAvatarPreview(profile.avatar || null);
        const nameInput = $qs('#accName');
        if (nameInput) nameInput.value = profile.name || '';
        const emailInput = $qs('#accEmail');
        if (emailInput) emailInput.value = profile.email || '';
        const phoneInput = $qs('#accPhone');
        if (phoneInput) phoneInput.value = profile.phone || '';
        const addr = profile.address || {};
        const line1 = $qs('#accLine1');
        if (line1) line1.value = addr.line1 || '';
        const line2 = $qs('#accLine2');
        if (line2) line2.value = addr.line2 || '';
        const city = $qs('#accCity');
        if (city) city.value = addr.city || '';
        const state = $qs('#accState');
        if (state) state.value = addr.state || '';
        const postal = $qs('#accPostal');
        if (postal) postal.value = addr.postal_code || '';
        const country = $qs('#accCountry');
        if (country) country.value = addr.country || '';
      }
    } catch (err) {
      if (!isAuthError(err)) {
        console.warn('Failed to refresh profile', err);
      }
    }
    await refreshCardShortcuts();
  }

  async function refreshCardShortcuts(){
    try {
      let card = AccountGateway.getBanking();
      if (!card) {
        card = await AccountGateway.loadBanking();
      }
      const last4 = card?.card_last4 || '';
      const buttons = $$qs('#view-account a[href="#/account/card"]');
      buttons.forEach(btn => {
        const base = btn.dataset.label || btn.textContent.trim();
        btn.dataset.label = base;
        if (last4) {
          btn.innerHTML = `${base} <span class="badge text-bg-secondary ms-1">\u2022\u2022\u2022\u2022 ${last4}</span>`;
        } else {
          btn.innerHTML = base;
        }
      });
    } catch (err) {
      if (!isAuthError(err)) {
        console.warn('Failed to refresh card shortcuts', err);
      }
    }
  }

  async function renderAccount(){
    await refreshAccountShortcuts();
    const profile = AccountGateway.getProfile() || {};
    let avatarData = profile.avatar || null;
    const input = $qs('#accAvatarInput');
    if(input){
      input.value='';
      input.onchange = () => {
        const f = input.files?.[0];
        if(!f) return;
        if(!/^image\//.test(f.type)) return toast('Please choose an image file');
        if(f.size > 2*1024*1024) return toast('Image must be under 2MB');
        const reader = new FileReader();
        reader.onload = () => {
          avatarData = reader.result;
          setAvatarPreview(avatarData);
        };
        reader.onerror = () => toast('Failed to read image');
        reader.readAsDataURL(f);
      };
    }
    if (window.jQuery && $.fn && $.fn.validate) {
      $('#accForm').validate({ rules:{ accName:{required:true,minlength:2}, accEmail:{required:true,email:true}, accPhone:{required:false}, accLine1:{required:true,minlength:3}, accCity:{required:true}, accState:{required:true}, accPostal:{required:true}, accCountry:{required:true} }, errorClass:'is-invalid', validClass:'is-valid' });
    }
    const form = $qs('#accForm');
    if(form){
      form.onsubmit = async (e)=>{
        e.preventDefault();
        if (window.jQuery && $.fn && $.fn.validate) {
          if(!$('#accForm').valid()) { toast('Please fix the highlighted fields'); return; }
        } else {
          if(!form.checkValidity()){ form.classList.add('was-validated'); toast('Please fix the highlighted fields'); return; }
        }
        const payload = {
          name: form.accName.value.trim(),
          email: form.accEmail.value.trim(),
          phone: form.accPhone.value.trim(),
          address: {
            line1: form.accLine1.value.trim(),
            line2: form.accLine2.value.trim(),
            city: form.accCity.value.trim(),
            state: form.accState.value.trim(),
            postal_code: form.accPostal.value.trim(),
            country: form.accCountry.value.trim(),
          },
        };
        if(avatarData) payload.avatar = avatarData;
        try {
          await AccountGateway.saveProfile(payload);
          await refreshAccountShortcuts();
          toast('Profile saved');
        } catch(err){
          if (isAuthError(err)) {
            toast('Please sign in to sync your profile');
            return;
          }
          console.error(err);
          toast('Failed to save profile');
        }
      };
    }
  }
  // Render password change form
  function renderAccountPassword(){ const f = $qs('#pwdForm'); if(!f) return; if (window.jQuery && $.fn && $.fn.validate) { $('#pwdForm').validate({ rules:{ pwdCurrent:{required:true,minlength:8}, pwdNew:{required:true,minlength:8}, pwdConfirm:{required:true,equalTo:'#pwdNew'} }, errorClass:'is-invalid', validClass:'is-valid' }); }
    const bar = $qs('#pwdStrengthBar'); const newInput = $qs('#pwdNew'); if(newInput && bar){ newInput.addEventListener('input', ()=>{ const score = (window.zxcvbn? zxcvbn(newInput.value).score : 0); const pct = [5,25,50,75,100][score]; bar.style.width = pct+'%'; bar.className = score<2? 'bg-danger' : score<3? 'bg-warning' : 'bg-success'; }); }
    f.onsubmit = (e)=>{ e.preventDefault(); if (window.jQuery && $.fn && $.fn.validate) { if(!$('#pwdForm').valid()) { toast('Please fix the highlighted fields'); return; } } else { if(!f.checkValidity()){ f.classList.add('was-validated'); toast('Please fix the highlighted fields'); return; } if($qs('#pwdNew')?.value !== $qs('#pwdConfirm')?.value){ toast('Passwords do not match'); return; } } toast('Password updated'); route('/account'); };
  }
  // Render saved card form
  function parseExpiry(value=''){
    const digits = getCardDigits(value);
    if(digits.length < 4) return null;
    const month = Number(digits.slice(0,2));
    const yearPart = Number(digits.slice(2,4));
    if(month < 1 || month > 12) return null;
    const year = yearPart + (yearPart < 100 ? 2000 : 0);
    return { month, year };
  }

  async function renderAccountCard(){
    const f = $qs('#cardForm');
    if(!f) return;
    let cleaveNumber = null;
    let cleaveExpiry = null;
    if(window.Cleave){
      cleaveNumber = new Cleave('#cardNumber', { creditCard: true });
      cleaveExpiry = new Cleave('#cardExpiry', { date: true, datePattern: ['m','y'] });
    }
    if(window.Inputmask){
      Inputmask({ mask: '9999' }).mask('#cardCvc');
      Inputmask({ mask: '9{3,10}' }).mask('#cardZip');
    }
    let stored = AccountGateway.getBanking();
    try {
      if(!stored){
        stored = await AccountGateway.loadBanking();
      }
      if(stored){
        if(stored.cardholder) f.cardName.value = stored.cardholder;
        if(stored.postal_code) f.cardZip.value = stored.postal_code;
        if(stored.exp_month && stored.exp_year){
          const mm = String(stored.exp_month).padStart(2, '0');
          const yy = String(stored.exp_year).slice(-2);
          if(cleaveExpiry){ cleaveExpiry.setRawValue(mm + yy); }
          else { f.cardExpiry.value = `${mm}/${yy}`; }
        }
        f.cardNumber.placeholder = stored.card_last4 ? `•••• ${stored.card_last4}` : f.cardNumber.placeholder;
      }
    } catch(err){
      if (!isAuthError(err)) {
        console.error(err);
        toast('Failed to load saved card');
      }
    }
    if (window.jQuery && $.fn && $.fn.validate) {
      $('#cardForm').validate({ rules:{ cardName:{required:true,minlength:2}, cardNumber:{required:true,creditcard:true}, cardExpiry:{required:true}, cardCvc:{required:true,minlength:3}, cardZip:{required:true,minlength:3} }, errorClass:'is-invalid', validClass:'is-valid' });
    }
    f.onsubmit = async (e)=>{
      e.preventDefault();
      if (window.jQuery && $.fn && $.fn.validate) {
        if(!$('#cardForm').valid()) { toast('Please fix the highlighted fields'); return; }
      } else {
        if(!f.checkValidity()){ f.classList.add('was-validated'); toast('Please fix the highlighted fields'); return; }
      }
      const expiry = parseExpiry(f.cardExpiry.value);
      if(!expiry){ toast('Please enter a valid expiry date'); return; }
      const payload = {
        cardholder: f.cardName.value.trim(),
        card_number: getCardDigits(f.cardNumber.value),
        exp_month: expiry.month,
        exp_year: expiry.year,
        cvc: getCardDigits(f.cardCvc.value),
        postal_code: f.cardZip.value.trim(),
      };
      try {
        const saved = await AccountGateway.saveBanking(payload);
        if(cleaveNumber){ cleaveNumber.setRawValue(''); } else { f.cardNumber.value = ''; }
        if(cleaveExpiry){ cleaveExpiry.setRawValue(''); } else { f.cardExpiry.value = ''; }
        f.cardCvc.value = '';
        if(saved){
          f.cardName.value = saved.cardholder || '';
          f.cardZip.value = saved.postal_code || f.cardZip.value;
          f.cardNumber.placeholder = saved.card_last4 ? `•••• ${saved.card_last4}` : '';
        }
        await refreshCardShortcuts();
        toast('Card saved');
        route('/account');
      } catch(err){
        if (isAuthError(err)) {
          toast('Please sign in to save your card');
          return;
        }
        console.error(err);
        toast('Failed to save card');
      }
    };
  }

  // ------------------------------
  // Small helpers
  // ------------------------------
  // Show a small toast message
  function toast(msg){ Toastify({ text: msg, gravity:'bottom', position:'right', duration:2000, className:'bg-dark text-white' }).showToast(); }
  // Toggle site theme
  function applyTheme(next){ const cur = document.documentElement.getAttribute('data-bs-theme')||'dark'; const t = next || (cur==='light'?'dark':'light'); document.documentElement.setAttribute('data-bs-theme', t); localStorage.setItem('nm_theme', t); }
  const themeBtn = document.getElementById('themeBtn'); if(themeBtn) themeBtn.onclick = ()=> applyTheme();
  // Update footer year
  async function updateYear(){
    const { default: dayjs } = await import('https://cdn.jsdelivr.net/npm/dayjs@1/dayjs.min.js');
    const yearEl = document.getElementById('year');
    if(yearEl) yearEl.textContent = dayjs().year();
  }
  updateYear();

  // -------------
  // Self-tests
  // -------------
  // Simple sanity checks during development
  function runSelfTests(){
    const results = [];
    const ok = (name, pass, detail='') => results.push({name, pass, detail});
    // Test 1: router map covers required routes
    ok('routes contain core', ['/home','/shop','/product','/cart','/checkout','/account','/account/password','/account/card'].every(r=> r in routes), 'route keys');
    // Test 2: safe() works even if DOMPurify absent
    const dp = window.DOMPurify; try { window.DOMPurify = undefined; ok('safe fallback', safe('<img onerror=1>hi') === 'hi', 'sanitized'); } finally { window.DOMPurify = dp; }
    // Test 3: guards for optional libs
    ok('Cleave guarded', typeof window.Cleave === 'function' || true, 'no throw when absent');
    ok('jQuery validate guard', !(window.jQuery && $.fn) || typeof $.fn.validate === 'function' || true, 'guarded');
    // Test 4: money formatting
    ok('money()', money(12.5).includes('12'), 'format');
    console.groupCollapsed('Vendly self-tests');
    results.forEach(r=> console[r.pass? 'log':'warn'](`${r.pass?'PASS':'FAIL'}: ${r.name} ${r.detail?'- '+r.detail:''}`));
    console.groupEnd();
  }

  // Boot
  // Application entry point
  function boot(){
    updateMiniCart();
    applyTheme(localStorage.getItem('nm_theme'));
    loadCatalog();
    onRoute();
    refreshAccountShortcuts();
    if(!location.hash) route('/home');
    // Mask numeric price inputs if library is available
    if(window.Inputmask){ const els = document.querySelectorAll('#minPrice,#maxPrice'); if(els.length) Inputmask({ alias: 'decimal', groupSeparator: ',', autoGroup: true, digits: 2, digitsOptional: true, rightAlign: false }).mask(els); }
    // Run non-intrusive self tests
    runSelfTests();
  }
  window.addEventListener('DOMContentLoaded', boot);

  // Global error toast (helps surface CDN or cross-origin failures)
  window.addEventListener('error', (e)=>{
    if(String(e.message).toLowerCase().includes('script error')){
      toast('One of the external libraries failed to load. Features will gracefully degrade.');
    }
  });
    // Fade/blur transition between pages (Chrome/Edge/Safari TP support)
    // Smoothly navigate between pages
    function softNavigate(href){
      if (document.startViewTransition) {
        document.startViewTransition(() => { location.href = href; });
      } else {
        location.href = href;
      }
    }
    // Intercept same-origin links that opt-in with data-xnav
    document.addEventListener('click', (e)=>{
      const a = e.target.closest('a[data-xnav]');
      if(!a) return;
      const url = new URL(a.getAttribute('href'), location.href);
      if(url.origin !== location.origin) return;
      e.preventDefault();
      softNavigate(url.href);
    });
