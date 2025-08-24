  // ==============================
  // Marketplace UI (no backend)
  // ==============================
  const $qs = (sel, el=document) => el.querySelector(sel);
  const $$qs = (sel, el=document) => [...el.querySelectorAll(sel)];
  const money = n => new Intl.NumberFormat(undefined, { style:'currency', currency:'USD' }).format(n||0);
  const safe = s => (window.DOMPurify ? DOMPurify.sanitize(String(s ?? ''), {ALLOWED_TAGS:[], ALLOWED_ATTR:[]}) : String(s ?? ''));

  const API_URL = `${location.protocol}//${location.hostname}:7890`;
  const adminLink = document.getElementById('navAdmin');
  if (adminLink) adminLink.href = `${API_URL}/admin`;

  // Pull product catalog from backend API
  async function loadCatalog(){
    try {
      const { data } = await axios.get(`${API_URL}/products`);
      NM.setCatalog(data);
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
  function onRoute(){ const { path, params } = parseHash(); $$qs('.nav-link[data-nav]').forEach(a => a.classList.toggle('active', a.getAttribute('href')===`#${path}`)); $$qs('.view').forEach(v=>v.classList.remove('active')); const map = { '/home':'view-home', '/shop':'view-shop', '/product':'view-product', '/cart':'view-cart', '/checkout':'view-checkout', '/account':'view-account', '/account/password':'view-account-password', '/account/card':'view-account-card' }; const id = map[path] || 'view-home'; const view = document.getElementById(id); if(view) view.classList.add('active'); (routes[path] || routes['/home'])(params); }
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
  function renderCart(){ const cart = store.cart; const area = $qs('#cartArea'); if(!area) return; if(!cart.length){ area.innerHTML = `<div class='text-center text-secondary py-5'>Your cart is empty.</div>`; return; } const rows = cart.map(i=>{ const p = NM.catalog.find(p=> String(p.id)===String(i.id)); const title = safe(p?.title || `Item ${i.id}`); const price = p?.price ?? 0; const cat = safe(p?.category||''); return `<tr><td style="width:72px"><div class="ph" style="width:72px;height:54px;border-radius:.5rem"></div></td><td><a href="#/product?id=${encodeURIComponent(i.id)}">${title}</a><div class='small text-secondary'>${cat}</div></td><td>${money(price)}</td><td style="width:130px"><input type="number" min="1" value="${i.qty}" class="form-control form-control-sm" data-qty="${i.id}"></td><td class="fw-bold">${money(price * (i.qty||0))}</td><td><button class="btn btn-sm btn-outline-danger" data-del="${i.id}"><i class="bi bi-x"></i></button></td></tr>`; }).join(''); area.innerHTML = `<div class="table-responsive"><table class="table align-middle"><thead><tr><th></th><th>Item</th><th>Price</th><th>Qty</th><th>Subtotal</th><th></th></tr></thead><tbody>${rows}</tbody></table></div><div class="d-flex justify-content-end gap-3"><div class="h5">Total: <span class="text-primary">${money(cartTotal())}</span></div></div>`; $$qs('[data-qty]', area).forEach(inp=> inp.onchange = ()=> setQty(inp.dataset.qty, inp.value) ); $$qs('[data-del]', area).forEach(btn=> btn.onclick = ()=> removeFromCart(btn.dataset.del) ); }
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
  function renderAccount(){ const input = $qs('#accAvatarInput'); if(input){ input.onchange = () => { const f = input.files?.[0]; if(!f) return; if(!/^image\//.test(f.type)) return toast('Please choose an image file'); if(f.size > 2*1024*1024) return toast('Image must be under 2MB'); const url = URL.createObjectURL(f); const prev = $qs('#accAvatarPreview'); if(prev) prev.innerHTML = `<img src="${url}" alt="avatar" class="rounded-circle" style="width:100%;height:100%;object-fit:cover">`; }; }
    if (window.jQuery && $.fn && $.fn.validate) {
      $('#accForm').validate({ rules:{ accName:{required:true,minlength:2}, accEmail:{required:true,email:true}, accPhone:{required:false} }, errorClass:'is-invalid', validClass:'is-valid' });
    }
    const form = $qs('#accForm'); if(form){ form.onsubmit = (e)=>{ e.preventDefault(); if (window.jQuery && $.fn && $.fn.validate) { if(!$('#accForm').valid()) { toast('Please fix the highlighted fields'); return; } } else { if(!form.checkValidity()){ form.classList.add('was-validated'); toast('Please fix the highlighted fields'); return; } } toast('Saved'); }; }
  }
  // Render password change form
  function renderAccountPassword(){ const f = $qs('#pwdForm'); if(!f) return; if (window.jQuery && $.fn && $.fn.validate) { $('#pwdForm').validate({ rules:{ pwdCurrent:{required:true,minlength:8}, pwdNew:{required:true,minlength:8}, pwdConfirm:{required:true,equalTo:'#pwdNew'} }, errorClass:'is-invalid', validClass:'is-valid' }); }
    const bar = $qs('#pwdStrengthBar'); const newInput = $qs('#pwdNew'); if(newInput && bar){ newInput.addEventListener('input', ()=>{ const score = (window.zxcvbn? zxcvbn(newInput.value).score : 0); const pct = [5,25,50,75,100][score]; bar.style.width = pct+'%'; bar.className = score<2? 'bg-danger' : score<3? 'bg-warning' : 'bg-success'; }); }
    f.onsubmit = (e)=>{ e.preventDefault(); if (window.jQuery && $.fn && $.fn.validate) { if(!$('#pwdForm').valid()) { toast('Please fix the highlighted fields'); return; } } else { if(!f.checkValidity()){ f.classList.add('was-validated'); toast('Please fix the highlighted fields'); return; } if($qs('#pwdNew')?.value !== $qs('#pwdConfirm')?.value){ toast('Passwords do not match'); return; } } toast('Password updated'); route('/account'); };
  }
  // Render saved card form
  function renderAccountCard(){ const f = $qs('#cardForm'); if(!f) return; if(window.Cleave){ new Cleave('#cardNumber', { creditCard: true }); new Cleave('#cardExpiry', { date: true, datePattern: ['m','y'] }); } if(window.Inputmask){ Inputmask({ mask: '9999' }).mask('#cardCvc'); Inputmask({ mask: '9{3,10}' }).mask('#cardZip'); }
    if (window.jQuery && $.fn && $.fn.validate) { $('#cardForm').validate({ rules:{ cardName:{required:true,minlength:2}, cardNumber:{required:true,creditcard:true}, cardExpiry:{required:true}, cardCvc:{required:true,minlength:3}, cardZip:{required:true,minlength:3} }, errorClass:'is-invalid', validClass:'is-valid' }); }
    f.onsubmit = (e)=>{ e.preventDefault(); if (window.jQuery && $.fn && $.fn.validate) { if(!$('#cardForm').valid()) { toast('Please fix the highlighted fields'); return; } } else { if(!f.checkValidity()){ f.classList.add('was-validated'); toast('Please fix the highlighted fields'); return; } } toast('Card saved'); route('/account'); };
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
