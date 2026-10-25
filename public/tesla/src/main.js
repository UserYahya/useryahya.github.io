/* বাংলা টেসলা — the game shell: screens, input, saved progress, garage and the main loop. */
(function () {
  'use strict';

  const { art: A, audio, Race, ROUTES, ENDLESS, DEMO, fmtTime, ORDINAL } = window.BT;
  const bn = A.bn;

  // ------------------------------------------------------------------ saved progress

  const SAVE_KEY = 'bangla-tesla-v1';
  const DEFAULTS = {
    wallet: 0, unlocked: 1, best: {}, endlessBest: 0,
    upgrades: { battery: 0, motor: 0, bell: 0 }, owned: ['tesla'], skin: 'tesla',
    night: false, music: true, sfx: true, view3d: true,
  };
  const save = loadSave();

  function loadSave() {
    let data = {};
    try {
      data = JSON.parse(localStorage.getItem(SAVE_KEY)) || {};
    } catch (e) {
      data = {};
    }
    const s = Object.assign({}, DEFAULTS, data);
    s.upgrades = Object.assign({}, DEFAULTS.upgrades, data.upgrades);
    s.best = Object.assign({}, data.best);
    if (!Array.isArray(s.owned)) s.owned = ['tesla'];
    return s;
  }

  function store() {
    try {
      localStorage.setItem(SAVE_KEY, JSON.stringify(save));
    } catch (e) {
      // storage blocked (private mode): progress lasts for this visit only
    }
  }

  const UPGRADES = [
    { id: 'battery', name: 'বড় ব্যাটারি', desc: 'চার্জ কম খরচ হয়, প্রতি লেভেলে ১৮%', cost: [300, 650, 1100] },
    { id: 'motor', name: 'জোরালো মোটর', desc: 'সব গতি বাড়ে, প্রতি লেভেলে ৫%', cost: [400, 800, 1400] },
    { id: 'bell', name: 'জোরালো ঘণ্টি', desc: 'ঘণ্টি আরও দূরে শোনা যায়, দ্রুত আবার বাজে', cost: [200, 450, 800] },
  ];
  const SKIN_SHOP = [
    { id: 'tesla', name: 'আসল টেসলা', price: 0 },
    { id: 'sky', name: 'নীল আকাশ', price: 500 },
    { id: 'gold', name: 'সোনালি', price: 900 },
    { id: 'queen', name: 'রাতের রানী', price: 1400 },
  ];

  // ------------------------------------------------------------------ stage

  const { scenery: S, hudLayout } = window.BT;
  const stage = document.getElementById('stage');
  const canvas = document.getElementById('game');
  const ctx = canvas.getContext('2d');
  // 3D: the street is drawn with WebGL on #gl; #game on top carries the HUD and speech bubbles
  const glCanvas = document.getElementById('gl');
  let can3d = !!(window.THREE && window.BT.View3D && window.BT.View3D.supported());
  let view = null;
  const use3d = () => can3d && save.view3d;

  function ensureView() {
    if (view || !use3d()) return view;
    try {
      view = new window.BT.View3D(glCanvas, { touch: isTouch() });
    } catch (e) {
      // no WebGL after all: the 2D game it is
      can3d = false;
      view = null;
    }
    return view;
  }
  glCanvas.addEventListener('webglcontextlost', (e) => {
    e.preventDefault();
    // the GPU gave up: carry on in 2D for this visit
    can3d = false;
    view = null;
    layout();
    refresh();
  });
  const safeArea = document.getElementById('safe');
  const pauseBtn = document.getElementById('pauseBtn');
  const laneBtns = [document.querySelector('[data-hold="up"]'), document.querySelector('[data-hold="down"]')];
  let scale = 1; // canvas px per logical px
  let hudScale = 1;
  let turned = 0; // 90 or -90 while the stage is turned to play landscape on a portrait screen
  let tilt = 90; // which way the phone is held sideways, from the motion sensor

  const isTouch = () => stage.classList.contains('touch');
  if (window.matchMedia('(pointer: coarse)').matches) stage.classList.add('touch');

  /* Fits the stage to the screen (inside the notch-safe area). The logical height is always 720;
   * the width stretches from 16:9 up to 21:9 so wide phones get no black bars. On a portrait
   * touch screen (rotation locked, or not turned yet) the whole stage is turned sideways, so the
   * game still plays in landscape: turn the phone and it reads the right way up. */
  function layout() {
    const r = safeArea.getBoundingClientRect();
    turned = isTouch() && r.height > r.width ? tilt : 0;
    const vw = turned ? r.height : r.width, vh = turned ? r.width : r.height;
    const aspect = Math.max(16 / 9, Math.min(21 / 9, vw / vh));
    const W = Math.round(720 * aspect);
    const h = Math.min(vh, vw / aspect), w = h * aspect;
    S.setWidth(W);
    stage.style.width = w + 'px';
    stage.style.height = h + 'px';
    stage.style.left = r.left + (r.width - w) / 2 + 'px';
    stage.style.top = r.top + (r.height - h) / 2 + 'px';
    stage.style.transform = turned ? 'rotate(' + turned + 'deg)' : '';
    stage.classList.toggle('turned', !!turned);
    // menus: 1em is 1/45 of the stage height, but never below 11.5px so phones stay readable
    const em = h / 45;
    stage.style.fontSize = Math.max(em, 11.5) + 'px';
    stage.classList.toggle('compact', em < 11.5);
    const dpr = Math.min(window.devicePixelRatio || 1, isTouch() ? 1.5 : 1.75);
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    scale = canvas.width / W;
    stage.classList.toggle('three', use3d() && !!view);
    if (view) view.setSize(w, h, W);
    // the lane buttons follow the view: ▲ ▼ in 2D, ◀ ▶ in 3D (index.html swaps the arrows)
    const three = stage.classList.contains('three');
    laneBtns[0].setAttribute('aria-label', three ? 'বাঁ দিকের লেন' : 'উপরের লেন');
    laneBtns[1].setAttribute('aria-label', three ? 'ডান দিকের লেন' : 'নিচের লেন');
    const cssScale = w / W;
    // HUD text at least ~11 CSS px on phones, as long as the panels still fit across the screen
    hudScale = Math.max(1, Math.min(11 / (16 * cssScale), (W - 80) / 912));
    const p = hudLayout(W, hudScale).pause;
    Object.assign(pauseBtn.style, {
      left: p.x * cssScale + 'px',
      top: p.y * cssScale + 'px',
      width: p.size * cssScale + 'px',
      height: p.size * cssScale + 'px',
      fontSize: p.size * cssScale * 0.38 + 'px',
    });
  }
  window.addEventListener('resize', layout);
  window.addEventListener('orientationchange', () => setTimeout(layout, 300));
  if (window.visualViewport) window.visualViewport.addEventListener('resize', layout);
  layout();

  // ------------------------------------------------------------------ phone orientation and fullscreen

  // accelerationIncludingGravity points up along whichever axis faces the sky. iOS reports it with
  // the opposite sign; we learn the sign whenever the phone is held upright.
  let gSign = /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1) ? -1 : 1;
  window.addEventListener('devicemotion', (e) => {
    const g = e.accelerationIncludingGravity;
    if (!g || g.x == null || g.y == null) return;
    if (Math.abs(g.y) > 7 && Math.abs(g.x) < 3) gSign = Math.sign(g.y);
    if (Math.abs(g.x) > 6.5 && Math.abs(g.y) < 4) {
      const t = g.x * gSign > 0 ? 90 : -90;
      if (t !== tilt) {
        tilt = t;
        if (turned) layout();
      }
    }
  });

  // iOS 13+ only shares the motion sensor after asking, and only from a tap.
  let motionAsked = false;
  function askMotion() {
    if (motionAsked || !turned || typeof DeviceMotionEvent === 'undefined' || typeof DeviceMotionEvent.requestPermission !== 'function') return;
    motionAsked = true;
    DeviceMotionEvent.requestPermission().catch(() => {});
  }

  const isFullscreen = () => !!(document.fullscreenElement || document.webkitFullscreenElement);
  if (!(document.fullscreenEnabled || document.webkitFullscreenEnabled)) stage.classList.add('no-fs');

  // In fullscreen, Android lets a page lock the screen to landscape even with auto-rotate off.
  function lockLandscape() {
    if (isFullscreen() && screen.orientation && screen.orientation.lock) screen.orientation.lock('landscape').catch(() => {});
  }

  function fullscreen(on) {
    try {
      if (on && !isFullscreen()) {
        const el = document.documentElement;
        const req = el.requestFullscreen || el.webkitRequestFullscreen;
        const p = req && req.call(el, { navigationUI: 'hide' });
        if (p && p.then) p.then(lockLandscape, () => {});
      } else if (!on && isFullscreen()) {
        (document.exitFullscreen || document.webkitExitFullscreen).call(document);
      }
    } catch (e) {
      // not allowed here (iPhone Safari); "Add to Home Screen" gives a full-screen app instead
    }
  }
  for (const ev of ['fullscreenchange', 'webkitfullscreenchange']) {
    document.addEventListener(ev, () => {
      layout();
      lockLandscape();
      refresh();
    });
  }

  // ------------------------------------------------------------------ screens

  let current = 'title'; // visible screen id, or null while racing
  let race = null;
  let paused = false;
  let lastRoute = null;

  function show(id) {
    current = id;
    for (const s of document.querySelectorAll('.screen')) s.classList.toggle('show', s.id === id);
    stage.classList.toggle('racing', !id && !!race && !race.demo);
    // racing: let go of the focus on any button, so Space or Enter can't press it mid-race
    if (!id && document.activeElement && document.activeElement !== document.body) document.activeElement.blur();
    if (id === 'routes') renderRoutes();
    if (id === 'garage') renderGarage();
    refresh();
  }

  function refresh() {
    for (const el of document.querySelectorAll('[data-wallet]')) el.textContent = bn(save.wallet);
    for (const b of document.querySelectorAll('[data-toggle]')) {
      const k = b.dataset.toggle;
      if (k === 'night') {
        b.textContent = save.night ? '🌙 রাত' : '☀ দিন';
      } else if (k === 'music') {
        b.textContent = (save.music ? '🎵' : '🔇') + ' মিউজিক';
        b.classList.toggle('off', !save.music);
      } else if (k === 'sfx') {
        b.textContent = (save.sfx ? '🔊' : '🔈') + ' সাউন্ড';
        b.classList.toggle('off', !save.sfx);
      } else if (k === 'fullscreen') {
        b.textContent = isFullscreen() ? '⛶ ছোট পর্দা' : '⛶ ফুলস্ক্রিন';
      } else if (k === 'view') {
        b.textContent = use3d() ? '🧊 ৩ডি' : '🖼 ২ডি';
        b.style.display = can3d ? '' : 'none';
      }
    }
  }

  function toggle(what) {
    if (what === 'fullscreen') {
      fullscreen(!isFullscreen());
      return;
    }
    if (what === 'flip') {
      // upside down? turn the stage the other way (for phones without a motion sensor)
      tilt = -tilt;
      layout();
      return;
    }
    if (what === 'view') {
      // 3D or the classic 2D game; the demo behind the menus restarts in the new look
      if (!can3d) return;
      save.view3d = !save.view3d;
      ensureView();
      layout();
      store();
      startDemo();
      show(current);
      return;
    }
    if (what === 'night') {
      save.night = !save.night;
      if (race && race.demo) race.night = save.night;
    } else if (what === 'music') {
      save.music = !save.music;
      audio.set({ music: save.music });
    } else if (what === 'sfx') {
      save.sfx = !save.sfx;
      audio.set({ sfx: save.sfx });
    }
    store();
    refresh();
  }

  function renderRoutes() {
    const grid = document.getElementById('routeGrid');
    grid.innerHTML = '';
    const stars = (n) => [1, 2, 3].map((k) => (k <= n ? '★' : '<span class="no">★</span>')).join('');
    ROUTES.forEach((r, i) => {
      const locked = i >= save.unlocked;
      const b = save.best[r.id];
      const card = document.createElement('button');
      card.className = 'route' + (locked ? ' locked' : '');
      card.disabled = locked;
      // the real streets the route runs along (OpenStreetMap)
      const osm = window.BT.osm && window.BT.osm[r.id];
      const via = osm ? osm.streets.map((st) => st[1]).join(' · ') : '';
      card.innerHTML =
        '<div class="name">' + (locked ? '🔒 ' : '') + r.from + ' → ' + r.to + '</div>' +
        '<div class="tagline"><span class="chip">' + bn(r.km) + ' কিমি</span>' +
        (r.night ? '<span class="chip">🌙 রাত</span>' : '') + (r.rain ? '<span class="chip">🌧 বৃষ্টি</span>' : '') + '</div>' +
        (via ? '<div class="via">🛣 ' + via + '</div>' : '') +
        '<div class="about">' + (locked ? 'আগের রুটে ৩য় বা তার ভালো হলে খুলবে।' : r.about) + '</div>' +
        '<div class="meta"><span class="stars">' + stars(b ? b.stars : 0) + '</span><span>' + (b ? 'সেরা সময় ' + fmtTime(b.time) : '') + '</span></div>';
      card.addEventListener('click', () => startRace(r));
      grid.appendChild(card);
    });
    const e = document.createElement('button');
    e.className = 'route';
    e.innerHTML =
      '<div class="name">🚦 জ্যাম মোড</div><div class="tagline"><span class="chip">যত দূর যাওয়া যায়</span></div>' +
      '<div class="about">শেষ নেই। প্রাইভেট কারে ৪ বার ধাক্কা দিলেই খেলা শেষ।</div>' +
      '<div class="meta"><span></span><span>' + (save.endlessBest ? 'সেরা ' + bn(save.endlessBest.toFixed(2)) + ' কিমি' : '') + '</span></div>';
    e.addEventListener('click', () => startRace(ENDLESS));
    grid.appendChild(e);
  }

  function drawSkinPreview(cv, skin) {
    const c = cv.getContext('2d');
    c.setTransform(2, 0, 0, 2, 0, 0);
    const g = c.createLinearGradient(0, 0, 0, 190);
    g.addColorStop(0, '#fff3dc');
    g.addColorStop(1, '#f6d7b5');
    c.fillStyle = g;
    c.fillRect(0, 0, 300, 190);
    c.fillStyle = '#5d6169';
    c.fillRect(0, 160, 300, 30);
    A.drawRickshaw(c, 150, 174, 0.72, 0, { skin });
  }

  function buy(cost, apply) {
    if (save.wallet < cost) return;
    save.wallet -= cost;
    apply();
    store();
    audio.play('coin');
    renderGarage();
    refresh();
  }

  function renderGarage() {
    const up = document.getElementById('upgrades');
    up.innerHTML = '';
    for (const u of UPGRADES) {
      const lvl = save.upgrades[u.id] || 0;
      const cost = u.cost[lvl];
      const row = document.createElement('div');
      row.className = 'upgrade';
      row.innerHTML = '<div><div class="name">' + u.name + ' <span class="pips">' + '●'.repeat(lvl) + '○'.repeat(3 - lvl) + '</span></div><div class="desc">' + u.desc + '</div></div>';
      const b = document.createElement('button');
      b.className = 'pill';
      if (cost == null) {
        b.textContent = 'সর্বোচ্চ';
        b.disabled = true;
      } else {
        b.textContent = '৳' + bn(cost);
        b.disabled = save.wallet < cost;
        b.addEventListener('click', () => buy(cost, () => (save.upgrades[u.id] = lvl + 1)));
      }
      row.appendChild(b);
      up.appendChild(row);
    }
    const sk = document.getElementById('skins');
    sk.innerHTML = '';
    for (const s of SKIN_SHOP) {
      const card = document.createElement('div');
      card.className = 'skin' + (save.skin === s.id ? ' on' : '');
      const cv = document.createElement('canvas');
      cv.width = 600;
      cv.height = 380;
      card.appendChild(cv);
      if (use3d() && ensureView()) view.snapshot(A.SKINS[s.id], cv);
      else drawSkinPreview(cv, A.SKINS[s.id]);
      const name = document.createElement('div');
      name.className = 'name';
      name.textContent = s.name;
      card.appendChild(name);
      const b = document.createElement('button');
      b.className = 'pill';
      if (save.skin === s.id) {
        b.textContent = '✓ চলছে';
        b.disabled = true;
      } else if (save.owned.includes(s.id)) {
        b.textContent = 'বেছে নিন';
        b.addEventListener('click', () => {
          save.skin = s.id;
          store();
          renderGarage();
        });
      } else {
        b.textContent = '৳' + bn(s.price);
        b.disabled = save.wallet < s.price;
        b.addEventListener('click', () => buy(s.price, () => {
          save.owned.push(s.id);
          save.skin = s.id;
        }));
      }
      card.appendChild(b);
      sk.appendChild(card);
    }
  }

  // ------------------------------------------------------------------ races

  function startDemo() {
    if (race) race.stopSounds();
    ensureView();
    race = new Race({ route: DEMO, demo: true, night: save.night, sound: false, view3d: use3d() });
    paused = false;
    audio.music('menu');
  }

  function startRace(route) {
    if (race) race.stopSounds();
    if (isTouch()) fullscreen(true); // phones: full screen, locked to landscape where allowed
    lastRoute = route;
    paused = false;
    const r = new Race({
      route,
      night: route.night || save.night,
      audio,
      sound: true,
      touch: isTouch(),
      upgrades: save.upgrades,
      skin: A.SKINS[save.skin] || A.SKINS.tesla,
      view3d: use3d(),
      // let the finish (or the last crash) play out before the results card
      onEvent: (type, res) => setTimeout(() => race === r && endRace(res), type === 'over' ? 2200 : 2600),
    });
    race = r;
    audio.music(r.night ? 'race-night' : 'race-day');
    show(null);
  }

  function endRace(res) {
    let note = '';
    if (res.route.endless) {
      if (res.km > save.endlessBest) {
        save.endlessBest = res.km;
        note = 'নতুন রেকর্ড!';
      }
    } else {
      const id = res.route.id, b = save.best[id];
      if (b && res.time < b.time) note = 'নতুন সেরা সময়!';
      save.best[id] = {
        stars: Math.max(b ? b.stars : 0, res.stars),
        pos: Math.min(b ? b.pos : 9, res.pos),
        time: b ? Math.min(b.time, res.time) : res.time,
      };
      const idx = ROUTES.indexOf(res.route);
      if (res.stars >= 1 && idx + 1 < ROUTES.length && save.unlocked < idx + 2) {
        save.unlocked = idx + 2;
        note = 'নতুন রুট খুলেছে: ' + ROUTES[idx + 1].from + ' → ' + ROUTES[idx + 1].to + '!';
      }
    }
    save.wallet += res.total;
    store();
    showResults(res, note);
  }

  function showResults(res, note) {
    const r = res.route;
    const $ = (id) => document.getElementById(id);
    let rows;
    if (r.endless) {
      $('resPos').textContent = 'জ্যাম মোড শেষ';
      $('resRoute').textContent = 'আর ক্ষমা নেই!';
      $('resStars').innerHTML = '';
      rows = [
        ['পাড়ি দিলেন', bn(res.km.toFixed(2)) + ' কিমি'],
        ['সেরা', bn(save.endlessBest.toFixed(2)) + ' কিমি'],
        ['কুড়ানো টাকা', '+৳' + bn(res.coins)],
        ['জরিমানা', '−৳' + bn(res.fines)],
        ['মোট আয়', '৳' + bn(res.total)],
      ];
    } else {
      $('resPos').textContent = ORDINAL[res.pos - 1] + (res.pos === 1 ? '! জিতে গেছেন' : res.pos <= 3 ? ' হয়েছেন!' : ', পরের বার!');
      $('resRoute').textContent = r.from + ' → ' + r.to + (res.night ? ' · রাত' : ' · দিন');
      $('resStars').innerHTML = [1, 2, 3].map((k) => (k <= res.stars ? '★' : '<span class="no">★</span>')).join('');
      rows = [
        ['সময়', fmtTime(res.time)],
        ['কুড়ানো টাকা', '+৳' + bn(res.coins)],
        ['পুরস্কার', '+৳' + bn(res.bonus)],
        ['জরিমানা', '−৳' + bn(res.fines)],
        ['ধাক্কা', 'কার ' + bn(res.hits.car) + ' · মানুষ ' + bn(res.hits.person) + ' · অন্য ' + bn(res.hits.other)],
        ['মোট আয়', '৳' + bn(res.total)],
      ];
    }
    $('resTable').innerHTML = rows.map(([k, v], i) => '<tr' + (i === rows.length - 1 ? ' class="total"' : '') + '><td>' + k + '</td><td>' + v + '</td></tr>').join('');
    $('resNote').textContent = note;
    const idx = ROUTES.indexOf(r);
    $('btnNext').style.display = !r.endless && idx + 1 < ROUTES.length && save.unlocked > idx + 1 ? '' : 'none';
    show('results');
  }

  function pause() {
    if (!race || race.demo || current !== null) return;
    paused = true;
    race.stopSounds(); // loops restart on their own when the race resumes
    show('pause');
  }

  function resume() {
    paused = false;
    show(null);
  }

  function act(a) {
    if (a === 'endless') startRace(ENDLESS);
    else if (a === 'pause') pause();
    else if (a === 'resume') resume();
    else if (a === 'restart' || a === 'retry') startRace(lastRoute);
    else if (a === 'next') startRace(ROUTES[ROUTES.indexOf(lastRoute) + 1]);
    else if (a === 'quit') {
      startDemo();
      show('title');
    }
  }

  // ------------------------------------------------------------------ input

  const held = { accel: false, brake: false };
  const tapped = { up: false, down: false, bell: false, boost: false };
  // The keys follow the view. In 2D the lanes run up and down the screen, so ↑ ↓ change lane
  // and → ← speed up and brake; in 3D the camera rides behind the rickshaw, so ← → change lane
  // and ↑ ↓ speed up and brake. ('up' is the lane toward the kerb: above in 2D, left in 3D.)
  const COMMON_KEYS = { Space: 'bell', ShiftLeft: 'boost', ShiftRight: 'boost', KeyX: 'boost' };
  const KEYS_2D = Object.assign({
    ArrowUp: 'up', KeyW: 'up', ArrowDown: 'down', KeyS: 'down',
    ArrowRight: 'accel', KeyD: 'accel', ArrowLeft: 'brake', KeyA: 'brake',
  }, COMMON_KEYS);
  const KEYS_3D = Object.assign({
    ArrowLeft: 'up', KeyA: 'up', ArrowRight: 'down', KeyD: 'down',
    ArrowUp: 'accel', KeyW: 'accel', ArrowDown: 'brake', KeyS: 'brake',
  }, COMMON_KEYS);
  const in3d = () => !!(race && race.view3d && view);
  const pressedBy = {}; // key code → the action it pressed, so its key-up lets go of that same action

  function press(k, down) {
    if (k in held) held[k] = down;
    else if (down) tapped[k] = true;
  }

  window.addEventListener('keydown', (e) => {
    audio.unlock();
    const k = (in3d() ? KEYS_3D : KEYS_2D)[e.code];
    if (k && current === null) {
      e.preventDefault();
      if (!e.repeat) {
        pressedBy[e.code] = k;
        press(k, true);
      }
    } else if (e.code === 'KeyP' || e.code === 'Escape') {
      if (current === null) pause();
      else if (current === 'pause') resume();
      else if (current === 'routes' || current === 'garage' || current === 'help') show('title');
    } else if (e.code === 'Enter' && current === 'title') {
      e.preventDefault();
      show('routes');
    } else if (e.code === 'KeyM') {
      toggle('music');
    } else if (e.code === 'KeyF') {
      toggle('fullscreen');
    }
  });
  window.addEventListener('keyup', (e) => {
    const k = pressedBy[e.code];
    if (!k) return;
    if (current === null) e.preventDefault(); // so Space can't press a focused button either
    delete pressedBy[e.code];
    // ↑ and W both hold the throttle in 3D: let go only when neither is down
    if (!Object.values(pressedBy).includes(k)) press(k, false);
  });
  window.addEventListener('blur', () => {
    held.accel = held.brake = false;
    for (const code in pressedBy) delete pressedBy[code];
  });
  window.addEventListener('pointerdown', () => audio.unlock(), { capture: true });
  window.addEventListener('click', askMotion, { capture: true });

  stage.addEventListener('click', (e) => {
    const b = e.target.closest('button');
    if (!b) return;
    if (b.dataset.go) show(b.dataset.go);
    else if (b.dataset.toggle) toggle(b.dataset.toggle);
    else if (b.dataset.act) act(b.dataset.act);
    if (!b.dataset.hold) audio.play('click');
  });

  // on-screen controls for phones
  for (const b of document.querySelectorAll('[data-hold]')) {
    const k = b.dataset.hold;
    const off = () => press(k, false);
    b.addEventListener('pointerdown', (e) => {
      e.preventDefault();
      if (b.setPointerCapture) b.setPointerCapture(e.pointerId);
      press(k, true);
    });
    b.addEventListener('pointerup', off);
    b.addEventListener('pointercancel', off);
    b.addEventListener('lostpointercapture', off);
  }
  // swipe across the lanes anywhere on the road to change lanes: up or down in 2D, left or
  // right in 3D
  let swipe = null;
  canvas.addEventListener('pointerdown', (e) => {
    swipe = current === null ? { x: e.clientX, y: e.clientY } : null;
  });
  canvas.addEventListener('pointerup', (e) => {
    if (!swipe || current !== null) return;
    const dx = e.clientX - swipe.x, dy = e.clientY - swipe.y;
    // measure the swipe in the game's own frame, which may be turned sideways
    const gx = turned === 90 ? dy : turned === -90 ? -dy : dx;
    const gy = turned === 90 ? -dx : turned === -90 ? dx : dy;
    const d = in3d() ? gx : gy;
    if (Math.abs(d) > 24) press(d < 0 ? 'up' : 'down', true);
    swipe = null;
  });
  window.addEventListener('touchstart', () => {
    if (isTouch()) return;
    stage.classList.add('touch');
    layout();
  }, { passive: true });

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) pause();
  });

  // ------------------------------------------------------------------ main loop

  let last = performance.now();
  function frame(now) {
    const dt = Math.min(0.05, (now - last) / 1000);
    last = now;
    if (race && !paused) {
      race.update(dt, { up: tapped.up, down: tapped.down, bell: tapped.bell, boost: tapped.boost, accel: held.accel, brake: held.brake });
    }
    tapped.up = tapped.down = tapped.bell = tapped.boost = false;
    if (race) {
      if (race.view3d && view) {
        view.render(race, paused ? 0 : dt);
        race.renderOverlay(ctx, scale, hudScale, view);
      } else {
        race.render(ctx, scale, hudScale);
      }
    }
    requestAnimationFrame(frame);
  }

  audio.set({ music: save.music, sfx: save.sfx });
  audio.preload();
  ensureView();
  layout();
  startDemo();
  show('title');
  requestAnimationFrame(frame);

  // handle for playtesting from the browser console
  window.BT.game = {
    get race() {
      return race;
    },
    get view() {
      return view;
    },
    save,
    startRace,
  };
})();
