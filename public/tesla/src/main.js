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
    night: false, music: true, sfx: true,
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

  const stage = document.getElementById('stage');
  const canvas = document.getElementById('game');
  const ctx = canvas.getContext('2d');
  let scale = 1;

  // 16:9 letterbox; 1em on the stage is 1/45 of its height, so the menus scale with it.
  function resize() {
    const w = Math.min(window.innerWidth, (window.innerHeight * 16) / 9);
    const h = (w * 9) / 16;
    stage.style.width = w + 'px';
    stage.style.height = h + 'px';
    stage.style.fontSize = h / 45 + 'px';
    const dpr = Math.min(window.devicePixelRatio || 1, 1.75);
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    scale = canvas.width / 1280;
  }
  window.addEventListener('resize', resize);
  resize();

  // ------------------------------------------------------------------ screens

  let current = 'title'; // visible screen id, or null while racing
  let race = null;
  let paused = false;
  let lastRoute = null;

  function show(id) {
    current = id;
    for (const s of document.querySelectorAll('.screen')) s.classList.toggle('show', s.id === id);
    stage.classList.toggle('racing', !id && !!race && !race.demo);
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
      }
    }
  }

  function toggle(what) {
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
      card.innerHTML =
        '<div class="name">' + (locked ? '🔒 ' : '') + r.from + ' → ' + r.to + '</div>' +
        '<div class="tagline"><span class="chip">' + bn(r.km) + ' কিমি</span>' +
        (r.night ? '<span class="chip">🌙 রাত</span>' : '') + (r.rain ? '<span class="chip">🌧 বৃষ্টি</span>' : '') + '</div>' +
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
      drawSkinPreview(cv, A.SKINS[s.id]);
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
    race = new Race({ route: DEMO, demo: true, night: save.night, sound: false });
    paused = false;
    audio.music('menu');
  }

  function startRace(route) {
    if (race) race.stopSounds();
    lastRoute = route;
    paused = false;
    const r = new Race({
      route,
      night: route.night || save.night,
      audio,
      sound: true,
      upgrades: save.upgrades,
      skin: A.SKINS[save.skin] || A.SKINS.tesla,
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
  const KEYS = {
    ArrowUp: 'up', KeyW: 'up', ArrowDown: 'down', KeyS: 'down',
    ArrowRight: 'accel', KeyD: 'accel', ArrowLeft: 'brake', KeyA: 'brake',
    Space: 'bell', ShiftLeft: 'boost', ShiftRight: 'boost', KeyX: 'boost',
  };

  function press(k, down) {
    if (k in held) held[k] = down;
    else if (down) tapped[k] = true;
  }

  window.addEventListener('keydown', (e) => {
    audio.unlock();
    const k = KEYS[e.code];
    if (k && current === null) {
      e.preventDefault();
      if (!e.repeat) press(k, true);
    } else if (e.code === 'KeyP' || e.code === 'Escape') {
      if (current === null) pause();
      else if (current === 'pause') resume();
      else if (current === 'routes' || current === 'garage' || current === 'help') show('title');
    } else if (e.code === 'Enter' && current === 'title') {
      e.preventDefault();
      show('routes');
    } else if (e.code === 'KeyM') {
      toggle('music');
    }
  });
  window.addEventListener('keyup', (e) => {
    const k = KEYS[e.code];
    if (k) press(k, false);
  });
  window.addEventListener('blur', () => {
    held.accel = held.brake = false;
  });
  window.addEventListener('pointerdown', () => audio.unlock(), { capture: true });

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
  // swipe up or down anywhere on the road to change lanes
  let swipeY = null;
  canvas.addEventListener('pointerdown', (e) => {
    swipeY = current === null ? e.clientY : null;
  });
  canvas.addEventListener('pointerup', (e) => {
    if (swipeY == null || current !== null) return;
    const dy = e.clientY - swipeY;
    if (Math.abs(dy) > 24) press(dy < 0 ? 'up' : 'down', true);
    swipeY = null;
  });
  if (window.matchMedia('(pointer: coarse)').matches) stage.classList.add('touch');
  window.addEventListener('touchstart', () => stage.classList.add('touch'), { once: true, passive: true });

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
    if (race) race.render(ctx, scale);
    requestAnimationFrame(frame);
  }

  audio.set({ music: save.music, sfx: save.sfx });
  audio.preload();
  startDemo();
  show('title');
  requestAnimationFrame(frame);

  // handle for playtesting from the browser console
  window.BT.game = {
    get race() {
      return race;
    },
    save,
    startRace,
  };
})();
