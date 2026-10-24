/* Graphics preview: the game's self-driving demo plus a gallery of every sprite, by day or night. */
(function () {
  'use strict';

  const { art: A, audio, Race, DEMO } = window.BT;
  let night = false;

  // Keeps a canvas's backing store matched to its on-screen size; returns the logical->pixel scale.
  function fit(canvas, lw, lh) {
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    const cw = canvas.clientWidth || lw;
    const bw = Math.round(cw * dpr), bh = Math.round(((cw * lh) / lw) * dpr);
    if (canvas.width !== bw || canvas.height !== bh) {
      canvas.width = bw;
      canvas.height = bh;
    }
    return bw / lw;
  }

  // ------------------------------------------------------------------ gameplay mock-up

  const mock = document.getElementById('mock');
  const mctx = mock.getContext('2d');
  const demo = new Race({ route: DEMO, demo: true, audio, sound: false });

  function renderMock() {
    const k = fit(mock, 1280, 720);
    demo.night = night;
    demo.render(mctx, k);
    A.rrect(mctx, 18, 676, 200, 30, 15);
    A.paint(mctx, 'rgba(29,20,40,0.75)');
    mctx.font = '700 15px ' + A.FONT_UI;
    mctx.textAlign = 'left';
    mctx.textBaseline = 'middle';
    mctx.fillStyle = '#ff4fa3';
    mctx.fillText('● অটোপাইলট ডেমো', 34, 691);
  }

  // ------------------------------------------------------------------ sprite gallery

  const gallery = document.getElementById('gallery');
  const cards = [];

  function card(spec) {
    const el = document.createElement('article');
    el.className = 'card';
    const cv = document.createElement('canvas');
    cv.width = spec.w;
    cv.height = spec.h;
    el.appendChild(cv);
    const info = document.createElement('div');
    info.className = 'info';
    info.innerHTML = '<h3>' + spec.title + ' <span>' + spec.en + '</span></h3><p>' + spec.text + '</p>';
    if (spec.buttons) {
      const row = document.createElement('div');
      row.className = 'controls';
      for (const [text, fn] of spec.buttons) {
        const b = document.createElement('button');
        b.textContent = text;
        b.addEventListener('click', () => fn(spec, b));
        row.appendChild(b);
      }
      info.appendChild(row);
    }
    el.appendChild(info);
    gallery.appendChild(el);
    if (spec.click) {
      cv.style.cursor = 'pointer';
      cv.addEventListener('click', (e) => {
        const r = cv.getBoundingClientRect();
        spec.click(spec, ((e.clientX - r.left) / r.width) * spec.w, ((e.clientY - r.top) / r.height) * spec.h);
      });
    }
    Object.assign(spec, { canvas: cv, ctx: cv.getContext('2d'), t: 0, dt: 0, scroll: 0, overlay: [] });
    cards.push(spec);
  }

  // A plain road strip for the gallery cards.
  function stage(ctx, w, h, scroll, gy) {
    const g = ctx.createLinearGradient(0, 0, 0, h);
    g.addColorStop(0, '#fff3dc');
    g.addColorStop(1, '#f6d7b5');
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, w, h);
    ctx.fillStyle = '#5d6169';
    ctx.fillRect(0, gy - 22, w, h - gy + 22);
    ctx.fillStyle = '#ffd23f';
    ctx.fillRect(0, gy - 24, w, 4);
    ctx.fillStyle = 'rgba(244,244,236,0.8)';
    const off = ((scroll % 100) + 100) % 100;
    for (let x = -off; x < w; x += 100) ctx.fillRect(x, gy + 16, 50, 4);
  }

  function say(name) {
    audio.unlock();
    audio.play(name);
  }

  function toggle(key) {
    return (c, b) => {
      c.st[key] = !c.st[key];
      b.classList.toggle('on', c.st[key]);
    };
  }

  function heroLine(c, which) {
    const sorry = which === 'sorry';
    c.st.pose = sorry ? 'sorry' : 'scratch';
    c.st.poseT = sorry ? 2.4 : 1.8;
    c.st.bubble = { text: sorry ? 'আমার ভুল হয়েছে,\nক্ষমা করে দেন!' : 'রাগ করলা?', t: 0, life: c.st.poseT + 0.2 };
    say(which);
  }

  card({
    title: 'বাংলা টেসলা',
    en: 'the hero rickshaw',
    text: 'ব্যাটারি চালিত রিকশা: চাকার হাবে মোটর, পাদানির নিচে ব্যাটারি। চার্জ থাকলে চালক পা তুলে আরামে বসে (অটোপাইলট), চার্জ শেষ হলে প্যাডেল মারে। রাতে হুডে রঙিন LED জ্বলে।',
    w: 760,
    h: 380,
    st: { pedal: false, boost: false, lights: false, pose: null, poseT: 0, bubble: null },
    buttons: [
      ['🦵 প্যাডেল মোড', toggle('pedal')],
      ['⚡ বুস্ট', toggle('boost')],
      ['💡 হেডলাইট', toggle('lights')],
      ['🙏 আমার ভুল হয়েছে', (c) => heroLine(c, 'sorry')],
      ['😅 রাগ করলা?', (c) => heroLine(c, 'raag')],
    ],
    draw(c, ctx, t) {
      const st = c.st;
      c.scroll += (st.boost ? 700 : 260) * c.dt;
      stage(ctx, c.w, c.h, c.scroll, 334);
      A.drawRickshaw(ctx, 360, 334, 1.25, t, {
        wheelRot: c.scroll / 31, pedal: st.pedal, crank: t * 6, boost: st.boost, lights: st.lights,
        pose: st.pose, talk: !!st.bubble, sway: st.boost ? 1 : 0.55,
      });
      if (st.bubble) c.overlay.push((g) => A.drawBubble(g, 360 + 60 * 1.25, 334 - 168 * 1.25, st.bubble.text, { pop: st.bubble.t / 0.22, size: 22 }));
    },
  });

  const RIVALS = [A.SKINS.peacock, A.SKINS.redfairy, A.SKINS.golden];
  card({
    title: 'প্রতিদ্বন্দ্বী রিকশা',
    en: 'rival racers',
    text: 'ময়ূরপঙ্খী, লাল পরী আর সোনার তরী: প্যাডেলে চলা তিন প্রতিদ্বন্দ্বী, প্রত্যেকের নিজস্ব রং, হুডের নকশা আর চালক। রাতে সিটের নিচে হারিকেন জ্বলে।',
    w: 760,
    h: 300,
    draw(c, ctx, t) {
      c.scroll += 220 * c.dt;
      stage(ctx, c.w, c.h, c.scroll, 270);
      RIVALS.forEach((skin, i) => A.drawRickshaw(ctx, 133 + i * 250, 270, 0.74, t, { skin, wheelRot: c.scroll / 31 + i, crank: t * 7 + i * 2, sway: 0.5 }));
    },
  });

  card({
    title: 'প্রাইভেট কার',
    en: 'private car (click to bump)',
    text: 'সাদা সেডান, সামনে ক্যাপ পরা ড্রাইভার, পেছনে সাহেব। ধাক্কা দিলে "ধুম!", গাড়িতে টোল পড়ে, হ্যাজার্ড লাইট জ্বলে, আর রিকশাওয়ালা কান ধরে বলে "আমার ভুল হয়েছে, ক্ষমা করে দেন"।',
    w: 760,
    h: 330,
    st: { hitT: null, fired: false },
    buttons: [['💥 ধাক্কা দিন', (c) => { c.st.hitT = 0; c.st.fired = false; }]],
    click(c) {
      c.st.hitT = 0;
      c.st.fired = false;
    },
    draw(c, ctx, t) {
      const st = c.st;
      stage(ctx, c.w, c.h, 0, 300);
      let rx = 128, pose = null;
      const k = st.hitT == null ? -1 : (st.hitT += c.dt);
      if (k >= 0 && k < 0.35) rx = 128 + 108 * (k / 0.35) * (k / 0.35); // rolls into the car
      else if (k >= 0.35) rx = 236 - Math.min(1, (k - 0.35) / 0.25) * 22; // bounces back
      const hit = k >= 0.35;
      if (hit && !st.fired) {
        st.fired = true;
        say('sorry');
      }
      if (hit && k < 2.6) pose = 'sorry';
      const jolt = hit && k < 0.75 ? Math.sin((k - 0.35) * 40) * (0.75 - k) * 14 : 0;
      A.drawCar(ctx, 520, 300, 1, t, { dent: hit, hazard: hit && k < 3.5, jolt });
      A.drawRickshaw(ctx, rx, 300, 0.75, t, { pose, talk: !!pose, wheelRot: rx / 23 });
      if (hit && k - 0.35 < 0.6) c.overlay.push((g) => A.drawBurst(g, 340, 228, 'ধুম!', 0.55 + 0.3 * A.easeOutBack(Math.min(1, (k - 0.35) / 0.15))));
      if (hit && k < 2.6) c.overlay.push((g) => A.drawBubble(g, rx + 45, 300 - 126, 'আমার ভুল হয়েছে,\nক্ষমা করে দেন!', { pop: (k - 0.35) / 0.22, size: 20 }));
      if (k > 3.8) st.hitT = null;
    },
  });

  card({
    title: 'পথচারী',
    en: 'pedestrians (click one)',
    text: 'যেখানে খুশি রাস্তা পার হয়: ফোনে ব্যস্ত অফিসযাত্রী, শাড়ি পরা আপা, বাজার হাতে চাচা, স্কুলছাত্র, মাথায় ঝাঁকা নিয়ে ফেরিওয়ালা। ধাক্কা খেলে "ধপাস!", মাথার চারপাশে তারা ঘোরে, তারপর রেগে মুঠি পাকায়।',
    w: 760,
    h: 300,
    st: { hits: [null, null, null, null, null] },
    buttons: [['▶ রাগ করলা?', () => say('raag')]],
    click(c, x) {
      c.st.hits[Math.max(0, Math.min(4, Math.round((x - 80) / 150)))] = 0;
      say('raag');
    },
    draw(c, ctx, t) {
      stage(ctx, c.w, c.h, 0, 262);
      A.PEOPLE_TYPES.forEach((type, i) => {
        const x = 80 + i * 150;
        let hit = c.st.hits[i];
        if (hit != null) hit = c.st.hits[i] = hit + c.dt > 3 ? null : hit + c.dt;
        A.drawPerson(ctx, x, 262, 1.25, t, { type, phase: i * 1.3, hit, spinDir: i % 2 ? 1 : -1 });
        if (hit != null && hit < 0.5) {
          const h = hit;
          c.overlay.push((g) => A.drawBurst(g, x, 96, 'ধপাস!', 0.45 + 0.2 * A.easeOutBack(Math.min(1, h / 0.15)), { rot: 0.08 }));
        }
        c.overlay.push((g) => {
          g.font = '600 14px ' + A.FONT_UI;
          g.textAlign = 'center';
          g.textBaseline = 'middle';
          g.fillStyle = '#fff7e8';
          g.fillText(A.PEOPLE_NAMES[type], x, 290);
        });
      });
    },
  });

  card({
    title: 'বাস ও সিএনজি',
    en: 'local bus and CNG',
    text: '"ঠেলাঠেলি পরিবহন": টোল খাওয়া লোকাল বাস, দরজায় ঝুলে থাকা হেলপার, পেছনে কালো ধোঁয়া। সবুজ সিএনজি পেছন থেকে এসে ওভারটেক করে, খাঁচার মতো গ্রিলের দরজা।',
    w: 760,
    h: 300,
    draw(c, ctx, t) {
      c.scroll += 160 * c.dt;
      stage(ctx, c.w, c.h, c.scroll, 270);
      A.drawBus(ctx, 248, 270, 0.62, t, { wheelRot: c.scroll / 30 });
      A.drawCNG(ctx, 626, 270, 0.92, t, { wheelRot: c.scroll / 19 });
    },
  });

  const ITEMS = [
    [52, 'টাকা', (ctx, x, t) => A.drawCoin(ctx, x, 256, 1.6, t)],
    [136, 'ব্যাটারি', (ctx, x, t) => A.drawBatteryPickup(ctx, x, 256, 1.4, t, { seed: 1 })],
    [222, 'বুস্ট', (ctx, x, t) => A.drawBoostPickup(ctx, x, 256, 1.3, t, { seed: 2 })],
    [308, 'চা', (ctx, x, t) => A.drawTea(ctx, x, 256, 1.6, t, { seed: 3 })],
    [412, 'গর্ত', (ctx, x) => A.drawPothole(ctx, x, 258, 0.9)],
    [546, 'জলাবদ্ধতা', (ctx, x, t) => A.drawPuddle(ctx, x, 260, 0.66, t)],
    [684, 'কাজ চলিতেছে', (ctx, x, t) => A.drawBarricade(ctx, x - 20, 256, 0.88, t)],
  ];
  card({
    title: 'পিকআপ ও বাধা',
    en: 'pickups and road hazards',
    text: 'টাকা (৳), ব্যাটারি, বুস্ট আর গরম চা কুড়িয়ে নিন। গর্ত, জলাবদ্ধতা আর "কাজ চলিতেছে" ব্যারিকেড এড়িয়ে চলুন।',
    w: 760,
    h: 300,
    draw(c, ctx, t) {
      stage(ctx, c.w, c.h, 0, 262);
      for (const [x, name, draw] of ITEMS) {
        draw(ctx, x, t);
        c.overlay.push((g) => {
          g.font = '600 14px ' + A.FONT_UI;
          g.textAlign = 'center';
          g.textBaseline = 'middle';
          g.fillStyle = '#fff7e8';
          g.fillText(name, x, 290);
        });
      }
    },
  });

  // ------------------------------------------------------------------ controls and loop

  for (const btn of document.querySelectorAll('[data-voice]')) btn.addEventListener('click', () => say(btn.dataset.voice));
  for (const [name, file] of [['sorry', 'assets/audio/amar-vul-hoyeche.mp3'], ['raag', 'assets/audio/rag-korla.mp3']]) {
    const probe = new Audio(file);
    probe.preload = 'metadata';
    probe.addEventListener('loadedmetadata', () => {
      const el = document.querySelector('[data-dur="' + name + '"]');
      if (el) el.textContent = A.bn(probe.duration.toFixed(1)) + ' সেকেন্ড';
    });
  }

  const soundBtn = document.getElementById('sound');
  soundBtn.addEventListener('click', () => {
    demo.sound = !demo.sound;
    if (demo.sound) audio.unlock();
    else audio.stopLoops();
    soundBtn.textContent = demo.sound ? '🔊 সাউন্ড চালু' : '🔇 সাউন্ড বন্ধ';
    soundBtn.classList.toggle('on', demo.sound);
  });
  const nightBtn = document.getElementById('night');
  nightBtn.addEventListener('click', () => {
    night = !night;
    nightBtn.textContent = night ? '🌙 রাত' : '☀ দিন';
    nightBtn.classList.toggle('on', night);
  });
  let paused = false;
  const pauseBtn = document.getElementById('pause');
  pauseBtn.addEventListener('click', () => {
    paused = !paused;
    pauseBtn.textContent = paused ? '▶ চালান' : '⏸ থামান';
  });

  // only animate canvases that are on screen
  const onScreen = new Map();
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) onScreen.set(e.target, e.isIntersecting);
  }, { rootMargin: '120px' });
  io.observe(mock);
  for (const c of cards) io.observe(c.canvas);
  const visible = (el) => onScreen.get(el) !== false;

  function tickPose(st, dt) {
    if (st.poseT > 0 && (st.poseT -= dt) <= 0) st.pose = null;
    if (st.bubble && (st.bubble.t += dt) > st.bubble.life) st.bubble = null;
  }

  audio.preload();
  let last = performance.now();
  function frame(now) {
    const dt = Math.min(0.05, (now - last) / 1000);
    last = now;
    if (!paused) demo.update(dt);
    if (visible(mock)) renderMock();
    for (const c of cards) {
      c.dt = dt;
      c.t += dt;
      if (c.st) tickPose(c.st, dt);
      if (!visible(c.canvas)) continue;
      const k = fit(c.canvas, c.w, c.h);
      c.ctx.setTransform(k, 0, 0, k, 0, 0);
      c.overlay.length = 0;
      A.beginNight(night);
      A.layer(c.ctx, (ctx) => c.draw(c, ctx, c.t));
      A.beginNight(false);
      for (const f of c.overlay) f(c.ctx);
    }
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
})();
