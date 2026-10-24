/* বাংলা টেসলা — the Dhaka street: sky, hazy skyline, buildings, tangled wires,
 * footpath and road, by day or by night. Everything is anchored to world x and seeded
 * by tile index, so scrolling never reshuffles the city. */
(function () {
  'use strict';

  const A = window.BT.art;
  const { TAU, OL, FONT_DISPLAY, FONT_UI, rrect, paint, circle, ellipse, shade, hash, fitText, emit, glow } = A;

  const W = 1280, H = 720;
  const FOOT_TOP = 392; // footpath begins
  const ROAD_TOP = 436; // kerb
  const LANE_EDGES = [436, 531, 626, 720];
  const LANES = [508, 603, 698]; // ground-contact y per lane, far to near
  const scaleAt = (y) => 0.86 + (0.14 * (y - LANES[0])) / (LANES[2] - LANES[0]);
  const mod = (a, n) => ((a % n) + n) % n;

  // Calls fn(i, screenX) for every world tile of width tw visible at parallax p.
  function tiles(camX, p, tw, fn, pad = 1) {
    const off = camX * p;
    const i0 = Math.floor(off / tw) - pad, i1 = Math.floor((off + W) / tw) + pad;
    for (let i = i0; i <= i1; i++) fn(i, i * tw - off);
  }

  // ------------------------------------------------------------------ sky

  function daySky(ctx, t) {
    const g = ctx.createLinearGradient(0, 0, 0, FOOT_TOP);
    g.addColorStop(0, '#7cc3ec');
    g.addColorStop(0.55, '#cbe5f0');
    g.addColorStop(1, '#f8e2bd');
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, W, FOOT_TOP + 4);
    const sg = ctx.createRadialGradient(1060, 110, 8, 1060, 110, 130);
    sg.addColorStop(0, 'rgba(255,250,225,1)');
    sg.addColorStop(0.22, 'rgba(255,238,185,0.65)');
    sg.addColorStop(1, 'rgba(255,238,185,0)');
    ctx.fillStyle = sg;
    ctx.fillRect(920, 0, 280, 250);
    circle(ctx, 1060, 110, 26);
    paint(ctx, '#fff7de');
    kites(ctx, t);
    crows(ctx, t);
  }

  // The night sky is painted in its final colours; the night tint only applies to layers.
  function nightSky(ctx, t) {
    const g = ctx.createLinearGradient(0, 0, 0, FOOT_TOP);
    g.addColorStop(0, '#0a0f2c');
    g.addColorStop(0.55, '#19214f');
    g.addColorStop(1, '#4b3b60');
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, W, FOOT_TOP + 4);
    for (let i = 0; i < 90; i++) {
      const tw = 0.5 + 0.5 * Math.sin(t * (0.8 + hash(i) * 2.2) + i * 1.7);
      const sz = 1 + hash(i * 3) * 1.8;
      ctx.fillStyle = 'rgba(255,252,235,' + (0.25 + 0.65 * tw).toFixed(2) + ')';
      ctx.fillRect(hash(i * 7 + 1) * W, hash(i * 13 + 2) * 300, sz, sz);
    }
    // full moon over the city
    const mg = ctx.createRadialGradient(1060, 104, 20, 1060, 104, 130);
    mg.addColorStop(0, 'rgba(255,246,210,0.35)');
    mg.addColorStop(1, 'rgba(255,246,210,0)');
    ctx.fillStyle = mg;
    ctx.fillRect(930, 0, 260, 240);
    circle(ctx, 1060, 104, 26);
    paint(ctx, '#fff3cf');
    ctx.fillStyle = 'rgba(205,190,150,0.5)';
    for (const [dx, dy, r] of [[-9, -6, 5.5], [7, 7, 4.5], [8, -10, 3], [-4, 11, 2.6]]) {
      circle(ctx, 1060 + dx, 104 + dy, r);
      ctx.fill();
    }
  }

  const KITES = [[230, 92, '#ff4fa3', '#ffd23f'], [700, 58, '#35d07f', '#ff9f1c'], [905, 168, '#4cc3ff', '#ffffff']];
  function kites(ctx, t) {
    KITES.forEach(([kx, ky, c1, c2], i) => {
      const x = kx + Math.sin(t * 0.5 + i) * 18, y = ky + Math.cos(t * 0.7 + i * 2) * 10;
      ctx.beginPath();
      ctx.moveTo(x, y + 4);
      ctx.quadraticCurveTo(x + 60, y + 120, x + 140, 300);
      ctx.strokeStyle = 'rgba(40,30,40,0.35)';
      ctx.lineWidth = 1;
      ctx.stroke();
      ctx.save();
      ctx.translate(x, y);
      ctx.rotate(Math.sin(t * 0.9 + i) * 0.15);
      ctx.beginPath();
      ctx.moveTo(0, 18);
      for (let k = 1; k <= 6; k++) ctx.lineTo(Math.sin(t * 4 + k + i) * 5, 18 + k * 7);
      ctx.strokeStyle = c1;
      ctx.lineWidth = 2;
      ctx.stroke();
      ctx.beginPath();
      ctx.moveTo(0, -16); ctx.lineTo(13, 0); ctx.lineTo(0, 18); ctx.lineTo(-13, 0);
      ctx.closePath();
      paint(ctx, c1, OL, 1.2);
      ctx.beginPath();
      ctx.moveTo(0, -16); ctx.lineTo(0, 18); ctx.moveTo(-13, 0); ctx.lineTo(13, 0);
      ctx.strokeStyle = c2;
      ctx.lineWidth = 1.4;
      ctx.stroke();
      ctx.restore();
    });
  }

  function crows(ctx, t) {
    ctx.strokeStyle = '#2a2530';
    ctx.lineWidth = 2;
    ctx.lineCap = 'round';
    for (let i = 0; i < 4; i++) {
      const x = mod(t * (24 + i * 7) + i * 380, W + 200) - 100;
      const y = 60 + i * 30 + Math.sin(t * 1.3 + i) * 8;
      const f = Math.sin(t * 9 + i * 2) * 5;
      ctx.beginPath();
      ctx.moveTo(x - 9, y - f);
      ctx.quadraticCurveTo(x - 4, y - 4, x, y);
      ctx.quadraticCurveTo(x + 4, y - 4, x + 9, y - f);
      ctx.stroke();
    }
  }

  // ------------------------------------------------------------------ city

  const HAZE = ['#a7b6cb', '#9cadc4', '#b3c0d2'];
  const HAZE_NIGHT = ['#1d2347', '#232a54', '#1a1f40'];
  function skyline(ctx, camX) {
    const night = A.isNight();
    tiles(camX, 0.12, 86, (i, x) => {
      const r = (k) => hash(i * 31 + k);
      const w = 56 + r(1) * 60, h = 70 + r(2) * 170;
      const top = FOOT_TOP - 40 - h;
      ctx.fillStyle = (night ? HAZE_NIGHT : HAZE)[Math.floor(r(3) * HAZE.length)];
      ctx.fillRect(x, top, w, h + 40);
      if (r(4) > 0.86) {
        // mosque dome and minaret
        ctx.beginPath();
        ctx.arc(x + w / 2, top, w * 0.28, Math.PI, 0);
        ctx.fill();
        ctx.fillRect(x + w - 8, top - 52, 6, 52);
        ctx.beginPath();
        ctx.arc(x + w - 5, top - 52, 5, Math.PI, 0);
        ctx.fill();
        if (night) {
          circle(ctx, x + w - 5, top - 60, 2.2); // minaret light
          paint(ctx, '#7dffb0');
        }
      } else if (r(5) > 0.88) {
        // construction crane, with a red warning light at night
        ctx.beginPath();
        ctx.moveTo(x + 10, top); ctx.lineTo(x + 10, top - 70);
        ctx.moveTo(x - 24, top - 70); ctx.lineTo(x + 96, top - 70);
        ctx.moveTo(x + 76, top - 70); ctx.lineTo(x + 76, top - 40);
        ctx.strokeStyle = night ? '#2f3866' : '#8796ad';
        ctx.lineWidth = 2;
        ctx.stroke();
        if (night) {
          circle(ctx, x + 96, top - 72, 2.5);
          paint(ctx, '#ff4d4d');
        }
      }
      const rows = Math.floor((h - 10) / 14), cols = Math.floor((w - 10) / 12);
      for (let ry = 0; ry < rows; ry++) {
        for (let cx = 0; cx < cols; cx++) {
          const v = hash(i * 977 + ry * 31 + cx * 7);
          if (night ? v > 0.6 : v > 0.55) {
            ctx.fillStyle = night ? (v > 0.9 ? 'rgba(200,235,255,0.75)' : 'rgba(255,214,140,0.8)') : 'rgba(255,255,255,0.22)';
            ctx.fillRect(x + 6 + cx * 12, top + 8 + ry * 14, 5, 6);
          }
        }
      }
    }, 2);
    const hz = ctx.createLinearGradient(0, 120, 0, FOOT_TOP);
    if (night) {
      // the orange glow a big city throws up at night
      hz.addColorStop(0, 'rgba(255,140,90,0)');
      hz.addColorStop(1, 'rgba(255,140,90,0.22)');
    } else {
      hz.addColorStop(0, 'rgba(248,226,189,0)');
      hz.addColorStop(1, 'rgba(248,226,189,0.55)');
    }
    ctx.fillStyle = hz;
    ctx.fillRect(0, 120, W, FOOT_TOP - 120);
  }

  const FACADES = ['#f4a261', '#e9c46a', '#8ecae6', '#f7c6c7', '#b5e48c', '#ffd6a5', '#cdb4db', '#efe3d0', '#90be6d', '#f28482', '#a8dadc'];
  const SIGN_BG = ['#d62828', '#2a9d4b', '#1d4e89', '#e09f00', '#7b2cbf', '#e76f51', '#0b6e4f'];
  const LAUNDRY = ['#e63946', '#ffd23f', '#4cc3ff', '#ff4fa3', '#f1faee', '#35d07f'];
  const WINDOW_LIGHT = ['#ffd58a', '#ffd58a', '#eafff2', '#eafff2', '#a8d8ff']; // bulbs, tube lights, TV glow
  const SHOPS = [
    'মায়ের দোয়া স্টোর', 'বিসমিল্লাহ হোটেল', 'ভাই ভাই টেলিকম', 'নিউ মডেল টেইলার্স',
    'দোয়েল ফার্মেসী', 'গরম চা পাওয়া যায়', 'পুরান ঢাকার বিরিয়ানি', 'ফটোকপি ও প্রিন্ট',
    'আল্লাহর দান হার্ডওয়্যার', 'মোবাইল সার্ভিসিং', 'রহমান ক্লথ স্টোর', 'নিউ সুইটমিট',
  ];
  const ADS = [
    ['বাংলা টেসলা', '১০০% ব্যাটারি চালিত!', '#1d2f6f', '#ffd23f'],
    ['জ্যামে আটকে আছেন?', 'রিকশা নিন!', '#d62828', '#ffffff'],
    ['গরম গরম সিঙ্গারা', 'মাত্র ৳১০', '#e09f00', '#1d1428'],
    ['মোবাইল রিচার্জ', 'এখানে করা হয়', '#2a9d4b', '#ffffff'],
  ];

  function waterTank(ctx, x, y) {
    // the black rooftop water tank on every Dhaka building
    rrect(ctx, x, y - 26, 28, 26, 6);
    paint(ctx, '#1e1e24', OL, 1.4);
    ctx.fillStyle = 'rgba(255,255,255,0.18)';
    ctx.fillRect(x + 4, y - 22, 3, 18);
    rrect(ctx, x + 9, y - 30, 10, 5, 2);
    paint(ctx, '#1e1e24');
  }

  function billboardFace(ctx, cx, by, idx) {
    const [l1, l2, bg, ink] = ADS[idx];
    rrect(ctx, cx - 82, by, 164, 62, 4);
    paint(ctx, bg, OL, 2);
    fitText(ctx, l1, cx, by + 22, 148, 21, FONT_DISPLAY, ink, null);
    fitText(ctx, l2, cx, by + 46, 148, 14, FONT_UI, ink, null, 0, '700');
  }

  function billboard(ctx, cx, y, idx) {
    const by = y - 96;
    ctx.beginPath();
    ctx.moveTo(cx - 50, y); ctx.lineTo(cx - 50, by + 62);
    ctx.moveTo(cx + 50, y); ctx.lineTo(cx + 50, by + 62);
    ctx.moveTo(cx - 50, y - 12); ctx.lineTo(cx + 50, y - 26);
    ctx.strokeStyle = '#4a4f57';
    ctx.lineWidth = 3;
    ctx.stroke();
    billboardFace(ctx, cx, by, idx);
    if (A.isNight()) {
      // floodlit from two lamps on top
      emit(ctx, (c) => billboardFace(c, cx, by, idx));
      for (const lx of [cx - 40, cx + 40]) {
        rrect(ctx, lx - 6, by - 8, 12, 6, 2);
        paint(ctx, '#3a3f47', OL, 1);
        glow(ctx, lx, by + 10, 58, '#fff2c4', 0.35);
      }
    }
  }

  function facadeWindow(ctx, x, y, col, h) {
    ctx.fillStyle = '#2b3442';
    ctx.fillRect(x, y, 24, 26);
    if (h > 0.55) {
      // curtains
      ctx.fillStyle = SIGN_BG[Math.floor(h * 1000) % SIGN_BG.length];
      ctx.globalAlpha = 0.55;
      ctx.fillRect(x, y, 10, 26);
      ctx.globalAlpha = 1;
    }
    windowGrill(ctx, x, y, 'rgba(232,232,232,0.8)');
    ctx.strokeStyle = shade(col, -0.4);
    ctx.lineWidth = 1.6;
    ctx.strokeRect(x, y, 24, 26);
    if (h < 0.14) {
      // window AC
      ctx.fillStyle = '#eef0f2';
      ctx.fillRect(x + 2, y + 28, 20, 8);
      ctx.fillStyle = '#9aa1a9';
      ctx.fillRect(x + 4, y + 30, 16, 1.2);
      ctx.fillRect(x + 4, y + 33, 16, 1.2);
    }
  }

  function windowGrill(ctx, x, y, color) {
    ctx.beginPath();
    for (let b = 1; b < 4; b++) {
      ctx.moveTo(x + b * 6, y);
      ctx.lineTo(x + b * 6, y + 26);
    }
    ctx.moveTo(x, y + 13);
    ctx.lineTo(x + 24, y + 13);
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.2;
    ctx.stroke();
  }

  function balcony(ctx, x, fy, w, t, seed) {
    const by = fy + 30;
    ctx.fillStyle = 'rgba(40,30,30,0.5)';
    ctx.fillRect(x + 6, by, w - 18, 4);
    ctx.beginPath();
    ctx.moveTo(x + 6, by - 9);
    ctx.lineTo(x + w - 12, by - 9);
    for (let bx = x + 10; bx < x + w - 12; bx += 7) {
      ctx.moveTo(bx, by - 9);
      ctx.lineTo(bx, by);
    }
    ctx.strokeStyle = 'rgba(40,30,30,0.55)';
    ctx.lineWidth = 1.2;
    ctx.stroke();
    for (let k = 0; k < 2; k++) {
      // potted plants
      const px = x + 20 + hash(seed * 7 + k) * (w - 50);
      ctx.fillStyle = '#9c4a2a';
      ctx.fillRect(px - 4, by - 7, 8, 7);
      ctx.fillStyle = k ? '#3a8f3a' : '#2f7d32';
      for (const [dx, dy, r] of [[0, -11, 6], [-4, -8, 4], [4, -8, 4]]) {
        circle(ctx, px + dx, by + dy, r);
        ctx.fill();
      }
    }
    if (hash(seed * 13) > 0.4) {
      // laundry line
      const lx0 = x + 14, lx1 = x + w - 22, ly = fy - 2;
      ctx.beginPath();
      ctx.moveTo(lx0, ly);
      ctx.quadraticCurveTo((lx0 + lx1) / 2, ly + 6, lx1, ly);
      ctx.strokeStyle = 'rgba(30,30,30,0.6)';
      ctx.lineWidth = 1;
      ctx.stroke();
      for (let k = 0; k < 4; k++) {
        const cx = lx0 + 16 + k * ((lx1 - lx0 - 30) / 3);
        const sw = Math.sin(t * 2 + k + seed) * 1.5;
        ctx.fillStyle = LAUNDRY[mod(seed + k, LAUNDRY.length)];
        ctx.beginPath();
        ctx.moveTo(cx - 7, ly + 3); ctx.lineTo(cx + 7, ly + 3); ctx.lineTo(cx + 6 + sw, ly + 20); ctx.lineTo(cx - 6 + sw, ly + 20);
        ctx.closePath();
        ctx.fill();
      }
    }
  }

  function shopSign(ctx, x, y, w, i) {
    const bg = SIGN_BG[Math.floor(hash(i * 29 + 5) * SIGN_BG.length)];
    rrect(ctx, x + 5, y + 2, w - 10, 20, 3);
    paint(ctx, bg, OL, 1.5);
    fitText(ctx, SHOPS[mod(i, SHOPS.length)], x + w / 2, y + 12.5, w - 24, 14, FONT_UI, '#ffffff', null, 0, '700');
    return bg;
  }

  function shop(ctx, x, y, w, i) {
    const bg = shopSign(ctx, x, y, w, i);
    ctx.fillStyle = '#2a2326';
    ctx.fillRect(x + 10, y + 24, w - 20, 24);
    for (let k = 0; k < 9; k++) {
      ctx.fillStyle = SIGN_BG[(k + mod(i, 7)) % SIGN_BG.length];
      ctx.fillRect(x + 15 + k * ((w - 32) / 9), y + 34 + (k % 2) * 5, 9, 9);
    }
    ctx.fillStyle = '#a3a9b1'; // rolled-up shutter
    ctx.fillRect(x + 10, y + 24, w - 20, 7);
    ctx.fillStyle = '#7d848c';
    ctx.fillRect(x + 10, y + 27, w - 20, 1);
    if (A.isNight()) {
      // back-lit signboard and a lit shop front
      emit(ctx, (c) => {
        c.shadowColor = bg;
        c.shadowBlur = 14;
        shopSign(c, x, y, w, i);
        c.shadowBlur = 0;
      });
      emit(ctx, (c) => {
        c.fillStyle = 'rgba(255,214,150,0.32)';
        c.fillRect(x + 10, y + 31, w - 20, 17);
      }, 'lighter');
    }
  }

  function buildings(ctx, camX, t) {
    const night = A.isNight();
    tiles(camX, 0.45, 222, (i, tx) => {
      const r = (k) => hash(i * 97 + k);
      const x = tx + r(1) * 10;
      const w = 182 + r(2) * 34;
      const floors = 4 + Math.floor(r(3) * 4);
      const base = FOOT_TOP + 4;
      const top = base - 48 - floors * 40 - 10;
      const col = FACADES[Math.floor(r(4) * FACADES.length)];
      ctx.fillStyle = col;
      ctx.fillRect(x, top, w, base - top);
      const st = ctx.createLinearGradient(0, top, 0, top + 70); // monsoon stains
      st.addColorStop(0, 'rgba(60,50,40,0.2)');
      st.addColorStop(1, 'rgba(60,50,40,0)');
      ctx.fillStyle = st;
      ctx.fillRect(x, top, w, 70);
      ctx.fillStyle = 'rgba(0,0,0,0.13)';
      ctx.fillRect(x + w - 9, top, 9, base - top);
      ctx.fillStyle = shade(col, -0.22);
      ctx.fillRect(x - 3, top - 7, w + 6, 9);
      if (r(5) > 0.25) waterTank(ctx, x + 16 + r(6) * (w - 60), top - 7);
      if (r(7) > 0.68) billboard(ctx, x + w / 2, top - 7, Math.floor(r(8) * ADS.length));
      const cols = Math.floor((w - 20) / 38);
      const gx = x + (w - cols * 38) / 2 + 7;
      const lit = [];
      for (let f = 0; f < floors; f++) {
        const fy = top + 12 + f * 40;
        for (let c = 0; c < cols; c++) {
          const h = hash(i * 131 + f * 17 + c * 5);
          facadeWindow(ctx, gx + c * 38, fy, col, h);
          if (night && hash(i * 211 + f * 23 + c * 3) > 0.48) lit.push([gx + c * 38, fy, Math.floor(h * 997) % WINDOW_LIGHT.length]);
        }
        if (hash(i * 53 + f * 7) > 0.62) balcony(ctx, x, fy, w, t, i * 10 + f);
      }
      if (lit.length) {
        emit(ctx, (c) => {
          for (const [wx, wy, li] of lit) {
            c.fillStyle = WINDOW_LIGHT[li];
            c.fillRect(wx, wy, 24, 26);
            windowGrill(c, wx, wy, 'rgba(40,36,48,0.85)');
          }
        });
      }
      shop(ctx, x, base - 48, w, i);
      ctx.strokeStyle = 'rgba(29,20,40,0.5)';
      ctx.lineWidth = 1.5;
      ctx.strokeRect(x, top, w, base - top);
    });
  }

  // Light from the shop fronts spilling onto the footpath (drawn with the street layer).
  function shopSpills(ctx, camX) {
    tiles(camX, 0.45, 222, (i, tx) => {
      const x = tx + hash(i * 97 + 1) * 10, w = 182 + hash(i * 97 + 2) * 34;
      emit(ctx, (c) => {
        const g = c.createLinearGradient(0, FOOT_TOP, 0, ROAD_TOP + 30);
        g.addColorStop(0, 'rgba(255,205,140,0.32)');
        g.addColorStop(1, 'rgba(255,205,140,0)');
        c.fillStyle = g;
        c.fillRect(x + 6, FOOT_TOP, w - 12, ROAD_TOP + 30 - FOOT_TOP);
      }, 'lighter');
    });
  }

  // ------------------------------------------------------------------ wires and poles

  const POLE_SP = 430;
  const wireY = (i, k) => 150 + hash(i * 41 + k) * 72;

  function tangle(ctx, x, y, i) {
    ctx.beginPath();
    for (let k = 0; k < 9; k++) {
      const cx = x + (hash(i * 5 + k) - 0.5) * 22, cy = y + (hash(i * 3 + k) - 0.5) * 20;
      const rx = 10 + hash(i * 7 + k) * 24, ry = 5 + hash(i * 11 + k) * 12;
      ctx.moveTo(cx + rx, cy);
      ctx.ellipse(cx, cy, rx, ry, hash(i + k * 3) * 3, 0, TAU);
    }
    ctx.strokeStyle = 'rgba(28,22,32,0.9)';
    ctx.lineWidth = 1.2;
    ctx.stroke();
  }

  function streetLight(c, lx) {
    // sodium lamp: a cone down to the road and a pool of light on the tarmac
    const cone = c.createLinearGradient(0, 130, 0, H);
    cone.addColorStop(0, 'rgba(255,204,128,0.34)');
    cone.addColorStop(1, 'rgba(255,204,128,0.03)');
    c.fillStyle = cone;
    c.beginPath();
    c.moveTo(lx - 8, 131);
    c.lineTo(lx + 8, 131);
    c.lineTo(lx + 190, H);
    c.lineTo(lx - 170, H);
    c.closePath();
    c.fill();
    const pool = c.createRadialGradient(lx + 10, 590, 10, lx + 10, 590, 200);
    pool.addColorStop(0, 'rgba(255,204,128,0.22)');
    pool.addColorStop(1, 'rgba(255,204,128,0)');
    c.fillStyle = pool;
    c.fillRect(lx - 200, 390, 420, 330);
  }

  function poles(ctx, camX) {
    const night = A.isNight();
    tiles(camX, 1, POLE_SP, (i, x) => {
      const x1 = x + 60, x2 = x1 + POLE_SP;
      const n = 8 + Math.floor(hash(i * 3) * 6);
      ctx.beginPath();
      for (let k = 0; k < n; k++) {
        const y1 = wireY(i, k), y2 = wireY(i + 1, k);
        ctx.moveTo(x1, y1);
        ctx.quadraticCurveTo((x1 + x2) / 2, Math.max(y1, y2) + 16 + hash(i * 59 + k) * 36, x2, y2);
      }
      ctx.strokeStyle = 'rgba(28,22,32,0.85)';
      ctx.lineWidth = 1.3;
      ctx.stroke();
    });
    tiles(camX, 1, POLE_SP, (i, x) => {
      const px = x + 60;
      // street lamp on an arm
      ctx.beginPath();
      ctx.moveTo(px, 140);
      ctx.quadraticCurveTo(px + 18, 116, px + 44, 122);
      ctx.strokeStyle = '#5d6068';
      ctx.lineWidth = 3;
      ctx.stroke();
      rrect(ctx, px + 34, 120, 24, 8, 3);
      paint(ctx, '#4b4f57', OL, 1.2);
      if (night) {
        emit(ctx, (c) => streetLight(c, px + 46), 'lighter');
        emit(ctx, (c) => {
          rrect(c, px + 37, 127, 18, 4, 2);
          c.fillStyle = '#fff1c1';
          c.fill();
        });
        glow(ctx, px + 46, 129, 30, '#ffd08a', 0.8);
      }
      ctx.fillStyle = '#8e9096';
      ctx.fillRect(px - 5, 132, 10, ROAD_TOP - 138);
      ctx.strokeStyle = OL;
      ctx.lineWidth = 1.4;
      ctx.strokeRect(px - 5, 132, 10, ROAD_TOP - 138);
      ctx.fillStyle = '#6d6f75';
      ctx.fillRect(px - 30, 146, 60, 6);
      ctx.strokeRect(px - 30, 146, 60, 6);
      for (const ix of [-24, -8, 8, 24]) {
        circle(ctx, px + ix, 143, 2.6);
        paint(ctx, '#e8e2d6', OL, 1);
      }
      if (hash(i * 17 + 9) > 0.7) {
        rrect(ctx, px + 6, 196, 26, 38, 3); // transformer
        paint(ctx, '#7a828c', OL, 1.4);
      }
      if (hash(i * 13 + 2) > 0.35) tangle(ctx, px, 186 + hash(i) * 40, i);
      if (hash(i * 23 + 1) > 0.5) {
        rrect(ctx, px - 7, 300, 14, 22, 1); // poster
        paint(ctx, SIGN_BG[Math.floor(hash(i * 5) * SIGN_BG.length)], OL, 1);
      }
    });
  }

  // ------------------------------------------------------------------ footpath

  function footpath(ctx, camX) {
    ctx.fillStyle = '#c4b49c';
    ctx.fillRect(0, FOOT_TOP, W, ROAD_TOP - FOOT_TOP);
    ctx.fillStyle = 'rgba(0,0,0,0.08)';
    ctx.fillRect(0, FOOT_TOP, W, 5);
    ctx.beginPath();
    const off = mod(camX, 44);
    for (let x = -off - 44; x < W + 44; x += 44) {
      ctx.moveTo(x, FOOT_TOP);
      ctx.lineTo(x - 10, ROAD_TOP - 8);
    }
    ctx.moveTo(0, FOOT_TOP + 18);
    ctx.lineTo(W, FOOT_TOP + 18);
    ctx.strokeStyle = 'rgba(90,70,50,0.25)';
    ctx.lineWidth = 1;
    ctx.stroke();
    const ko = mod(camX, 60); // kerb painted yellow and black
    for (let x = -ko - 60; x < W + 60; x += 60) {
      ctx.fillStyle = '#ffd23f';
      ctx.fillRect(x, ROAD_TOP - 8, 30, 10);
      ctx.fillStyle = '#26232b';
      ctx.fillRect(x + 30, ROAD_TOP - 8, 30, 10);
    }
  }

  const JARS = ['#e9c46a', '#f4a261', '#e76f51'];
  function teaStall(ctx, x, y, t) {
    ctx.fillStyle = '#5b3a21';
    ctx.fillRect(x - 46, y - 86, 5, 86);
    ctx.fillRect(x + 41, y - 86, 5, 86);
    ctx.beginPath(); // tin roof
    ctx.moveTo(x - 58, y - 84); ctx.lineTo(x + 58, y - 84); ctx.lineTo(x + 50, y - 98); ctx.lineTo(x - 50, y - 98);
    ctx.closePath();
    paint(ctx, '#7d8a99', OL, 1.6);
    ctx.beginPath();
    for (let k = -48; k <= 48; k += 8) {
      ctx.moveTo(x + k, y - 97);
      ctx.lineTo(x + k * 1.12, y - 85);
    }
    ctx.strokeStyle = 'rgba(29,20,40,0.3)';
    ctx.lineWidth = 1;
    ctx.stroke();
    // bulb hanging under the roof
    ctx.beginPath();
    ctx.moveTo(x - 6, y - 84);
    ctx.lineTo(x - 6, y - 72);
    ctx.strokeStyle = '#222';
    ctx.lineWidth = 1;
    ctx.stroke();
    circle(ctx, x - 6, y - 69, 3.5);
    paint(ctx, '#ffe9a8', OL, 0.8);
    rrect(ctx, x - 44, y - 46, 88, 46, 3); // counter
    paint(ctx, '#9c6b3c', OL, 1.6);
    rrect(ctx, x - 30, y - 82, 60, 16, 3);
    paint(ctx, '#d62828', OL, 1.2);
    fitText(ctx, 'চা-বিস্কুট', x, y - 74, 52, 12, FONT_UI, '#ffffff', null, 0, '700');
    for (let j = 0; j < 3; j++) {
      rrect(ctx, x - 38 + j * 19, y - 62, 15, 16, 3);
      paint(ctx, 'rgba(255,255,255,0.55)', OL, 1);
      ctx.fillStyle = JARS[j];
      ctx.fillRect(x - 36 + j * 19, y - 54, 11, 7);
    }
    for (let k = 0; k < 5; k++) {
      // banana bunch hanging from the roof
      ellipse(ctx, x + 30 + (k % 3) * 4, y - 76 + k * 3, 3, 8, 0.4);
      paint(ctx, '#f4d03f', OL, 0.8);
    }
    rrect(ctx, x + 18, y - 60, 18, 14, 5); // kettle
    paint(ctx, '#b8c0c8', OL, 1.2);
    ctx.beginPath();
    ctx.moveTo(x + 36, y - 54);
    ctx.lineTo(x + 42, y - 60);
    ctx.strokeStyle = OL;
    ctx.lineWidth = 2;
    ctx.stroke();
    for (let k = 0; k < 2; k++) {
      const p = (t * 0.7 + k * 0.5) % 1;
      circle(ctx, x + 43 + p * 6, y - 64 - p * 20, 2 + p * 4);
      paint(ctx, 'rgba(255,255,255,' + (0.8 * (1 - p)).toFixed(2) + ')');
    }
    if (A.isNight()) {
      glow(ctx, x - 6, y - 60, 120, '#ffc978', 0.42);
      emit(ctx, (c) => {
        circle(c, x - 6, y - 69, 3.5);
        c.fillStyle = '#fffbe6';
        c.fill();
      });
    }
  }

  function tree(ctx, x, y) {
    rrect(ctx, x - 6, y - 112, 12, 112, 3);
    paint(ctx, '#6b4a2f', OL, 1.4);
    rrect(ctx, x - 6, y - 26, 12, 26, 2); // whitewashed trunk
    paint(ctx, '#f1f1ec', OL, 1.2);
    const blobs = [[0, -140, 30]];
    for (let k = 0; k < 6; k++) {
      const a = (k / 6) * TAU;
      blobs.push([Math.cos(a) * 30, -130 + Math.sin(a) * 18, 26]);
    }
    for (const [dx, dy, r] of blobs) {
      circle(ctx, x + dx, y + dy, r);
      paint(ctx, null, OL, 3);
    }
    blobs.forEach(([dx, dy, r], k) => {
      circle(ctx, x + dx, y + dy, r);
      paint(ctx, ['#3f8f3a', '#2f7a33', '#4fa046'][k % 3]);
    });
  }

  function fruitVan(ctx, x, y, t) {
    A.drawPerson(ctx, x + 52, y - 2, 0.74, t, { type: 'lungi', walk: false, look: { prop: null } });
    for (const wx of [-36, 36]) {
      circle(ctx, x + wx, y - 14, 13);
      paint(ctx, null, '#1c1922', 4);
      circle(ctx, x + wx, y - 14, 3);
      paint(ctx, '#9aa3ae');
    }
    for (const [fx, fy, c] of [[-40, -44, '#ff9f1c'], [-28, -44, '#ff9f1c'], [-34, -54, '#ff9f1c'], [-16, -44, '#9bd36a'], [-4, -44, '#9bd36a'], [-10, -53, '#9bd36a'], [8, -44, '#e63946'], [20, -44, '#e63946'], [14, -53, '#e63946']]) {
      circle(ctx, x + fx, y + fy, 6.5);
      paint(ctx, c, OL, 1);
    }
    for (let k = 0; k < 3; k++) {
      ellipse(ctx, x + 36 + k * 5, y - 48, 3.5, 10, 0.5);
      paint(ctx, '#f4d03f', OL, 0.8);
    }
    rrect(ctx, x - 56, y - 38, 112, 9, 2);
    paint(ctx, '#8d5524', OL, 1.4);
    rrect(ctx, x - 22, y - 80, 44, 15, 2);
    paint(ctx, '#ffffff', OL, 1);
    fitText(ctx, '৳৬০ কেজি', x, y - 72.5, 38, 11, FONT_UI, '#d62828', null, 0, '700');
    // kerosene lamp on a stick
    ctx.beginPath();
    ctx.moveTo(x - 52, y - 38);
    ctx.lineTo(x - 52, y - 88);
    ctx.strokeStyle = '#5b3a21';
    ctx.lineWidth = 2.5;
    ctx.stroke();
    ellipse(ctx, x - 52, y - 94, 4.5, 6);
    paint(ctx, '#ffd98a', OL, 1);
    if (A.isNight()) {
      const f = 0.75 + Math.sin(t * 11) * 0.08;
      glow(ctx, x - 52, y - 94, 90, '#ffb347', f * 0.6);
      emit(ctx, (c) => {
        ellipse(c, x - 52, y - 94, 3.8, 5.2);
        c.fillStyle = '#fff1b8';
        c.fill();
      });
    }
  }

  function bystanders(ctx, x, y, t, i) {
    rrect(ctx, x - 70, y - 30, 22, 30, 3); // dustbin
    paint(ctx, '#2a9d4b', OL, 1.4);
    A.drawPerson(ctx, x - 14, y, 0.74, t, { type: hash(i) > 0.5 ? 'office' : 'student', walk: false, look: { prop: null } });
    A.drawPerson(ctx, x + 22, y, 0.74, t, { type: 'saree', walk: false });
  }

  function props(ctx, camX, t) {
    const gy = FOOT_TOP + 30;
    tiles(camX, 1, 540, (i, x) => {
      const px = x + 120 + hash(i * 19) * 260;
      const kind = Math.floor(hash(i * 23 + 4) * 4);
      if (kind === 0) teaStall(ctx, px, gy, t);
      else if (kind === 1) tree(ctx, px, gy);
      else if (kind === 2) fruitVan(ctx, px, gy, t);
      else bystanders(ctx, px, gy, t, i);
    });
  }

  // ------------------------------------------------------------------ road

  function road(ctx, camX) {
    const g = ctx.createLinearGradient(0, ROAD_TOP, 0, H);
    g.addColorStop(0, '#62666e');
    g.addColorStop(1, '#4b4e56');
    ctx.fillStyle = g;
    ctx.fillRect(0, ROAD_TOP, W, H - ROAD_TOP);
    tiles(camX, 1, 280, (i, x) => {
      const r = (k) => hash(i * 61 + k);
      if (r(12) > 0.92) {
        // zebra crossing that nobody uses
        ctx.fillStyle = 'rgba(240,240,232,0.8)';
        for (let zy = ROAD_TOP + 12; zy < H; zy += 26) ctx.fillRect(x + 60, zy, 100, 13);
        return;
      }
      if (r(1) > 0.45) {
        rrect(ctx, x + r(2) * 160, ROAD_TOP + 14 + r(3) * 230, 50 + r(4) * 120, 16 + r(5) * 26, 8);
        paint(ctx, 'rgba(25,25,30,0.16)');
      }
      if (r(6) > 0.35) {
        let cx = x + r(7) * 220, cy = ROAD_TOP + 20 + r(8) * 250;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        for (let k = 0; k < 5; k++) {
          cx += 8 + r(10 + k) * 14;
          cy += (r(20 + k) - 0.5) * 12;
          ctx.lineTo(cx, cy);
        }
        ctx.strokeStyle = 'rgba(20,20,24,0.45)';
        ctx.lineWidth = 1.2;
        ctx.stroke();
      }
      if (r(9) > 0.82) {
        ellipse(ctx, x + 140, ROAD_TOP + 60 + r(11) * 200, 26, 7); // manhole
        paint(ctx, '#3d4047', '#2a2c31', 2);
      }
    });
    const off = mod(camX, 120);
    ctx.fillStyle = 'rgba(244,244,236,0.85)';
    for (const ly of [LANE_EDGES[1], LANE_EDGES[2]]) {
      for (let lx = -off - 120; lx < W + 120; lx += 120) ctx.fillRect(lx, ly - 2, 62, 4);
    }
    ctx.fillStyle = 'rgba(244,244,236,0.7)';
    ctx.fillRect(0, ROAD_TOP + 5, W, 3);
  }

  // Finish line across the road, plus a banner, at screen x.
  function finishLine(ctx, x, label) {
    for (let r = 0; r < 12; r++) {
      for (let c = 0; c < 2; c++) {
        ctx.fillStyle = (r + c) % 2 ? '#f4f4ee' : '#1d1428';
        ctx.fillRect(x + c * 12, ROAD_TOP + r * 24, 12, 24);
      }
    }
    for (const px of [x - 4, x + 24]) {
      ctx.fillStyle = '#d0d4da';
      ctx.fillRect(px - 3, 236, 6, ROAD_TOP - 236);
    }
    rrect(ctx, x - 80, 214, 188, 48, 6);
    paint(ctx, '#d62828', OL, 2.5);
    fitText(ctx, label, x + 14, 239, 170, 26, FONT_DISPLAY, '#ffd23f', OL, 4);
    if (A.isNight()) {
      emit(ctx, (c) => {
        c.shadowColor = '#ff4d4d';
        c.shadowBlur = 16;
        rrect(c, x - 80, 214, 188, 48, 6);
        c.fillStyle = '#d62828';
        c.fill();
        c.shadowBlur = 0;
        fitText(c, label, x + 14, 239, 170, 26, FONT_DISPLAY, '#ffe066', OL, 4);
      });
    }
  }

  // Monsoon rain: slanted streaks and splashes, drawn over everything.
  function drawRain(ctx, t, amount) {
    ctx.save();
    ctx.lineCap = 'round';
    ctx.strokeStyle = A.isNight() ? 'rgba(170,190,230,0.45)' : 'rgba(225,235,250,0.55)';
    ctx.lineWidth = 1.3;
    ctx.beginPath();
    for (let i = 0, n = Math.round(240 * amount); i < n; i++) {
      const speed = 1100 + hash(i * 5) * 500;
      const len = 16 + hash(i * 11) * 14;
      const y = mod(hash(i * 7) * (H + 80) + t * speed, H + 80) - 40;
      const x = mod(hash(i * 3 + 1) * (W + 300) - t * speed * 0.28, W + 300) - 150;
      ctx.moveTo(x, y);
      ctx.lineTo(x - len * 0.28, y + len);
    }
    ctx.stroke();
    ctx.strokeStyle = 'rgba(220,230,250,0.6)';
    ctx.lineWidth = 1;
    for (let i = 0, n = Math.round(30 * amount); i < n; i++) {
      const phase = t * 2.2 + hash(i * 17);
      const k = phase % 1, gen = Math.floor(phase);
      const sx = hash(i * 19 + gen * 7) * W, sy = ROAD_TOP + 16 + hash(i * 23 + gen * 13) * (H - ROAD_TOP - 16);
      ctx.globalAlpha = 1 - k;
      ellipse(ctx, sx, sy, 2 + k * 10, 0.8 + k * 2.6);
      ctx.stroke();
    }
    ctx.restore();
  }

  /* Draws the whole street. drawSprites(ctx) paints the vehicles and people on the road,
   * inside the street layer so they share its night lighting. finishX (screen x) adds the
   * finish line. Call A.beginNight(on) first to choose day or night. */
  function drawScene(ctx, camX, t, drawSprites, finish) {
    if (A.isNight()) nightSky(ctx, t);
    else daySky(ctx, t);
    skyline(ctx, camX);
    A.layer(ctx, (c) => buildings(c, camX, t));
    A.layer(ctx, (c) => {
      footpath(c, camX);
      if (A.isNight()) shopSpills(c, camX);
      poles(c, camX);
      props(c, camX, t);
      road(c, camX);
      if (finish && finish.x > -200 && finish.x < W + 200) finishLine(c, finish.x, finish.label);
      if (drawSprites) drawSprites(c);
    });
  }

  window.BT.scenery = { W, H, FOOT_TOP, ROAD_TOP, LANE_EDGES, LANES, scaleAt, drawScene, drawRain };
})();
