/* বাংলা টেসলা 3D — every texture, painted with Canvas 2D: glows and shadows, the road,
 * footpath and kerb, windows (with a matching night-glow atlas), Bengali shop signs,
 * billboards, shop fronts and posters, number plates, bus liveries, CNG panels and the
 * painted back plate and hood of each rickshaw. Each one is made once and cached. */
(function () {
  'use strict';

  const { canvasTex } = window.BT.k3;
  const A = window.BT.art;
  const { rrect, paint, circle, ellipse, fitText, flower, bolt, star, shade, hash, rng, bn, OL, FONT_DISPLAY, FONT_UI } = A;
  const TAU = Math.PI * 2;

  const memo = new Map();
  const once = (key, make) => {
    let v = memo.get(key);
    if (!v) memo.set(key, (v = make()));
    return v;
  };

  const SIGN_BG = ['#d62828', '#2a9d4b', '#1d4e89', '#e09f00', '#7b2cbf', '#e76f51', '#0b6e4f'];

  // ------------------------------------------------------------------ light, shadow, smoke

  function radial(c, x, y, r, stops) {
    const g = c.createRadialGradient(x, y, 0, x, y, r);
    for (const [o, s] of stops) g.addColorStop(o, s);
    c.fillStyle = g;
    c.fillRect(x - r, y - r, r * 2, r * 2);
  }

  const glow = () => once('glow', () => canvasTex(64, 64, (c) => radial(c, 32, 32, 32, [[0, 'rgba(255,255,255,1)'], [0.2, 'rgba(255,255,255,0.6)'], [0.5, 'rgba(255,255,255,0.18)'], [1, 'rgba(255,255,255,0)']])));

  // a hard little dot with a soft rim: LEDs, tail lights, stars
  const dot = () => once('dot', () => canvasTex(32, 32, (c) => radial(c, 16, 16, 16, [[0, 'rgba(255,255,255,1)'], [0.45, 'rgba(255,255,255,0.9)'], [0.7, 'rgba(255,255,255,0.25)'], [1, 'rgba(255,255,255,0)']])));

  const blob = () => once('blob', () => canvasTex(64, 64, (c) => radial(c, 32, 32, 32, [[0, 'rgba(0,0,0,0.62)'], [0.55, 'rgba(0,0,0,0.42)'], [1, 'rgba(0,0,0,0)']])));

  const puff = () => once('puff', () => canvasTex(64, 64, (c) => {
    for (let i = 0; i < 7; i++) {
      const x = 22 + hash(i * 3 + 1) * 20, y = 22 + hash(i * 5 + 2) * 20, r = 11 + hash(i * 7 + 3) * 10;
      radial(c, x, y, r, [[0, 'rgba(255,255,255,0.55)'], [1, 'rgba(255,255,255,0)']]);
    }
  }));

  const ring = () => once('ring', () => canvasTex(64, 64, (c) => {
    c.strokeStyle = 'rgba(255,255,255,0.9)';
    c.lineWidth = 4;
    circle(c, 32, 32, 26);
    c.stroke();
  }));

  // Headlight cone on the road: the lamp at the bottom edge, fading as it widens.
  const beam = () => once('beam', () => canvasTex(64, 128, (c) => {
    const img = c.createImageData(64, 128);
    for (let y = 0; y < 128; y++) {
      const t = (127 - y) / 127;
      const hw = 0.16 + 0.84 * t;
      for (let x = 0; x < 64; x++) {
        const s = Math.abs(x - 31.5) / 31.5;
        let a = Math.max(0, 1 - s / hw);
        a = Math.pow(a, 0.7) * Math.pow(1 - t, 1.4) * Math.min(1, t * 14);
        const o = (y * 64 + x) * 4;
        img.data[o] = img.data[o + 1] = img.data[o + 2] = 255;
        img.data[o + 3] = Math.round(a * 255);
      }
    }
    c.putImageData(img, 0, 0);
  }));

  const sparkle = () => once('sparkle', () => canvasTex(64, 64, (c) => {
    radial(c, 32, 32, 20, [[0, 'rgba(255,255,255,0.9)'], [1, 'rgba(255,255,255,0)']]);
    c.fillStyle = '#ffffff';
    star(c, 32, 32, 30, 4, 0.16);
    c.fill();
  }));

  // ------------------------------------------------------------------ road, footpath, kerb

  // 512 px across the 8.4 m road (61 px/m) and 1024 px along 16.8 m; it tiles along the road.
  // Lane lines sit at ±1.4 m; a white edge line by the kerb, a yellow one by the median.
  const ROAD_LOOK = {
    avenue: { base: '#5c6068', speck: 0.07, lines: 0.9, edge: true },
    gulshan: { base: '#53565d', speck: 0.05, lines: 0.95, edge: true },
    puran: { base: '#6a6865', speck: 0.1, lines: 0.45, edge: false },
    night: { base: '#4d5058', speck: 0.06, lines: 0.9, edge: true },
  };

  function road(look) {
    return once('road:' + look, () => canvasTex(512, 1024, (c) => {
      const L = ROAD_LOOK[look] || ROAD_LOOK.avenue;
      const r = rng(look.length * 7 + 3);
      c.fillStyle = L.base;
      c.fillRect(0, 0, 512, 1024);
      // worn wheel tracks in each lane
      for (const lx of [85, 256, 427]) {
        for (const side of [-30, 30]) {
          const g = c.createLinearGradient(lx + side - 20, 0, lx + side + 20, 0);
          g.addColorStop(0, 'rgba(20,20,26,0)');
          g.addColorStop(0.5, 'rgba(20,20,26,0.13)');
          g.addColorStop(1, 'rgba(20,20,26,0)');
          c.fillStyle = g;
          c.fillRect(lx + side - 20, 0, 40, 1024);
        }
      }
      // patches of newer and older asphalt
      for (let i = 0; i < 7; i++) {
        c.fillStyle = r() > 0.5 ? 'rgba(30,30,36,0.18)' : 'rgba(255,255,255,0.05)';
        rrect(c, r() * 440, r() * 960, 40 + r() * 120, 30 + r() * 90, 6);
        c.fill();
      }
      // grit
      for (let i = 0; i < 9000; i++) {
        const v = r();
        c.fillStyle = v > 0.5 ? 'rgba(255,255,255,' + (L.speck * v).toFixed(3) + ')' : 'rgba(0,0,0,' + (L.speck * 1.6 * (1 - v)).toFixed(3) + ')';
        c.fillRect(r() * 512, r() * 1024, 1 + (r() > 0.85), 1 + (r() > 0.85));
      }
      // cracks
      c.strokeStyle = 'rgba(18,18,22,0.5)';
      c.lineWidth = 1.4;
      for (let i = 0; i < 10; i++) {
        let x = r() * 512, y = r() * 1024;
        c.beginPath();
        c.moveTo(x, y);
        for (let k = 0; k < 6; k++) {
          x += (r() - 0.5) * 40;
          y += 8 + r() * 26;
          c.lineTo(x, y);
        }
        c.stroke();
      }
      // lane dashes: 2 m dash, 2.2 m gap (period 256 px)
      for (const lx of [171, 341]) {
        for (let y = 0; y < 1024; y += 256) {
          c.fillStyle = 'rgba(238,238,228,' + L.lines + ')';
          c.fillRect(lx - 4, y + 40, 8, 122);
          c.fillStyle = 'rgba(60,60,64,0.35)'; // worn bits
          for (let k = 0; k < 6; k++) c.fillRect(lx - 4 + r() * 6, y + 40 + r() * 118, 2 + r() * 3, 2 + r() * 4);
        }
      }
      if (L.edge) {
        c.fillStyle = 'rgba(238,238,228,0.85)';
        c.fillRect(10, 0, 6, 1024);
        c.fillStyle = 'rgba(255,200,40,0.85)';
        c.fillRect(496, 0, 6, 1024);
      }
    }, { repeat: true }));
  }

  // Paving tiles: 256 px = 2 m, tiles of 0.4 m.
  function foot(look) {
    return once('foot:' + look, () => canvasTex(256, 256, (c) => {
      const r = rng(11 + look.length);
      const base = look === 'puran' ? '#b9a58e' : look === 'gulshan' ? '#cdbfae' : '#c4b49c';
      c.fillStyle = base;
      c.fillRect(0, 0, 256, 256);
      const n = 5, s = 256 / n;
      for (let i = 0; i < n; i++) {
        for (let j = 0; j < n; j++) {
          const v = r();
          c.fillStyle = v > 0.6 ? 'rgba(255,255,255,0.08)' : v < 0.25 ? 'rgba(60,40,20,0.1)' : 'rgba(0,0,0,0)';
          c.fillRect(i * s + 1, j * s + 1, s - 2, s - 2);
          if (r() > 0.88) {
            // a cracked tile
            c.strokeStyle = 'rgba(70,55,40,0.45)';
            c.lineWidth = 1;
            c.beginPath();
            c.moveTo(i * s + r() * s, j * s);
            c.lineTo(i * s + r() * s, j * s + s * 0.5);
            c.lineTo(i * s + r() * s, j * s + s);
            c.stroke();
          }
        }
      }
      c.strokeStyle = 'rgba(80,62,44,0.45)';
      c.lineWidth = 2;
      for (let i = 0; i <= n; i++) {
        c.beginPath();
        c.moveTo(i * s, 0);
        c.lineTo(i * s, 256);
        c.moveTo(0, i * s);
        c.lineTo(256, i * s);
        c.stroke();
      }
      for (let i = 0; i < 14; i++) {
        c.fillStyle = 'rgba(70,50,30,' + (0.05 + r() * 0.08).toFixed(3) + ')';
        ellipse(c, r() * 256, r() * 256, 6 + r() * 20, 4 + r() * 12);
        c.fill();
      }
    }, { repeat: true }));
  }

  // Kerb painted yellow and black: 1 m per tile.
  const kerb = () => once('kerb', () => canvasTex(128, 32, (c) => {
    c.fillStyle = '#ffd23f';
    c.fillRect(0, 0, 64, 32);
    c.fillStyle = '#26232b';
    c.fillRect(64, 0, 64, 32);
    c.fillStyle = 'rgba(80,60,40,0.25)';
    c.fillRect(0, 24, 128, 8);
  }, { repeat: true }));

  // ------------------------------------------------------------------ windows

  /* 4 × 4 atlas of 64 px windows. Row = look (plain, red curtain, blue curtain, AC unit);
   * column = how it glows at night (dark, bulb, tube light, TV). The day map ignores the
   * column; the glow map lights the glass by column, behind the grille and curtains. */
  const WINDOW_LIGHT = [null, '#ffd27a', '#eafff2', '#9fd3ff'];
  const CURTAIN = [null, '#d62828', '#1d6fb8', null];

  function drawWindow(c, x, y, row, light) {
    const fx = x + 5, fy = y + 4, fw = 54, fh = 48;
    if (light == null) {
      c.fillStyle = '#e9e4da';
      c.fillRect(x + 2, y + 1, 60, 56); // concrete surround
      const g = c.createLinearGradient(0, fy, 0, fy + fh);
      g.addColorStop(0, '#465668');
      g.addColorStop(1, '#232c38');
      c.fillStyle = g;
      c.fillRect(fx, fy, fw, fh);
      c.fillStyle = 'rgba(255,255,255,0.14)';
      c.beginPath();
      c.moveTo(fx + 6, fy);
      c.lineTo(fx + 16, fy);
      c.lineTo(fx + 4, fy + fh);
      c.lineTo(fx - 6, fy + fh);
      c.closePath();
      c.fill();
    } else {
      c.fillStyle = '#000';
      c.fillRect(x, y, 64, 64);
      if (!WINDOW_LIGHT[light]) return;
      c.fillStyle = WINDOW_LIGHT[light];
      c.fillRect(fx, fy, fw, fh);
    }
    if (CURTAIN[row]) {
      c.fillStyle = light == null ? CURTAIN[row] : 'rgba(0,0,0,0.45)';
      c.globalAlpha = light == null ? 0.85 : 1;
      c.fillRect(fx, fy, 22, fh);
      c.globalAlpha = 1;
    }
    // the iron grille on every Dhaka window
    c.strokeStyle = light == null ? 'rgba(236,236,230,0.9)' : '#000';
    c.lineWidth = 2;
    c.beginPath();
    for (let b = 1; b < 6; b++) {
      c.moveTo(fx + (b * fw) / 6, fy);
      c.lineTo(fx + (b * fw) / 6, fy + fh);
    }
    c.moveTo(fx, fy + fh / 2);
    c.lineTo(fx + fw, fy + fh / 2);
    c.stroke();
    if (row === 3) {
      // window AC
      c.fillStyle = light == null ? '#eef0f2' : '#000';
      c.fillRect(x + 12, y + 46, 40, 16);
      if (light == null) {
        c.fillStyle = '#9aa1a9';
        for (let k = 0; k < 3; k++) c.fillRect(x + 15, y + 50 + k * 4, 34, 1.5);
      }
    }
  }

  const windows = () => once('windows', () => canvasTex(256, 256, (c) => {
    for (let r = 0; r < 4; r++) for (let k = 0; k < 4; k++) drawWindow(c, k * 64, r * 64, r, null);
  }));
  const windowsGlow = () => once('windowsGlow', () => canvasTex(256, 256, (c) => {
    for (let r = 0; r < 4; r++) for (let k = 0; k < 4; k++) drawWindow(c, k * 64, r * 64, r, k);
  }));

  // Glass-walled office towers (Gulshan, Motijheel): blue-green panes in a grid.
  const glassFacade = () => once('glass', () => canvasTex(128, 128, (c) => {
    const g = c.createLinearGradient(0, 0, 128, 128);
    g.addColorStop(0, '#6f9fb8');
    g.addColorStop(0.5, '#3e6d86');
    g.addColorStop(1, '#2d5368');
    c.fillStyle = g;
    c.fillRect(0, 0, 128, 128);
    c.fillStyle = 'rgba(255,255,255,0.18)';
    c.beginPath();
    c.moveTo(20, 0);
    c.lineTo(52, 0);
    c.lineTo(10, 128);
    c.lineTo(-22, 128);
    c.fill();
    c.strokeStyle = '#c9d4dc';
    c.lineWidth = 5;
    c.strokeRect(0, 0, 128, 128);
    c.lineWidth = 2;
    c.beginPath();
    c.moveTo(64, 0);
    c.lineTo(64, 128);
    c.stroke();
  }, { repeat: true }));

  const glassGlow = () => once('glassGlow', () => canvasTex(128, 128, (c) => {
    c.fillStyle = '#000';
    c.fillRect(0, 0, 128, 128);
    c.fillStyle = 'rgba(200,230,255,0.75)';
    c.fillRect(4, 4, 56, 120);
    c.fillStyle = 'rgba(255,220,150,0.5)';
    c.fillRect(68, 4, 56, 56);
  }, { repeat: true }));

  // ------------------------------------------------------------------ shop signs

  const SHOPS = [
    'মায়ের দোয়া স্টোর', 'বিসমিল্লাহ হোটেল', 'ভাই ভাই টেলিকম', 'নিউ মডেল টেইলার্স',
    'দোয়েল ফার্মেসী', 'গরম চা পাওয়া যায়', 'পুরান ঢাকার বিরিয়ানি', 'ফটোকপি ও প্রিন্ট',
    'আল্লাহর দান হার্ডওয়্যার', 'মোবাইল সার্ভিসিং', 'রহমান ক্লথ স্টোর', 'নিউ সুইটমিট',
  ];
  const SIGN_ROWS = SHOPS.length;

  // 12 signboards, one per 85 px row. Lit from behind at night (the same texture glows).
  const signs = () => once('signs', () => canvasTex(1024, 1024, (c) => {
    const h = 1024 / SIGN_ROWS;
    SHOPS.forEach((name, i) => {
      const y = i * h;
      const bg = SIGN_BG[i % SIGN_BG.length];
      c.fillStyle = shade(bg, -0.45);
      c.fillRect(0, y, 1024, h);
      rrect(c, 6, y + 6, 1012, h - 12, 8);
      paint(c, bg);
      c.strokeStyle = 'rgba(255,255,255,0.65)';
      c.lineWidth = 3;
      rrect(c, 16, y + 14, 992, h - 28, 6);
      c.stroke();
      const display = i % 3 === 1;
      fitText(c, name, 512, y + h / 2 + 2, 820, display ? 62 : 52, display ? FONT_DISPLAY : FONT_UI, '#ffffff', OL, 5, display ? null : '700');
      for (const sx of [56, 968]) {
        c.fillStyle = '#ffd23f';
        star(c, sx, y + h / 2, 18);
        c.fill();
      }
    });
  }, { text: true }));
  const signCell = (i) => [0, 1 - ((i % SIGN_ROWS) + 1) / SIGN_ROWS, 1, 1 - (i % SIGN_ROWS) / SIGN_ROWS];

  // ------------------------------------------------------------------ billboards

  const ADS = [
    ['বাংলা টেসলা', '১০০% ব্যাটারি চালিত!', '#1d2f6f', '#ffd23f', 'rickshaw'],
    ['জ্যামে আটকে আছেন?', 'রিকশা নিন!', '#d62828', '#ffffff', 'bell'],
    ['গরম গরম সিঙ্গারা', 'মাত্র ৳১০', '#e09f00', '#1d1428', 'singara'],
    ['মোবাইল রিচার্জ', 'এখানে করা হয়', '#2a9d4b', '#ffffff', 'phone'],
    ['ঝাক্কাস চানাচুর', 'মুখে দিলেই মজা!', '#7b2cbf', '#ffd23f', 'packet'],
    ['বাসা ভাড়া হবে', 'টু-লেট · ২ রুম, ১ বাথ', '#f4efe1', '#d62828', 'house'],
    ['ইলিশ উৎসব', 'পদ্মার ইলিশ, তাজা তাজা', '#0b6e4f', '#ffffff', 'fish'],
    ['নিরাপদে চলুন', 'লেন মেনে চলুন', '#1d4e89', '#ffffff', 'cone'],
  ];

  function adIcon(c, kind, x, y, s, ink) {
    c.save();
    c.translate(x, y);
    c.scale(s, s);
    switch (kind) {
      case 'rickshaw':
        A.drawRickshaw(c, 0, 60, 0.55, 0, { skin: A.SKINS.tesla });
        break;
      case 'bell':
        circle(c, 0, 0, 34);
        paint(c, '#ffd23f', OL, 4);
        circle(c, 0, -6, 12);
        paint(c, '#cfd6df', OL, 3);
        c.lineWidth = 5;
        c.strokeStyle = '#ffffff';
        for (const a of [-0.6, 0.6]) {
          c.beginPath();
          c.arc(0, -6, 26, -Math.PI / 2 + a - 0.25, -Math.PI / 2 + a + 0.25);
          c.stroke();
        }
        break;
      case 'singara':
        for (let i = 0; i < 3; i++) {
          c.beginPath();
          c.moveTo(-40 + i * 32, 30);
          c.lineTo(-24 + i * 32, -18);
          c.lineTo(-8 + i * 32, 30);
          c.closePath();
          paint(c, '#d99a3a', OL, 3);
        }
        break;
      case 'phone':
        rrect(c, -22, -40, 44, 80, 8);
        paint(c, '#1c1c22', OL, 3);
        rrect(c, -17, -32, 34, 56, 3);
        paint(c, '#4cc3ff');
        bolt(c, 0, -4, 30, '#ffd23f', OL);
        break;
      case 'packet':
        rrect(c, -28, -40, 56, 80, 6);
        paint(c, '#ff4fa3', OL, 3);
        fitText(c, 'চানাচুর', 0, 0, 50, 16, FONT_UI, '#ffffff', null, 0, '700');
        for (let i = 0; i < 8; i++) {
          circle(c, -30 + hash(i) * 60, 46 + hash(i * 3) * 6, 4);
          paint(c, '#e09f00');
        }
        break;
      case 'house':
        c.beginPath();
        c.moveTo(-40, -6);
        c.lineTo(0, -42);
        c.lineTo(40, -6);
        c.closePath();
        paint(c, '#d62828', OL, 3);
        c.fillStyle = '#f9e6c8';
        c.fillRect(-30, -6, 60, 44);
        c.strokeRect(-30, -6, 60, 44);
        c.fillStyle = '#4cc3ff';
        c.fillRect(-20, 4, 14, 14);
        c.fillRect(6, 4, 14, 14);
        break;
      case 'fish':
        ellipse(c, 0, 0, 46, 18);
        paint(c, '#cfd6df', OL, 3);
        c.beginPath();
        c.moveTo(40, 0);
        c.lineTo(62, -16);
        c.lineTo(62, 16);
        c.closePath();
        paint(c, '#aab4bf', OL, 3);
        circle(c, -30, -4, 4);
        paint(c, OL);
        break;
      case 'cone':
        c.beginPath();
        c.moveTo(-26, 40);
        c.lineTo(-8, -40);
        c.lineTo(8, -40);
        c.lineTo(26, 40);
        c.closePath();
        paint(c, '#ff7a00', OL, 3);
        c.fillStyle = '#ffffff';
        c.fillRect(-16, -4, 32, 12);
        break;
    }
    c.restore();
  }

  // 2 × 4 billboards, 512 × 256 each. Floodlit at night (the same texture glows).
  const ads = () => once('ads', () => canvasTex(1024, 1024, (c) => {
    ADS.forEach(([l1, l2, bg, ink, icon], i) => {
      const x = (i % 2) * 512, y = Math.floor(i / 2) * 256;
      c.fillStyle = '#e8e8e8';
      c.fillRect(x, y, 512, 256);
      c.fillStyle = bg;
      c.fillRect(x + 8, y + 8, 496, 240);
      c.strokeStyle = ink;
      c.lineWidth = 4;
      c.strokeRect(x + 20, y + 20, 472, 216);
      adIcon(c, icon, x + 96, y + 128, 1.25, ink);
      fitText(c, l1, x + 330, y + 102, 300, 58, FONT_DISPLAY, ink, bg === '#f4efe1' ? null : OL, 4);
      fitText(c, l2, x + 330, y + 176, 300, 32, FONT_UI, ink, null, 0, '700');
    });
  }, { text: true }));
  const adCell = (i) => {
    const k = i % ADS.length;
    return [(k % 2) * 0.5, 1 - (Math.floor(k / 2) + 1) * 0.25, (k % 2) * 0.5 + 0.5, 1 - Math.floor(k / 2) * 0.25];
  };

  // ------------------------------------------------------------------ shop fronts and posters

  /* 4 × 3 shop interiors (256 × 256) and a row of 8 posters (128 × 256) below them.
   * A matching glow atlas lights the open shops at night; shutters stay dark. */
  const SHOP_KINDS = ['grocery', 'pharmacy', 'cloth', 'mobile', 'sweets', 'tea', 'hardware', 'tailor', 'shutter', 'hotel', 'shutterAd', 'print'];
  const POSTERS = [
    ['টু-লেট', 'বাসা ভাড়া হবে', '#ffffff', '#d62828'],
    ['কোচিং', 'এসএসসি · এইচএসসি', '#1d4e89', '#ffffff'],
    ['বিরিয়ানি', 'কাচ্চি ৳২৫০', '#e09f00', '#1d1428'],
    ['সার্কাস!', 'হাতি · বাঘ · জোকার', '#7b2cbf', '#ffd23f'],
    ['ইংলিশ শিখুন', 'মাত্র ৩ মাসে', '#2a9d4b', '#ffffff'],
    ['বৈশাখী মেলা', 'নাগরদোলা · পুতুল নাচ', '#d62828', '#ffd23f'],
    ['নাটক', 'আজ রাত ৮টায়', '#1b1b1f', '#ff4fa3'],
    ['হারানো বিজ্ঞপ্তি', 'একটি লাল ছাতা', '#f4efe1', '#1d1428'],
  ];

  function shopInterior(c, x, y, kind, lit) {
    const W = 256, H = 256;
    const r = rng(SHOP_KINDS.indexOf(kind) * 13 + 5);
    if (lit) {
      c.fillStyle = '#000';
      c.fillRect(x, y, W, H);
      if (kind === 'shutter' || kind === 'shutterAd') return;
      const g = c.createLinearGradient(0, y, 0, y + H);
      g.addColorStop(0, 'rgba(255,236,190,1)');
      g.addColorStop(1, 'rgba(255,200,130,0.6)');
      c.fillStyle = g;
      c.fillRect(x + 6, y + 26, W - 12, H - 32);
      c.fillStyle = 'rgba(0,0,0,0.55)'; // the shopkeeper against the light
      circle(c, x + 128, y + 150, 20);
      c.fill();
      rrect(c, x + 100, y + 168, 56, 60, 14);
      c.fill();
      return;
    }
    c.fillStyle = '#3a2f2c';
    c.fillRect(x, y, W, H);
    if (kind === 'shutter' || kind === 'shutterAd') {
      // rolled-down corrugated shutter
      c.fillStyle = '#9aa1a8';
      c.fillRect(x + 4, y + 4, W - 8, H - 8);
      for (let k = 0; k < 30; k++) {
        c.fillStyle = k % 2 ? 'rgba(255,255,255,0.18)' : 'rgba(0,0,0,0.16)';
        c.fillRect(x + 4, y + 4 + k * 8.2, W - 8, 4);
      }
      if (kind === 'shutterAd') {
        c.fillStyle = '#d62828';
        c.fillRect(x + 30, y + 70, 196, 110);
        fitText(c, 'বন্ধ', x + 128, y + 112, 160, 44, FONT_DISPLAY, '#ffffff', OL, 4);
        fitText(c, 'জুম্মার পর খোলা', x + 128, y + 155, 170, 22, FONT_UI, '#ffd23f', null, 0, '700');
      } else {
        c.strokeStyle = 'rgba(40,30,40,0.55)';
        c.lineWidth = 5;
        c.beginPath();
        c.moveTo(x + 40, y + 120);
        c.quadraticCurveTo(x + 90, y + 80, x + 120, y + 140);
        c.quadraticCurveTo(x + 160, y + 190, x + 210, y + 110);
        c.stroke();
      }
      c.fillStyle = '#5a5f66';
      c.fillRect(x + 110, y + H - 18, 36, 10); // padlock plate
      return;
    }
    // back wall, shelves and goods
    const wall = { pharmacy: '#e8f3ec', mobile: '#1e2a44', sweets: '#f7e7c9', hotel: '#f1e0c4', print: '#dfe6ee' }[kind] || '#e9d8b8';
    c.fillStyle = wall;
    c.fillRect(x + 6, y + 6, W - 12, H - 12);
    c.fillStyle = 'rgba(255,255,255,0.85)'; // tube light
    c.fillRect(x + 60, y + 14, 136, 6);
    const goods = {
      grocery: ['#e63946', '#ffd23f', '#35d07f', '#4cc3ff', '#ff9f1c', '#ffffff'],
      pharmacy: ['#ffffff', '#4cc3ff', '#35d07f', '#e9edf2'],
      cloth: ['#d62828', '#7b2cbf', '#ffd23f', '#2a9d4b', '#ff4fa3', '#1d4e89'],
      mobile: ['#1c1c22', '#4cc3ff', '#e9edf2', '#ff4fa3'],
      sweets: ['#ffffff', '#f4d8a8', '#8a4a2a', '#ffe3a3'],
      tea: ['#c8963e', '#ffffff', '#e9c46a'],
      hardware: ['#9aa1a8', '#2a9d4b', '#4cc3ff', '#e63946', '#ffd23f'],
      tailor: ['#1d4e89', '#ffffff', '#d62828', '#e9c46a'],
      hotel: ['#d99a3a', '#ffffff', '#8a4a2a'],
      print: ['#ffffff', '#e9edf2', '#4cc3ff'],
    }[kind];
    for (let s = 0; s < 3; s++) {
      const sy = y + 40 + s * 52;
      c.fillStyle = '#7a5434';
      c.fillRect(x + 10, sy + 40, W - 20, 6);
      for (let k = 0; k < 9; k++) {
        const gw = 14 + r() * 10, gh = 20 + r() * 18;
        c.fillStyle = goods[Math.floor(r() * goods.length)];
        c.fillRect(x + 16 + k * 26, sy + 40 - gh, gw, gh);
        c.strokeStyle = 'rgba(0,0,0,0.25)';
        c.strokeRect(x + 16 + k * 26, sy + 40 - gh, gw, gh);
      }
    }
    if (kind === 'grocery' || kind === 'tea') {
      // strings of chip packets hanging at the front
      for (let k = 0; k < 12; k++) {
        c.fillStyle = ['#ff4fa3', '#ffd23f', '#35d07f', '#4cc3ff', '#ff9f1c'][k % 5];
        for (let j = 0; j < 3; j++) c.fillRect(x + 12 + k * 20, y + 26 + j * 20, 14, 17);
      }
    }
    if (kind === 'pharmacy') {
      c.fillStyle = '#2a9d4b';
      c.fillRect(x + 108, y + 26, 40, 12);
      c.fillRect(x + 122, y + 12, 12, 40);
    }
    if (kind === 'cloth' || kind === 'tailor') {
      // sarees hanging from a rail
      for (let k = 0; k < 7; k++) {
        c.fillStyle = goods[k % goods.length];
        c.fillRect(x + 16 + k * 33, y + 30, 26, 120);
        c.fillStyle = '#ffd23f';
        c.fillRect(x + 16 + k * 33, y + 140, 26, 8);
      }
    }
    // counter with glass jars, and the shopkeeper
    c.fillStyle = '#5b3a21';
    c.fillRect(x + 6, y + 196, W - 12, 54);
    circle(c, x + 128, y + 168, 17);
    paint(c, '#7a4a2e');
    c.fillStyle = '#1a1210';
    c.beginPath();
    c.ellipse(x + 128, y + 160, 17, 10, 0, Math.PI, TAU);
    c.fill();
    rrect(c, x + 104, y + 182, 48, 30, 10);
    paint(c, ['#f4f1ea', '#7fb3d5', '#e9c46a'][Math.floor(r() * 3)]);
    for (let k = 0; k < 4; k++) {
      rrect(c, x + 20 + k * 58, y + 178, 34, 22, 4);
      paint(c, 'rgba(255,255,255,0.55)', OL, 1.5);
      c.fillStyle = ['#e9c46a', '#f4a261', '#e76f51', '#90be6d'][k];
      c.fillRect(x + 23 + k * 58, y + 188, 28, 10);
    }
    c.fillStyle = 'rgba(0,0,0,0.25)';
    c.fillRect(x + 6, y + 196, W - 12, 4);
  }

  function poster(c, x, y, [t1, t2, bg, ink], lit) {
    if (lit) {
      c.fillStyle = '#000';
      c.fillRect(x, y, 128, 256);
      return;
    }
    c.fillStyle = bg;
    c.fillRect(x + 6, y + 10, 116, 236);
    c.strokeStyle = 'rgba(0,0,0,0.3)';
    c.lineWidth = 2;
    c.strokeRect(x + 6, y + 10, 116, 236);
    fitText(c, t1, x + 64, y + 86, 104, 34, FONT_DISPLAY, ink, null);
    c.save();
    c.translate(x + 64, y + 150);
    const lines = t2.split(' · ');
    lines.forEach((l, i) => fitText(c, l, 0, i * 26 - ((lines.length - 1) * 13), 104, 18, FONT_UI, ink, null, 0, '700'));
    c.restore();
    c.fillStyle = 'rgba(255,255,255,0.25)'; // torn corner
    c.beginPath();
    c.moveTo(x + 122, y + 10);
    c.lineTo(x + 100, y + 10);
    c.lineTo(x + 122, y + 34);
    c.fill();
  }

  function shopsDraw(lit) {
    return (c) => {
      SHOP_KINDS.forEach((k, i) => shopInterior(c, (i % 4) * 256, Math.floor(i / 4) * 256, k, lit));
      POSTERS.forEach((p, i) => poster(c, i * 128, 768, p, lit));
    };
  }
  const shops = () => once('shops', () => canvasTex(1024, 1024, shopsDraw(false), { text: true }));
  const shopsGlow = () => once('shopsGlow', () => canvasTex(1024, 1024, shopsDraw(true)));
  const shopCell = (i) => {
    const k = i % SHOP_KINDS.length;
    return [(k % 4) * 0.25, 1 - (Math.floor(k / 4) + 1) * 0.25, (k % 4) * 0.25 + 0.25, 1 - Math.floor(k / 4) * 0.25];
  };
  const posterCell = (i) => {
    const k = i % POSTERS.length;
    return [k * 0.125, 0, k * 0.125 + 0.125, 0.25];
  };

  // ------------------------------------------------------------------ road markings and decals

  /* 4 × 4 atlas (128 px cells) of things painted on or lying on the road:
   * 0 zebra, 1 manhole, 2 patch, 3 crack, 4 "ধীরে চলুন", 5 "স্কুল", 6 pothole, 7 puddle,
   * 8 litter, 9 drain grate, 10 oil stain, 11 finish chequer, 12 arrow */
  const decals = () => once('decals', () => canvasTex(512, 512, (c) => {
    const at = (i) => [(i % 4) * 128, Math.floor(i / 4) * 128];
    const r = rng(77);
    let [x, y] = at(0);
    c.fillStyle = 'rgba(240,240,232,0.92)';
    for (let k = 0; k < 4; k++) c.fillRect(x + 6 + k * 31, y + 4, 18, 120);
    [x, y] = at(1);
    circle(c, x + 64, y + 64, 50);
    paint(c, '#3d4047', '#26282d', 6);
    c.strokeStyle = 'rgba(20,20,24,0.6)';
    c.lineWidth = 3;
    for (let k = -3; k <= 3; k++) {
      c.beginPath();
      c.moveTo(x + 64 + k * 12, y + 20);
      c.lineTo(x + 64 + k * 12, y + 108);
      c.stroke();
    }
    [x, y] = at(2);
    rrect(c, x + 8, y + 18, 112, 92, 12);
    paint(c, 'rgba(30,30,36,0.45)');
    [x, y] = at(3);
    c.strokeStyle = 'rgba(16,16,20,0.75)';
    c.lineWidth = 2.5;
    c.beginPath();
    c.moveTo(x + 10, y + 64);
    for (let k = 0; k < 8; k++) c.lineTo(x + 20 + k * 14, y + 40 + r() * 48);
    c.stroke();
    // painted words, stretched along the road so they read from a moving vehicle
    for (const [i, word] of [[4, 'ধীরে চলুন'], [5, 'স্কুল']]) {
      [x, y] = at(i);
      c.save();
      c.translate(x + 64, y + 64);
      c.scale(1, 2.4);
      fitText(c, word, 0, 0, 118, 30, FONT_UI, 'rgba(240,240,232,0.92)', null, 0, '700');
      c.restore();
    }
    [x, y] = at(6); // pothole
    ellipse(c, x + 64, y + 64, 58, 50);
    paint(c, '#3a3631');
    ellipse(c, x + 64, y + 68, 46, 38);
    paint(c, '#5e4a33');
    ellipse(c, x + 52, y + 56, 22, 8);
    paint(c, 'rgba(255,255,255,0.18)');
    c.strokeStyle = 'rgba(20,20,24,0.7)';
    c.lineWidth = 2;
    c.beginPath();
    c.moveTo(x + 118, y + 60);
    c.lineTo(x + 126, y + 50);
    c.moveTo(x + 10, y + 70);
    c.lineTo(x + 2, y + 84);
    c.stroke();
    [x, y] = at(7); // puddle
    ellipse(c, x + 64, y + 64, 60, 56);
    paint(c, 'rgba(96,116,138,0.9)', 'rgba(60,70,80,0.7)', 3);
    ellipse(c, x + 80, y + 50, 26, 6);
    paint(c, 'rgba(255,255,255,0.35)');
    [x, y] = at(8); // litter
    for (let k = 0; k < 9; k++) {
      c.fillStyle = ['#ffffff', '#e63946', '#4cc3ff', '#8a6a3a', '#35d07f'][k % 5];
      c.save();
      c.translate(x + 16 + r() * 96, y + 16 + r() * 96);
      c.rotate(r() * 3);
      c.fillRect(-8, -5, 16 + r() * 8, 10);
      c.restore();
    }
    [x, y] = at(9); // drain grate
    c.fillStyle = '#2b2d33';
    c.fillRect(x + 24, y + 8, 80, 112);
    c.fillStyle = '#4a4d55';
    for (let k = 0; k < 9; k++) c.fillRect(x + 28, y + 14 + k * 12, 72, 5);
    [x, y] = at(10); // oil stain
    ellipse(c, x + 64, y + 64, 44, 30);
    paint(c, 'rgba(10,10,14,0.35)');
    [x, y] = at(11); // chequer
    for (let i = 0; i < 4; i++) for (let j = 0; j < 4; j++) {
      c.fillStyle = (i + j) % 2 ? '#f4f4ee' : '#1d1428';
      c.fillRect(x + i * 32, y + j * 32, 32, 32);
    }
    [x, y] = at(12); // arrow
    c.fillStyle = 'rgba(240,240,232,0.9)';
    c.fillRect(x + 58, y + 50, 12, 70);
    c.beginPath();
    c.moveTo(x + 40, y + 54);
    c.lineTo(x + 64, y + 8);
    c.lineTo(x + 88, y + 54);
    c.fill();
  }, { text: true }));
  const decalCell = (i) => [(i % 4) * 0.25, 1 - (Math.floor(i / 4) + 1) * 0.25, (i % 4) * 0.25 + 0.25, 1 - Math.floor(i / 4) * 0.25];


  // uv rect [u0, v0, u1, v1] of a pixel box in a W × H canvas (v runs up)
  const R = (x, y, w, h, W, H = W) => [x / W, 1 - (y + h) / H, (x + w) / W, 1 - y / H];
  const mid = (r) => [(r[0] + r[2]) / 2, (r[1] + r[3]) / 2];

  function paintCheck(c, x, y, w, h, a, b, size) {
    c.fillStyle = a;
    c.fillRect(x, y, w, h);
    c.fillStyle = b;
    c.globalAlpha = 0.5;
    for (let i = 0; i < w; i += size * 2) c.fillRect(x + i, y, size, h);
    for (let j = 0; j < h; j += size * 2) c.fillRect(x, y + j, w, size);
    c.globalAlpha = 1;
  }

  // ------------------------------------------------------------------ cars and CNGs

  const PLATES = ['ঢাকা মেট্রো-গ|১১-২৩৪৫', 'ঢাকা মেট্রো-গ|২৭-৮৮১২', 'ঢাকা মেট্রো-গ|৪৩-০৯৬১', 'ঢাকা মেট্রো-ঘ|১৯-৪৪২০',
    'ঢাকা মেট্রো-থ|১১-৭৩০২', 'ঢাকা মেট্রো-থ|১৪-২২৫৮', 'ঢাকা মেট্রো-ব|১১-০৫৭৭', 'ঢাকা মেট্রো-ব|১৫-৩১৯০'];

  // Two-line number plate, 256 × 64: private cars white, CNGs and buses green.
  function paintPlate(c, x, y, text, commercial) {
    rrect(c, x + 3, y + 3, 250, 58, 6);
    paint(c, commercial ? '#1f7a3f' : '#fbfbf7', OL, 3);
    const [l1, l2] = text.split('|');
    const ink = commercial ? '#ffffff' : '#111111';
    fitText(c, l1, x + 128, y + 21, 230, 22, FONT_UI, ink, null, 0, '700');
    fitText(c, l2, x + 128, y + 46, 230, 26, FONT_UI, ink, null, 0, '700');
  }

  // CNG back (256 × 128) above its front (256 × 128).
  function paintCng(c, x, y) {
    const body = '#2f9e44';
    c.fillStyle = body;
    c.fillRect(x, y, 256, 256);
    c.fillStyle = shade(body, -0.3);
    c.fillRect(x, y + 84, 256, 44);
    for (const tx of [14, 214]) {
      rrect(c, x + tx, y + 52, 28, 26, 5);
      paint(c, '#e63946', OL, 2);
    }
    rrect(c, x + 56, y + 10, 144, 34, 6);
    paint(c, '#ffd23f', OL, 2);
    fitText(c, 'মায়ের দোয়া', x + 128, y + 28, 130, 24, FONT_DISPLAY, '#d62828', null);
    c.save();
    c.translate(x + 64, y + 50);
    c.scale(0.5, 0.5);
    paintPlate(c, 0, 0, PLATES[4], true);
    c.restore();
    c.fillStyle = 'rgba(255,255,255,0.7)';
    c.fillRect(x, y + 80, 256, 3);
    // front
    c.fillStyle = shade(body, 0.08);
    c.fillRect(x, y + 128, 256, 128);
    c.fillStyle = '#ffd23f';
    c.fillRect(x, y + 190, 256, 10);
    circle(c, x + 128, y + 222, 18);
    paint(c, '#fff1a8', OL, 3);
  }

  /* Cars and CNGs share one atlas (512 × 512): eight number plates (256 × 64) on top, the CNG's
   * back and front panels bottom left, and plain white bottom right for the vertex-coloured parts. */
  const vehicles = () => once('vehicles', () => {
    const tex = canvasTex(512, 512, (c) => {
      PLATES.forEach((p, i) => paintPlate(c, (i % 2) * 256, Math.floor(i / 2) * 64, p, i >= 4));
      paintCng(c, 0, 256);
      c.fillStyle = '#ffffff';
      c.fillRect(256, 256, 256, 256);
    }, { text: true });
    return {
      tex,
      plate: (i) => R((i % 2) * 256 + 4, Math.floor(i / 2) * 64 + 4, 248, 56, 512),
      cngBack: R(0, 256, 256, 128, 512),
      cngFront: R(0, 384, 256, 128, 512),
      white: mid(R(256, 256, 256, 256, 512)),
    };
  });

  // ------------------------------------------------------------------ rickshaws

  // The folding hood (metres, around its pivot), shared with the 3D model: an arc of bows from
  // the raised front edge (a0) over the top to the back (a1), deeper in front than behind.
  const HOOD = { a0: 0.72, a1: Math.PI, rxBack: 0.51, rxFront: 0.84, ry: 1.0, w: 0.57 };
  function hoodEdge(n = 24, sc = 1) {
    const pts = [];
    for (let i = 0; i <= n; i++) {
      const a = HOOD.a0 + ((HOOD.a1 - HOOD.a0) * i) / n;
      const rx = a > Math.PI / 2 ? HOOD.rxBack : HOOD.rxFront;
      pts.push([Math.cos(a) * rx * sc, Math.sin(a) * HOOD.ry * sc, a]);
    }
    return pts;
  }
  // the side panel's uv box, in metres around the pivot
  const HOOD_UV = { x0: -0.6, w: 1.5, y0: -0.05, h: 1.15 };

  // Side panel of the hood (256²), painted like the 2D art: ribs in the skin's bands and a flower.
  function paintHoodSide(c, k) {
    const edge = hoodEdge(40);
    const X = (x) => ((x - HOOD_UV.x0) / HOOD_UV.w) * 256, Y = (y) => 256 - ((y - HOOD_UV.y0) / HOOD_UV.h) * 256;
    c.fillStyle = k.hood;
    c.fillRect(0, 0, 256, 256);
    c.save();
    c.beginPath();
    c.moveTo(X(0), Y(0));
    edge.forEach((p) => c.lineTo(X(p[0]), Y(p[1])));
    c.closePath();
    c.clip();
    for (let j = 1; j <= 4; j++) {
      const p = edge[Math.round((j / 5) * (edge.length - 1))];
      c.strokeStyle = k.bands[j - 1];
      c.lineWidth = 13;
      c.beginPath();
      c.moveTo(X(0), Y(0));
      c.lineTo(X(p[0] * 1.1), Y(p[1] * 1.1));
      c.stroke();
    }
    c.strokeStyle = k.bands[0];
    c.lineWidth = 7;
    c.beginPath();
    edge.forEach((p, i) => (i ? c.lineTo(X(p[0] * 0.84), Y(p[1] * 0.84)) : c.moveTo(X(p[0] * 0.84), Y(p[1] * 0.84))));
    c.stroke();
    const fp = edge[Math.round(edge.length * 0.62)];
    flower(c, X(fp[0] * 0.5), Y(fp[1] * 0.5), 34, k.bands[1], k.bands[0]);
    c.restore();
  }

  // The hood's canvas from the front edge (left) over the top to the back (right), across its width.
  function paintHoodRoof(c, k) {
    c.fillStyle = k.hood;
    c.fillRect(0, 0, 256, 128);
    for (let i = 1; i < 5; i++) {
      c.fillStyle = 'rgba(255,255,255,0.3)'; // chrome bows
      c.fillRect(i * 51 - 2, 0, 4, 128);
    }
    for (let i = 0; i < 8; i++) {
      // bunting across the back
      c.fillStyle = k.bands[i % 4];
      c.beginPath();
      c.moveTo(196, i * 16);
      c.lineTo(196, i * 16 + 16);
      c.lineTo(222, i * 16 + 8);
      c.closePath();
      c.fill();
    }
    c.fillStyle = k.bands[0];
    c.fillRect(186, 0, 6, 128);
    c.fillStyle = k.bands[2];
    c.fillRect(230, 0, 5, 128);
    c.fillStyle = k.trim;
    c.fillRect(0, 0, 256, 7);
    c.fillRect(0, 121, 256, 7);
    c.fillRect(0, 0, 6, 128);
  }

  // The painted tin plate on the back of the seat (512 × 256): a framed picture and the name.
  function paintBack(c, k) {
    c.fillStyle = k.panel;
    c.fillRect(0, 0, 512, 256);
    for (let i = 0; i < 4; i++) {
      c.strokeStyle = k.bands[i];
      c.lineWidth = 7;
      c.strokeRect(5 + i * 8, 5 + i * 8, 502 - i * 16, 246 - i * 16);
    }
    const px = 150, py = 44, pw = 212, ph = 124;
    const arch = () => {
      c.beginPath();
      c.moveTo(px, py + ph);
      c.lineTo(px, py + 40);
      c.quadraticCurveTo(px + pw / 2, py - 30, px + pw, py + 40);
      c.lineTo(px + pw, py + ph);
      c.closePath();
    };
    c.save();
    arch();
    c.clip();
    backPicture(c, k, px, py, pw, ph);
    c.restore();
    arch();
    c.lineWidth = 6;
    c.strokeStyle = OL;
    c.stroke();
    c.lineWidth = 3;
    c.strokeStyle = k.trim;
    c.stroke();
    for (const [fx, fy] of [[78, 70], [434, 70]]) flower(c, fx, fy, 34, k.bands[1], k.bands[0]);
    for (const [fx, fy] of [[60, 140], [452, 140]]) flower(c, fx, fy, 20, k.bands[2], k.bands[3]);
    rrect(c, 70, 176, 372, 64, 14);
    paint(c, shade(k.panel, -0.35), OL, 4);
    fitText(c, k.name, 256, 210, 340, 56, FONT_DISPLAY, k.ink, OL, 7);
  }

  function backPicture(c, k, x, y, w, h) {
    const sky = c.createLinearGradient(0, y - 30, 0, y + h);
    if (k.battery) {
      // বাংলা টেসলা: a lightning badge over the city at dusk
      sky.addColorStop(0, '#2b1754');
      sky.addColorStop(1, '#ff4fa3');
      c.fillStyle = sky;
      c.fillRect(x, y - 30, w, h + 30);
      for (let i = 0; i < 7; i++) {
        c.fillStyle = '#1d1428';
        const bw = 20 + hash(i * 5) * 16, bh = 30 + hash(i * 7) * 50;
        c.fillRect(x + i * 32, y + h - bh, bw, bh);
      }
      circle(c, x + w / 2, y + 56, 40);
      paint(c, k.trim, OL, 5);
      bolt(c, x + w / 2, y + 56, 58, k.panel === '#ffffff' ? '#0b3d91' : k.panel, OL);
      fitText(c, '১০০% ব্যাটারি', x + w / 2, y + h - 14, w - 30, 22, FONT_UI, '#ffffff', OL, 4, '700');
    } else if (k.name === 'ময়ূরপঙ্খী') {
      sky.addColorStop(0, '#9be7ff');
      sky.addColorStop(1, '#2a9d4b');
      c.fillStyle = sky;
      c.fillRect(x, y - 30, w, h + 30);
      for (let i = 0; i < 9; i++) {
        // a peacock's fan of eye feathers
        const a = Math.PI + (i / 8) * Math.PI;
        const ex = x + w / 2 + Math.cos(a) * 74, ey = y + 100 + Math.sin(a) * 74;
        c.strokeStyle = '#1c7c54';
        c.lineWidth = 4;
        c.beginPath();
        c.moveTo(x + w / 2, y + 100);
        c.lineTo(ex, ey);
        c.stroke();
        ellipse(c, ex, ey, 14, 18, a + Math.PI / 2);
        paint(c, '#2a9d4b', OL, 2);
        ellipse(c, ex, ey, 7, 9, a + Math.PI / 2);
        paint(c, '#1c3d99');
        circle(c, ex, ey, 3.5);
        paint(c, '#ffd23f');
      }
      ellipse(c, x + w / 2, y + 104, 16, 24);
      paint(c, '#1c3d99', OL, 3);
      circle(c, x + w / 2 + 4, y + 76, 10);
      paint(c, '#1c3d99', OL, 3);
    } else if (k.name === 'লাল পরী') {
      sky.addColorStop(0, '#ffd6e0');
      sky.addColorStop(1, '#d62828');
      c.fillStyle = sky;
      c.fillRect(x, y - 30, w, h + 30);
      for (const s of [-1, 1]) {
        ellipse(c, x + w / 2 + s * 46, y + 66, 46, 28, s * -0.5);
        paint(c, 'rgba(255,255,255,0.85)', OL, 3);
        ellipse(c, x + w / 2 + s * 36, y + 104, 30, 18, s * 0.5);
        paint(c, 'rgba(255,210,230,0.9)', OL, 3);
      }
      rrect(c, x + w / 2 - 14, y + 64, 28, 58, 10);
      paint(c, '#d62828', OL, 3);
      circle(c, x + w / 2, y + 52, 15);
      paint(c, '#a26b49', OL, 3);
      c.fillStyle = '#ffd23f';
      star(c, x + w / 2, y + 30, 12);
      c.fill();
      for (let i = 0; i < 6; i++) {
        c.fillStyle = '#ffffff';
        star(c, x + 20 + hash(i) * (w - 40), y + 10 + hash(i * 9) * 50, 5);
        c.fill();
      }
    } else {
      // সোনার তরী: a golden boat on the river at sunset
      sky.addColorStop(0, '#ffcf6b');
      sky.addColorStop(1, '#ff8a3d');
      c.fillStyle = sky;
      c.fillRect(x, y - 30, w, h + 30);
      circle(c, x + w * 0.7, y + 60, 26);
      paint(c, '#fff3b0');
      c.fillStyle = '#1b6fa8';
      c.fillRect(x, y + 92, w, h);
      c.strokeStyle = 'rgba(255,255,255,0.6)';
      c.lineWidth = 2;
      for (let i = 0; i < 4; i++) {
        c.beginPath();
        c.moveTo(x + 20 + i * 50, y + 104 + (i % 2) * 10);
        c.lineTo(x + 46 + i * 50, y + 104 + (i % 2) * 10);
        c.stroke();
      }
      c.beginPath();
      c.moveTo(x + 40, y + 86);
      c.quadraticCurveTo(x + w / 2, y + 118, x + w - 40, y + 86);
      c.lineTo(x + w - 60, y + 100);
      c.lineTo(x + 60, y + 100);
      c.closePath();
      paint(c, '#f4b400', OL, 3);
      c.beginPath();
      c.moveTo(x + w / 2, y + 86);
      c.lineTo(x + w / 2, y + 20);
      c.lineTo(x + w / 2 + 46, y + 74);
      c.closePath();
      paint(c, '#fff4e6', OL, 3);
    }
  }

  /* One atlas per rickshaw (512²): the hood's side panel top left, its canvas top right, then
   * lungi and gamchha check, white for the vertex-coloured parts, and the back plate below. */
  function rickshaw(skin) {
    return once('rickshaw:' + skin.name + skin.frame + skin.hood, () => {
      const tex = canvasTex(512, 512, (c) => {
        paintHoodSide(c, skin);
        c.save();
        c.translate(256, 0);
        paintHoodRoof(c, skin);
        c.restore();
        paintCheck(c, 256, 128, 128, 64, skin.lungi[0], skin.lungi[1], 9);
        paintCheck(c, 384, 128, 128, 64, skin.gamchha[0], skin.gamchha[1], 6);
        c.fillStyle = '#ffffff';
        c.fillRect(256, 192, 256, 64);
        c.save();
        c.translate(0, 256);
        paintBack(c, skin);
        c.restore();
      }, { text: true });
      return {
        tex,
        side: R(0, 0, 256, 256, 512),
        roof: R(256, 0, 256, 128, 512),
        lungi: R(258, 130, 124, 60, 512),
        gamchha: R(386, 130, 124, 60, 512),
        white: mid(R(256, 192, 256, 64, 512)),
        back: R(0, 256, 512, 256, 512),
      };
    });
  }

  // ------------------------------------------------------------------ people

  /* People (256²): white for vertex colours, the two lungis' check, and a saree with its border. */
  const people = () => once('people', () => {
    const tex = canvasTex(256, 256, (c) => {
      c.fillStyle = '#ffffff';
      c.fillRect(0, 0, 128, 128);
      paintCheck(c, 128, 0, 128, 64, '#2f6f3e', '#163a20', 8);
      paintCheck(c, 128, 64, 128, 64, '#7b2cbf', '#3c096c', 8);
      // saree: red, darker pleats, a yellow border along the hem (bottom of the cell)
      c.fillStyle = '#d62828';
      c.fillRect(0, 128, 128, 128);
      c.fillStyle = 'rgba(0,0,0,0.18)';
      for (let i = 0; i < 128; i += 16) c.fillRect(i, 128, 5, 128);
      c.fillStyle = '#ffd23f';
      c.fillRect(0, 230, 128, 22);
      c.fillStyle = '#ff9f1c';
      for (let i = 0; i < 128; i += 12) c.fillRect(i, 236, 6, 10);
      paintCheck(c, 128, 128, 128, 64, '#e63946', '#fff4e6', 6); // the bus helper's gamchha
      c.fillStyle = '#ffffff';
      c.fillRect(128, 192, 128, 64);
    });
    return {
      tex,
      white: mid(R(0, 0, 128, 128, 256)),
      lungiGreen: R(130, 2, 124, 60, 256),
      lungiPurple: R(130, 66, 124, 60, 256),
      saree: R(2, 130, 124, 124, 256),
      gamchha: R(130, 130, 124, 60, 256),
    };
  });

  // ------------------------------------------------------------------ buses

  /* Bus livery (512²): the side (512 × 192, front at the left) on top, the back and the front
   * (256² each) below it, and a white strip for vertex colours. */
  function busPaint(color, glowing) {
    return (c) => {
      const r = rng(parseInt(color.slice(1), 16) % 997);
      const win = (wx) => [wx, 30, 46, 72];
      if (glowing) {
        // tube lights inside, the LED route board and the headlights; everything else dark
        c.fillStyle = '#000';
        c.fillRect(0, 0, 512, 512);
        c.fillStyle = 'rgba(255,226,160,0.9)';
        for (let i = 0; i < 8; i++) {
          const [x, y, w, h] = win(64 + i * 55);
          rrect(c, x, y, w, h, 5);
          c.fill();
        }
        rrect(c, 22, 192 + 26, 212, 84, 8);
        c.fill();
        fitText(c, 'মিরপুর - গুলিস্তান', 256 + 128, 192 + 23, 210, 22, FONT_UI, '#ffb347', null, 0, '700');
        for (const hx of [256 + 34, 256 + 222]) {
          circle(c, hx, 192 + 180, 15);
          c.fillStyle = '#fff8d8';
          c.fill();
        }
        for (const tx of [10, 216]) {
          rrect(c, tx, 192 + 196, 30, 40, 5);
          c.fillStyle = '#ff5a5a';
          c.fill();
        }
        return;
      }
      // ---- side
      c.fillStyle = color;
      c.fillRect(0, 0, 512, 192);
      c.fillStyle = '#f4efe1';
      c.fillRect(0, 0, 512, 22);
      c.fillStyle = '#ffb703';
      c.fillRect(0, 118, 512, 8);
      c.fillStyle = '#1b998b';
      c.fillRect(0, 126, 512, 6);
      c.fillStyle = shade(color, -0.32);
      c.fillRect(0, 168, 512, 24);
      const grime = c.createLinearGradient(0, 120, 0, 192);
      grime.addColorStop(0, 'rgba(80,58,34,0)');
      grime.addColorStop(1, 'rgba(80,58,34,0.5)');
      c.fillStyle = grime;
      c.fillRect(0, 120, 512, 72);
      for (let i = 0; i < 8; i++) {
        const [wx, wy, ww, wh] = win(64 + i * 55);
        const g = c.createLinearGradient(0, wy, 0, wy + wh);
        g.addColorStop(0, '#5f7488');
        g.addColorStop(1, '#222c37');
        rrect(c, wx, wy, ww, wh, 5);
        c.fillStyle = g;
        c.fill();
        c.save();
        c.clip();
        const n = r() < 0.85 ? (r() < 0.5 ? 2 : 1) : 0;
        for (let j = 0; j < n; j++) {
          const px = wx + 12 + r() * 22;
          rrect(c, px - 12, 74, 24, 30, 8);
          paint(c, ['#e63946', '#f1faee', '#a8dadc', '#ffd166', '#90be6d', '#cdb4db'][Math.floor(r() * 6)]);
          circle(c, px, 64, 8);
          paint(c, ['#8a5a3c', '#a26b49', '#6f4329', '#b47a55'][Math.floor(r() * 4)]);
          c.fillStyle = '#1a1210';
          c.beginPath();
          c.ellipse(px, 61, 8.2, 5.5, 0, Math.PI, TAU);
          c.fill();
        }
        c.restore();
        rrect(c, wx, wy, ww, wh, 5);
        paint(c, null, OL, 2);
        c.fillStyle = '#c9d1da';
        c.fillRect(wx + 3, 64, 40, 2);
      }
      rrect(c, 8, 26, 46, 142, 4); // door
      paint(c, '#17191e', OL, 2);
      c.fillStyle = '#c9d1da';
      c.fillRect(14, 32, 3, 132);
      for (let i = 0; i < 6; i++) {
        const dx = 60 + r() * 440, dy = 30 + r() * 140, dr = 12 + r() * 16;
        radial(c, dx, dy, dr, [[0, 'rgba(0,0,0,0.28)'], [1, 'rgba(0,0,0,0)']]);
      }
      c.strokeStyle = 'rgba(255,255,255,0.5)';
      c.lineWidth = 1;
      c.beginPath();
      for (let i = 0; i < 14; i++) {
        const sx = 60 + r() * 440, sy = 108 + r() * 60;
        c.moveTo(sx, sy);
        c.lineTo(sx + 14 + r() * 36, sy + (r() - 0.5) * 8);
      }
      c.stroke();
      fitText(c, 'ঠেলাঠেলি পরিবহন', 290, 150, 330, 32, FONT_DISPLAY, '#ffffff', OL, 5);
      rrect(c, 420, 100, 78, 18, 3);
      paint(c, '#ffffff', OL, 1.5);
      fitText(c, 'সিটিং সার্ভিস', 459, 109, 70, 12, FONT_UI, '#d62828', null, 0, '700');
      // ---- back
      const by = 192;
      c.fillStyle = color;
      c.fillRect(0, by, 256, 256);
      c.fillStyle = '#f4efe1';
      c.fillRect(0, by, 256, 20);
      const rw = c.createLinearGradient(0, by + 26, 0, by + 110);
      rw.addColorStop(0, '#6a8094');
      rw.addColorStop(1, '#25303c');
      rrect(c, 22, by + 26, 212, 84, 8);
      c.fillStyle = rw;
      c.fill();
      for (let j = 0; j < 4; j++) {
        circle(c, 52 + j * 50, by + 94, 13);
        paint(c, ['#8a5a3c', '#a26b49', '#6f4329', '#b47a55'][j]);
        c.fillStyle = '#1a1210';
        c.beginPath();
        c.ellipse(52 + j * 50, by + 89, 13.3, 8.5, 0, Math.PI, TAU);
        c.fill();
      }
      rrect(c, 22, by + 26, 212, 84, 8);
      paint(c, null, OL, 3);
      c.fillStyle = '#ffb703';
      c.fillRect(0, by + 118, 256, 8);
      fitText(c, 'আল্লাহর নামে চলিলাম', 128, by + 146, 220, 30, FONT_DISPLAY, '#ffffff', OL, 5);
      fitText(c, 'দূরত্ব বজায় রাখুন', 128, by + 174, 180, 16, FONT_UI, '#ffd23f', OL, 3, '700');
      for (const tx of [10, 216]) {
        rrect(c, tx, by + 196, 30, 40, 5);
        paint(c, '#e63946', OL, 2);
      }
      c.save();
      c.translate(64, by + 190);
      c.scale(0.5, 0.5);
      paintPlate(c, 0, 0, PLATES[6 + (parseInt(color.slice(1, 3), 16) % 2)], true);
      c.restore();
      c.fillStyle = '#26262c';
      c.fillRect(0, by + 230, 256, 26);
      // ---- front
      const fx = 256;
      c.fillStyle = color;
      c.fillRect(fx, by, 256, 256);
      rrect(c, fx + 14, by + 8, 228, 30, 4);
      paint(c, '#111216', OL, 2);
      fitText(c, 'মিরপুর - গুলিস্তান', fx + 128, by + 23, 210, 22, FONT_UI, '#ff9f1c', null, 0, '700');
      const ws = c.createLinearGradient(0, by + 44, 0, by + 150);
      ws.addColorStop(0, '#8aa2b6');
      ws.addColorStop(1, '#2b3846');
      rrect(c, fx + 14, by + 44, 228, 108, 8);
      c.fillStyle = ws;
      c.fill();
      c.fillStyle = 'rgba(255,255,255,0.22)';
      c.beginPath();
      c.moveTo(fx + 60, by + 44);
      c.lineTo(fx + 100, by + 44);
      c.lineTo(fx + 60, by + 152);
      c.lineTo(fx + 20, by + 152);
      c.fill();
      rrect(c, fx + 14, by + 44, 228, 108, 8);
      paint(c, null, OL, 3);
      rrect(c, fx + 24, by + 120, 64, 24, 3);
      paint(c, '#ffffff', OL, 1.5);
      fitText(c, 'লোকাল', fx + 56, by + 132, 56, 18, FONT_UI, '#d62828', null, 0, '700');
      c.fillStyle = '#26262c';
      c.fillRect(fx, by + 200, 256, 56);
      for (const hx of [fx + 34, fx + 222]) {
        circle(c, hx, by + 180, 15);
        paint(c, '#fff1a8', OL, 3);
      }
      // ---- white strip
      c.fillStyle = '#ffffff';
      c.fillRect(0, 448, 512, 64);
    };
  }

  const BUS_UV = {
    side: R(0, 0, 512, 192, 512),
    back: R(0, 192, 256, 256, 512),
    front: R(256, 192, 256, 256, 512),
    white: mid(R(0, 448, 512, 64, 512)),
  };
  const bus = (color) => once('bus:' + color, () => Object.assign({ tex: canvasTex(512, 512, busPaint(color, false), { text: true }) }, BUS_UV));
  const busGlow = () => once('busGlow', () => canvasTex(512, 512, busPaint('#000000', true), { text: true }));

  // ------------------------------------------------------------------ pickups and road works

  /* Props (512 × 256): the taka coin face, the "সাবধান" sign, red-and-white stripes, white. */
  const props = () => once('props', () => {
    const tex = canvasTex(512, 256, (c) => {
      c.fillStyle = '#ffffff';
      c.fillRect(0, 0, 512, 256);
      circle(c, 64, 64, 60);
      paint(c, '#f4b400', '#a86f00', 6);
      circle(c, 64, 64, 44);
      paint(c, null, '#ffe28a', 5);
      c.font = '700 64px ' + FONT_UI;
      c.textAlign = 'center';
      c.textBaseline = 'middle';
      c.fillStyle = '#7a4d00';
      c.fillText('৳', 64, 68);
      rrect(c, 132, 4, 248, 120, 10);
      paint(c, '#ffd23f', OL, 6);
      fitText(c, 'সাবধান!', 256, 44, 220, 44, FONT_UI, '#d62828', null, 0, '700');
      fitText(c, 'কাজ চলিতেছে', 256, 92, 220, 32, FONT_UI, OL, null, 0, '700');
      c.save();
      c.beginPath();
      c.rect(384, 0, 128, 64);
      c.clip();
      c.fillStyle = '#ffffff';
      c.fillRect(384, 0, 128, 64);
      c.fillStyle = '#e63946';
      for (let i = -2; i < 6; i++) {
        c.beginPath();
        c.moveTo(384 + i * 32, 0);
        c.lineTo(384 + i * 32 + 16, 0);
        c.lineTo(384 + i * 32 + 48, 64);
        c.lineTo(384 + i * 32 + 32, 64);
        c.closePath();
        c.fill();
      }
      c.restore();
    }, { text: true });
    return {
      tex,
      coin: R(4, 4, 120, 120, 512, 256),
      caution: R(132, 4, 248, 120, 512, 256),
      stripes: R(384, 0, 128, 64, 512, 256),
      white: mid(R(0, 140, 512, 116, 512, 256)),
    };
  });

  // ------------------------------------------------------------------ banners and the metro

  // Start and finish banners, made per place name.
  function banner(label, finish) {
    return once('banner:' + label + finish, () => canvasTex(1024, 256, (c) => {
      c.fillStyle = finish ? '#d62828' : '#1d4e89';
      c.fillRect(0, 0, 1024, 256);
      for (let i = 0; i < 2; i++) {
        for (let j = 0; j < 8; j++) {
          for (const x of [0, 1024 - 64]) {
            c.fillStyle = (i + j) % 2 ? '#f4f4ee' : '#1d1428';
            c.fillRect(x + i * 32, j * 32, 32, 32);
          }
        }
      }
      c.strokeStyle = '#ffd23f';
      c.lineWidth = 8;
      c.strokeRect(76, 14, 872, 228);
      fitText(c, label, 512, 112, 820, 120, FONT_DISPLAY, '#ffd23f', OL, 10);
      fitText(c, finish ? 'ফিনিশ লাইন' : 'স্টার্ট', 512, 206, 400, 40, FONT_UI, '#ffffff', OL, 5, '700');
    }, { text: true }));
  }

  // Metro train side: white with red and green bands and a row of windows (no lettering).
  const train = () => once('train', () => canvasTex(512, 128, (c) => {
    c.fillStyle = '#f2f4f5';
    c.fillRect(0, 0, 512, 128);
    c.fillStyle = '#1f3b4d';
    c.fillRect(0, 28, 512, 40);
    c.fillStyle = '#d62828';
    c.fillRect(0, 76, 512, 8);
    c.fillStyle = '#2a9d4b';
    c.fillRect(0, 86, 512, 6);
    c.fillStyle = '#c9d1d8';
    for (let i = 0; i < 4; i++) c.fillRect(i * 128 + 54, 24, 20, 90);
    c.fillStyle = 'rgba(255,255,255,0.25)';
    for (let i = 0; i < 16; i++) c.fillRect(i * 32 + 4, 30, 10, 36);
  }));

  // ------------------------------------------------------------------ real names

  /* Name boards for one route's landmarks and side streets, from OpenStreetMap: 2 × 20 boards of
   * 1024 × 102 px, coloured by kind (green street signs, blue stations, red markets…). */
  const NAME_STYLE = {
    street: ['#0b6e4f', '#ffffff'], metro: ['#1d4e89', '#ffffff'], rail: ['#1d4e89', '#ffd23f'], terminal: ['#1d4e89', '#ffffff'],
    monument: ['#f4efe1', '#1d1428'], heritage: ['#8c1239', '#ffd23f'], mosque: ['#0b6e4f', '#ffd23f'], temple: ['#e09f00', '#1d1428'],
    church: ['#1b1b1f', '#ffffff'], market: ['#d62828', '#ffd23f'], hospital: ['#ffffff', '#d62828'], school: ['#1d3557', '#ffffff'],
    cinema: ['#ff4fa3', '#ffd23f'], civic: ['#2b3445', '#ffffff'], park: ['#2a9d4b', '#ffffff'], busstop: ['#e63946', '#ffffff'],
  };
  const NAME_COLS = 2, NAME_ROWS = 20, NAME_H = 2048 / NAME_ROWS;
  function names(key, entries) {
    return once('names:' + key, () => {
      const tex = canvasTex(2048, 2048, (c) => {
        entries.slice(0, NAME_COLS * NAME_ROWS).forEach(([kind, text], i) => {
          const x = (i % NAME_COLS) * 1024, y = Math.floor(i / NAME_COLS) * NAME_H;
          const [bg, ink] = NAME_STYLE[kind] || NAME_STYLE.civic;
          c.fillStyle = shade(bg, -0.45);
          c.fillRect(x, y, 1024, NAME_H);
          rrect(c, x + 4, y + 4, 1016, NAME_H - 8, 12);
          paint(c, bg);
          c.strokeStyle = ink;
          c.lineWidth = 3;
          rrect(c, x + 14, y + 13, 996, NAME_H - 26, 8);
          c.stroke();
          let left = x + 30;
          if (kind === 'hospital') {
            c.fillStyle = '#d62828';
            c.fillRect(x + 40, y + NAME_H / 2 - 9, 50, 18);
            c.fillRect(x + 56, y + NAME_H / 2 - 25, 18, 50);
            left = x + 100;
          }
          fitText(c, text, (left + x + 994) / 2, y + NAME_H / 2 + 3, x + 994 - left - 20, NAME_H * 0.6, FONT_UI, ink, null, 0, '700');
        });
      }, { text: true });
      return { tex, cell: (i) => R((i % NAME_COLS) * 1024 + 2, Math.floor(i / NAME_COLS) * NAME_H + 2, 1020, NAME_H - 4, 2048), max: NAME_COLS * NAME_ROWS };
    });
  }

  window.BT.tex3 = {
    names, NAMES_MAX: NAME_COLS * NAME_ROWS,
    R, mid,
    glow, dot, blob, puff, ring, beam, sparkle,
    road, foot, kerb,
    windows, windowsGlow, glassFacade, glassGlow,
    signs, signCell, SIGN_ROWS, SHOPS,
    ads, adCell, ADS,
    shops, shopsGlow, shopCell, posterCell, SHOP_KINDS, POSTERS,
    decals, decalCell,
    vehicles, PLATES,
    HOOD, HOOD_UV, hoodEdge, rickshaw,
    people, bus, busGlow, props, banner, train,
  };
})();
